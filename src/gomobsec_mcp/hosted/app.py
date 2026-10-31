"""The hosted connector as an ASGI app, and its ``gomobsec-mcp-hosted`` entry point.

Routes:

- ``POST /mcp`` — the MCP endpoint (Streamable HTTP, stateless), bearer token required
- ``/.well-known/oauth-protected-resource/mcp`` — RFC 9728 metadata (SDK)
- ``/.well-known/oauth-authorization-server`` — RFC 8414 metadata
- ``/authorize``, ``/token``, ``/register``, ``/revoke`` — OAuth (SDK + provider)
- ``/oauth/consent``, ``/oauth/callback`` — the hop through GoMobSec's consent page
- ``/healthz`` — liveness and Redis
"""

from __future__ import annotations

import hashlib
import html
import logging
import time
from pathlib import Path

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from gomobsec_mcp.client import GoMobSecClient, GoMobSecError
from gomobsec_mcp.config import Settings
from gomobsec_mcp.hosted.config import SCOPE, HostedSettings
from gomobsec_mcp.hosted.fetch import PublicFetcher
from gomobsec_mcp.hosted.platform import PlatformClient
from gomobsec_mcp.hosted.provider import ConsentError, GoMobSecAuthProvider
from gomobsec_mcp.hosted.seal import Sealer
from gomobsec_mcp.hosted.store import KV, RedisKV
from gomobsec_mcp.server import Hosting, build_server

logger = logging.getLogger("gomobsec_mcp.hosted")

HOSTED_KEY_HELP = ("GoMobSec no longer accepts this connection — it was disconnected in GoMobSec → API keys. "
                   "Reconnect GoMobSec in your AI app's connector settings.")
# Plans that include API access (the platform's `api_access` feature).
API_PLANS = frozenset({"professional", "enterprise"})
PLAN_CACHE_SECONDS = 300
_COOKIE_PREFIX = "gmcp_"


class HostedAccess:
    """Per tool call: the connection behind the bearer token, its key, its plan."""

    def __init__(self, provider: GoMobSecAuthProvider, base: GoMobSecClient, app_url: str) -> None:
        self._provider = provider
        self._base = base
        self._app_url = app_url
        self._plans: dict[str, tuple[float, str | None]] = {}

    def _grant_id(self) -> str:
        token = get_access_token()
        grant_id = (token.claims or {}).get("grant_id") if token else None
        if not grant_id:
            raise GoMobSecError("Not signed in to GoMobSec. Reconnect GoMobSec in your AI app.", 401)
        return str(grant_id)

    async def client(self) -> GoMobSecClient:
        grant = await self._provider.load_grant(self._grant_id())
        if grant is None:
            raise GoMobSecError("This GoMobSec connection has ended. Reconnect GoMobSec in your AI app.", 401)
        api = self._base.with_key(grant.api_key)
        await self._check_plan(grant.grant_id, api)
        return api

    async def _check_plan(self, grant_id: str, api: GoMobSecClient) -> None:
        """Only plans with API access may use the connector — checked at sign-in
        by GoMobSec, and again here, because a plan can lapse after that."""
        now = time.monotonic()
        cached = self._plans.get(grant_id)
        if cached is None or cached[0] < now:
            me = await api.me()
            allowed = me.get("api_access")
            if allowed is None:
                allowed = str(me.get("tier") or "").lower() in API_PLANS
            if len(self._plans) > 10_000:
                self._plans.clear()
            cached = (now + PLAN_CACHE_SECONDS, None if allowed else str(me.get("tier") or "free"))
            self._plans[grant_id] = cached
        if cached[1] is not None:
            raise GoMobSecError(
                "GoMobSec for AI assistants is part of the Professional and Enterprise plans; this account "
                f"is on the {cached[1]} plan. Upgrade at {self._app_url}/pricing and try again.", 403)

    async def rejected(self) -> None:
        # The key was revoked in GoMobSec: end the connection so the client's
        # next request gets a 401 and it asks the user to sign in again.
        try:
            grant_id = self._grant_id()
        except GoMobSecError:
            return
        self._plans.pop(grant_id, None)
        await self._provider.revoke_grant(grant_id, release_key=False)


def _cookie_name(request_code: str) -> str:
    return _COOKIE_PREFIX + hashlib.sha256(request_code.encode()).hexdigest()[:16]


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1b1b1f}}
h1{{font-size:1.4rem}}a{{color:#3d5afe}}</style></head>
<body><h1>{title}</h1><p>{body}</p><p><a href="{home}">GoMobSec</a></p></body></html>"""
_PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _page(title: str, body: str, home: str, status: int = 400) -> HTMLResponse:
    return HTMLResponse(_PAGE.format(title=html.escape(title), body=html.escape(body), home=html.escape(home)),
                        status_code=status, headers=_PAGE_HEADERS)


def create_app(settings: HostedSettings, *, kv: KV | None = None, platform: PlatformClient | None = None,
               fetcher: PublicFetcher | None = None, api_transport=None) -> Starlette:
    kv = kv or RedisKV(settings.redis_url)
    platform = platform or PlatformClient(settings.api_url, settings.service_token)
    fetcher = fetcher or PublicFetcher()
    provider = GoMobSecAuthProvider(settings, kv, platform, Sealer(settings.encryption_key), fetcher)
    base = GoMobSecClient(settings.api_url, None, transport=api_transport, key_help=HOSTED_KEY_HELP)
    docs_url = "https://github.com/UsamaSarwar121/gomobsec-mcp/blob/main/docs/HOSTED.md"

    # Plain strings: AuthSettings then keeps the issuer without a trailing
    # slash, and RFC 8414/9207 compare issuers as exact strings.
    auth = AuthSettings(
        issuer_url=settings.public_url,
        resource_server_url=settings.resource_url,
        validate_token_resource=True,
        service_documentation_url=docs_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[SCOPE],
    )
    server = build_server(
        # The tools only need the API and web app URLs from Settings; keys come
        # from each connection and nothing is written to disk.
        Settings(api_key=None, api_url=settings.api_url, app_url=settings.app_url, download_dir=Path("/nonexistent")),
        hosting=Hosting(
            access=HostedAccess(provider, base, settings.app_url),
            fetch_app=fetcher.fetch_app,
            server_options={"auth": auth, "auth_server_provider": provider},
        ),
    )

    @server.custom_route("/oauth/consent", methods=["GET"])
    async def consent(request: Request) -> Response:
        code = request.query_params.get("request", "")
        try:
            approve_url, cookie = await provider.begin_consent(code)
        except ConsentError as exc:
            return _page("Sign-in expired", str(exc), settings.app_url)
        resp = RedirectResponse(approve_url, status_code=302, headers={"Cache-Control": "no-store"})
        resp.set_cookie(_cookie_name(code), cookie, max_age=600, path="/oauth/callback",
                        secure=settings.public_url.startswith("https://"), httponly=True, samesite="lax")
        return resp

    @server.custom_route("/oauth/callback", methods=["GET"])
    async def callback(request: Request) -> Response:
        code = request.query_params.get("request", "")
        try:
            target = await provider.complete_consent(
                code, request.query_params.get("nonce"), request.cookies.get(_cookie_name(code)))
        except ConsentError as exc:
            return _page("Could not connect GoMobSec", str(exc), settings.app_url)
        resp = RedirectResponse(target, status_code=302, headers={"Cache-Control": "no-store"})
        resp.delete_cookie(_cookie_name(code), path="/oauth/callback")
        return resp

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        ok = await kv.ping()
        return JSONResponse({"ok": ok}, status_code=200 if ok else 503)

    @server.custom_route("/", methods=["GET"])
    async def home(request: Request) -> Response:
        return _page("GoMobSec MCP server",
                     f"Add {settings.resource_url} as a custom connector in Claude (or any MCP client that "
                     "supports OAuth) and sign in with your GoMobSec account.", settings.app_url, status=200)

    metadata = build_metadata(
        auth.issuer_url, auth.service_documentation_url, auth.client_registration_options,
        auth.revocation_options,
    ).model_dump(mode="json", exclude_none=True)
    # Public clients (Claude, Claude Code) authenticate with PKCE alone, and a
    # client_id may be a Client ID Metadata Document URL — the SDK's default
    # metadata advertises neither.
    metadata["token_endpoint_auth_methods_supported"] = ["none", "client_secret_post", "client_secret_basic"]
    metadata["revocation_endpoint_auth_methods_supported"] = ["none", "client_secret_post", "client_secret_basic"]
    metadata["client_id_metadata_document_supported"] = True

    async def as_metadata(request: Request) -> Response:
        return JSONResponse(metadata, headers={"Cache-Control": "public, max-age=3600",
                                               "Access-Control-Allow-Origin": "*"})

    app = server.streamable_http_app(
        stateless_http=True,
        host=settings.host,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[settings.public_host],
            allowed_origins=list(settings.allowed_origins),
        ),
    )
    authenticator = ClientAuthenticator(provider)

    async def revoke(request: Request) -> Response:
        """RFC 7009. Replaces the SDK's handler, which requires a ``client_secret``
        field and so refuses public clients — Claude among them."""
        done = Response(status_code=200, headers={"Cache-Control": "no-store"})
        try:
            client = await authenticator.authenticate_request(request)
        except AuthenticationError as exc:
            return JSONResponse({"error": "invalid_client", "error_description": exc.message}, status_code=401)
        token = str((await request.form()).get("token") or "")
        if not token:
            return JSONResponse({"error": "invalid_request", "error_description": "token is required"},
                                status_code=400)
        found = await provider.load_access_token(token) or await provider.load_refresh_token(client, token)
        if found is not None and found.client_id == client.client_id:
            await provider.revoke_token(found)
        return done  # unknown tokens are not an error (RFC 7009 §2.2)

    app.router.routes[0:0] = [
        Route("/.well-known/oauth-authorization-server", as_metadata, methods=["GET"]),
        Route("/revoke", revoke, methods=["POST"]),
    ]
    return app


def main() -> None:
    import uvicorn

    from gomobsec_mcp.hosted.config import ConfigError

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = HostedSettings.from_env()
    except ConfigError as exc:
        raise SystemExit(str(exc)) from None
    # Access logs would carry /oauth/callback query strings (one-time, but still).
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, access_log=False,
                server_header=False, proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
