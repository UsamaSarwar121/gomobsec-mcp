"""The OAuth 2.1 authorization server behind the hosted connector.

The MCP SDK serves the endpoints (``/authorize``, ``/token``, ``/register``,
``/revoke``, metadata) and checks PKCE, redirect URIs and code/refresh
expiry. This module decides what those endpoints mean for GoMobSec:

**Clients.** A ``client_id`` that is an https URL is a Client ID Metadata
Document, fetched through :class:`~gomobsec_mcp.hosted.fetch.PublicFetcher`
and cached for an hour; anything else is a client registered through DCR.
Redirect URIs must be https or loopback ``http``; a loopback URI matches a
registered one on any port (RFC 8252 §7.3; Claude Code picks a port per run).

**Consent.** ``authorize`` opens a link request on GoMobSec and sends the
browser to ``/oauth/consent``, which ties the sign-in to that browser with a
cookie before forwarding to GoMobSec's consent page. GoMobSec sends the
browser back to ``/oauth/callback`` with a one-time nonce. Completing needs
both: the cookie (so someone who tricks a user into approving cannot finish
in their own browser) and the nonce (so the browser that started cannot
finish without the user's approval).

**Tokens.** Opaque, stored under their SHA-256. Access tokens last an hour and
are bound to the MCP endpoint (RFC 8707); refresh tokens last 30 days and
rotate on every use. A rotated refresh token presented again means it leaked:
the whole connection is revoked, including its GoMobSec key.

**Connections** ("grants") hold the user's sealed GoMobSec key. Revoking one,
here or by revoking the key in GoMobSec, ends every token issued for it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, ValidationError

from gomobsec_mcp.client import GoMobSecError
from gomobsec_mcp.hosted.config import SCOPE, HostedSettings
from gomobsec_mcp.hosted.fetch import PublicFetcher
from gomobsec_mcp.hosted.platform import PlatformClient, PlatformError
from gomobsec_mcp.hosted.seal import Sealer
from gomobsec_mcp.hosted.store import KV

logger = logging.getLogger("gomobsec_mcp.hosted")

ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
PENDING_TTL = 600
CLIENT_TTL = 90 * 24 * 3600
CIMD_CACHE_TTL = 3600
CIMD_MAX_BYTES = 16 * 1024
# Two refreshes racing with the same token is a client bug, not a theft:
# within this window a reused refresh token is refused but not punished.
REUSE_GRACE_SECONDS = 60
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_CONTROL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]")


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


def redirect_uri_allowed(uri: str) -> bool:
    parts = urlsplit(uri)
    if parts.fragment or not parts.hostname:
        return False
    return parts.scheme == "https" or _is_loopback(uri)


def canonical_resource(uri: str) -> str:
    parts = urlsplit(uri.strip())
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.rstrip('/')}"


class HostedClient(OAuthClientInformationFull):
    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None and _is_loopback(str(redirect_uri)):
            asked = urlsplit(str(redirect_uri))
            for registered in self.redirect_uris or []:
                r = urlsplit(str(registered))
                if (_is_loopback(str(registered)) and r.hostname == asked.hostname
                        and r.path == asked.path and r.query == asked.query):
                    return redirect_uri
        return super().validate_redirect_uri(redirect_uri)


class GrantCode(AuthorizationCode):
    grant_id: str


class GrantRefreshToken(RefreshToken):
    grant_id: str


@dataclass(frozen=True)
class Grant:
    grant_id: str
    user_id: str
    username: str
    client_id: str
    api_key: str


class ConsentError(Exception):
    """Why a sign-in could not be finished, for the error page."""


def _clean(text: object, limit: int) -> str:
    t = " ".join(_CONTROL.sub("", str(text or "")).split())
    return t[:limit]


class GoMobSecAuthProvider:
    def __init__(self, settings: HostedSettings, kv: KV, platform: PlatformClient, sealer: Sealer,
                 fetcher: PublicFetcher) -> None:
        self.settings = settings
        self._kv = kv
        self._platform = platform
        self._sealer = sealer
        self._fetcher = fetcher

    @property
    def issuer(self) -> str:
        return self.settings.public_url

    # ── clients ─────────────────────────────────────────────────────────────
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id.startswith("https://"):
            return await self._metadata_document_client(client_id)
        raw = await self._kv.get(f"client:{client_id}")
        if raw is None:
            return None
        return HostedClient.model_validate_json(raw)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in client_info.redirect_uris or []]
        bad = [u for u in uris if not redirect_uri_allowed(u)]
        if not uris or bad:
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect_uris must be https URLs or loopback http URLs" + (f": {bad[0]}" if bad else ""))
        await self._kv.set(f"client:{client_info.client_id}", client_info.model_dump_json(), ttl=CLIENT_TTL)
        logger.info("client_registered client_id=%s name=%r", client_info.client_id,
                    _clean(client_info.client_name, 60))

    async def _metadata_document_client(self, url: str) -> HostedClient | None:
        parts = urlsplit(url)
        if parts.fragment or parts.path in ("", "/") or parts.username or parts.password:
            return None
        key = f"cimd:{_h(url)}"
        raw = await self._kv.get(key)
        if raw is None:
            try:
                doc = json.loads(await self._fetcher.get_small(url, CIMD_MAX_BYTES))
            except (GoMobSecError, ValueError) as exc:
                logger.warning("cimd_fetch_failed url=%s error=%s", url, exc)
                return None
            if not isinstance(doc, dict) or doc.get("client_id") != url:
                logger.warning("cimd_rejected url=%s reason=client_id mismatch", url)
                return None
            uris = doc.get("redirect_uris")
            if (not isinstance(uris, list) or not uris
                    or not all(isinstance(u, str) and redirect_uri_allowed(u) for u in uris)):
                logger.warning("cimd_rejected url=%s reason=redirect_uris", url)
                return None
            if doc.get("token_endpoint_auth_method", "none") != "none":
                # Only public clients: a metadata document cannot carry a secret.
                logger.warning("cimd_rejected url=%s reason=auth method", url)
                return None
            raw = json.dumps({"client_name": _clean(doc.get("client_name"), 80) or None, "redirect_uris": uris})
            await self._kv.set(key, raw, ttl=CIMD_CACHE_TTL)
        data = json.loads(raw)
        try:
            return HostedClient(
                client_id=url,
                client_name=data["client_name"],
                redirect_uris=data["redirect_uris"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
                scope=SCOPE,
            )
        except ValidationError:
            return None

    # ── authorization ───────────────────────────────────────────────────────
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and canonical_resource(params.resource) != canonical_resource(
                self.settings.resource_url):
            raise AuthorizeError("invalid_target", f"Tokens here are only for {self.settings.resource_url}")
        scopes = params.scopes or [SCOPE]
        if set(scopes) - {SCOPE}:
            raise AuthorizeError("invalid_scope", f"The only scope is {SCOPE!r}")
        redirect_host = urlsplit(str(params.redirect_uri)).hostname or ""
        try:
            link = await self._platform.create_link(
                client_name=_clean(client.client_name, 80) or "An MCP client", redirect_host=redirect_host)
        except PlatformError as exc:
            logger.error("link_request_failed error=%s", exc)
            raise AuthorizeError("temporarily_unavailable",
                                 "GoMobSec sign-in is unavailable; try again shortly.") from None
        pending = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "scopes": scopes,
            "state": params.state,
            "resource": self.settings.resource_url,
            "approve_url": link.approve_url,
        }
        await self._kv.set(f"pending:{link.code}", json.dumps(pending), ttl=PENDING_TTL)
        return f"{self.settings.public_url}/oauth/consent?request={link.code}"

    async def begin_consent(self, request_code: str) -> tuple[str, str]:
        """Bind a sign-in to this browser: returns (GoMobSec consent URL, cookie value)."""
        raw = await self._kv.get(f"pending:{request_code}")
        if raw is None:
            raise ConsentError("This sign-in link has expired. Start connecting again from your AI app.")
        cookie = secrets.token_urlsafe(32)
        if not await self._kv.set(f"bind:{request_code}", _h(cookie), ttl=PENDING_TTL, nx=True):
            raise ConsentError("This sign-in link was already opened. Start connecting again from your AI app.")
        return json.loads(raw)["approve_url"], cookie

    async def complete_consent(self, request_code: str, nonce: str | None, cookie: str | None) -> str:
        """Finish a sign-in GoMobSec answered; returns the client redirect (code or error)."""
        raw = await self._kv.get(f"pending:{request_code}")
        if raw is None:
            raise ConsentError("This sign-in has expired. Start connecting again from your AI app.")
        bound = await self._kv.get(f"bind:{request_code}")
        if not bound or not cookie or not hmac.compare_digest(bound, _h(cookie)):
            raise ConsentError("Finish signing in in the same browser you started from. "
                               "Start connecting again from your AI app.")
        pending = json.loads(raw)
        try:
            claim = await self._platform.claim(request_code, nonce)
        except PlatformError as exc:
            logger.error("link_claim_failed error=%s", exc)
            raise ConsentError("GoMobSec could not confirm this sign-in. Start connecting again "
                               "from your AI app.") from None
        if claim.status == "pending":
            raise ConsentError("This connection has not been approved yet. Go back to GoMobSec and "
                               "approve or decline it.")
        await self._kv.delete(f"pending:{request_code}", f"bind:{request_code}")
        if claim.status != "approved" or not claim.api_key or not claim.user_id:
            return construct_redirect_uri(
                pending["redirect_uri"], error="access_denied",
                error_description="The GoMobSec account holder declined access.",
                state=pending["state"], iss=self.issuer)

        grant_id = secrets.token_urlsafe(16)
        grant = {
            "user_id": claim.user_id,
            "username": claim.username or "",
            "client_id": pending["client_id"],
            "key": self._sealer.seal(claim.api_key, grant_id),
            "created_at": int(time.time()),
        }
        # Kept only as long as the code is valid until the code is redeemed.
        await self._kv.set(f"grant:{grant_id}", json.dumps(grant), ttl=CODE_TTL + 60)
        code = secrets.token_urlsafe(32)
        await self._kv.set(f"code:{_h(code)}", json.dumps({
            **{k: pending[k] for k in ("client_id", "redirect_uri", "redirect_uri_provided_explicitly",
                                       "code_challenge", "scopes", "resource")},
            "grant_id": grant_id,
            "subject": claim.user_id,
            "expires_at": time.time() + CODE_TTL,
        }), ttl=CODE_TTL)
        logger.info("connection_approved grant=%s client_id=%s", grant_id, pending["client_id"])
        return construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["state"], iss=self.issuer)

    # ── codes and tokens ────────────────────────────────────────────────────
    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> GrantCode | None:
        # Single use from the first look: a code that fails a check is gone too.
        raw = await self._kv.getdel(f"code:{_h(authorization_code)}")
        if raw is None:
            return None
        return GrantCode(code=authorization_code, **json.loads(raw))

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: GrantCode) -> OAuthToken:
        if await self._kv.get(f"grant:{authorization_code.grant_id}") is None:
            raise TokenError("invalid_grant", "authorization expired")
        return await self._issue(authorization_code.grant_id, client.client_id, authorization_code.scopes,
                                 authorization_code.subject)

    async def load_refresh_token(self, client: OAuthClientInformationFull,
                                 refresh_token: str) -> GrantRefreshToken | None:
        raw = await self._kv.get(f"rt:{_h(refresh_token)}")
        if raw is None:
            return None
        data = json.loads(raw)
        if data.get("rotated_at"):
            if time.time() - data["rotated_at"] > REUSE_GRACE_SECONDS:
                logger.warning("refresh_token_reused grant=%s — revoking the connection", data["grant_id"])
                await self.revoke_grant(data["grant_id"])
            return None
        return GrantRefreshToken(token=refresh_token, **data)

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: GrantRefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        key = f"rt:{_h(refresh_token.token)}"
        if await self._kv.getdel(key) is None:
            raise TokenError("invalid_grant", "refresh token already used")
        await self._kv.set(key, json.dumps({"grant_id": refresh_token.grant_id, "rotated_at": time.time()}),
                           ttl=REFRESH_TTL)
        if await self._kv.get(f"grant:{refresh_token.grant_id}") is None:
            raise TokenError("invalid_grant", "this connection was disconnected")
        return await self._issue(refresh_token.grant_id, client.client_id, scopes or refresh_token.scopes,
                                 refresh_token.subject)

    async def _issue(self, grant_id: str, client_id: str, scopes: list[str], subject: str | None) -> OAuthToken:
        access, refresh = f"gmcp_at_{secrets.token_urlsafe(32)}", f"gmcp_rt_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        common = {"grant_id": grant_id, "client_id": client_id, "scopes": scopes,
                  "resource": self.settings.resource_url, "subject": subject}
        await self._kv.set(f"at:{_h(access)}", json.dumps({**common, "expires_at": now + ACCESS_TTL}),
                           ttl=ACCESS_TTL)
        await self._kv.set(f"rt:{_h(refresh)}", json.dumps({**common, "expires_at": now + REFRESH_TTL}),
                           ttl=REFRESH_TTL)
        # Use keeps a connection alive; 30 days without a refresh ends it.
        await self._kv.expire(f"grant:{grant_id}", REFRESH_TTL)
        if not client_id.startswith("https://"):
            await self._kv.expire(f"client:{client_id}", CLIENT_TTL)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def load_access_token(self, token: str) -> AccessToken | None:
        raw = await self._kv.get(f"at:{_h(token)}")
        if raw is None:
            return None
        data = json.loads(raw)
        if await self._kv.get(f"grant:{data['grant_id']}") is None:
            return None
        grant_id = data.pop("grant_id")
        return AccessToken(token=token, claims={"grant_id": grant_id, "iss": self.issuer}, **data)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        grant_id = getattr(token, "grant_id", None) or (getattr(token, "claims", None) or {}).get("grant_id")
        if grant_id:
            await self.revoke_grant(grant_id)

    async def exchange_identity_assertion(self, *args, **kwargs):  # pragma: no cover - not advertised
        raise TokenError("unsupported_grant_type", "not supported")

    # ── connections ─────────────────────────────────────────────────────────
    async def load_grant(self, grant_id: str) -> Grant | None:
        raw = await self._kv.get(f"grant:{grant_id}")
        if raw is None:
            return None
        data = json.loads(raw)
        key = self._sealer.open(data["key"], grant_id)
        if key is None:
            logger.error("grant_unreadable grant=%s", grant_id)
            return None
        return Grant(grant_id=grant_id, user_id=data["user_id"], username=data["username"],
                     client_id=data["client_id"], api_key=key)

    async def revoke_grant(self, grant_id: str, *, release_key: bool = True) -> None:
        """End a connection; its tokens stop working and its GoMobSec key is deactivated."""
        grant = await self.load_grant(grant_id)
        await self._kv.delete(f"grant:{grant_id}")
        if grant is None:
            return
        logger.info("connection_revoked grant=%s", grant_id)
        if release_key:
            try:
                await self._platform.revoke_key(grant.api_key)
            except PlatformError as exc:
                logger.warning("key_release_failed grant=%s error=%s", grant_id, exc)
