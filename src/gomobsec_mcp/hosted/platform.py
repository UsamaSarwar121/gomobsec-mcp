"""The connector's side of GoMobSec's link API (``/api/integrations/mcp``).

Authenticated with the service token both sides share. Through it the
connector can open a link request (which only shows a consent page), claim
the key a user approved (once, and only with the nonce the approving browser
carried back), and give a key back when a connection ends. It cannot read or
create anything on an account by itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from gomobsec_mcp import __version__

PREFIX = "/api/integrations/mcp"


class PlatformError(Exception):
    pass


@dataclass(frozen=True)
class LinkRequest:
    code: str
    approve_url: str


@dataclass(frozen=True)
class Claim:
    status: str  # approved | declined | pending
    api_key: str | None = None
    user_id: str | None = None
    username: str | None = None


class PlatformClient:
    def __init__(self, api_url: str, service_token: str, *,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._http = httpx.AsyncClient(
            base_url=api_url,
            transport=transport,
            timeout=10.0,
            follow_redirects=False,
            headers={"X-MCP-Connector-Token": service_token, "User-Agent": f"gomobsec-mcp-hosted/{__version__}"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _post(self, path: str, **kwargs) -> dict:
        try:
            resp = await self._http.post(PREFIX + path, **kwargs)
        except httpx.HTTPError as exc:
            raise PlatformError(f"GoMobSec is unreachable: {type(exc).__name__}") from None
        if resp.status_code >= 400:
            raise PlatformError(f"GoMobSec answered {resp.status_code} on {path}")
        try:
            body = resp.json()
        except ValueError:
            raise PlatformError(f"GoMobSec sent a non-JSON answer on {path}") from None
        if not isinstance(body, dict):
            raise PlatformError(f"GoMobSec sent an unexpected answer on {path}")
        return body

    async def create_link(self, *, client_name: str, redirect_host: str) -> LinkRequest:
        body = await self._post("/link-requests", json={"client_name": client_name, "redirect_host": redirect_host})
        return LinkRequest(code=str(body["code"]), approve_url=str(body["approve_url"]))

    async def claim(self, code: str, nonce: str | None) -> Claim:
        body = await self._post(f"/link-requests/{code}/claim", json={"nonce": nonce})
        return Claim(
            status=str(body.get("status")),
            api_key=body.get("api_key"),
            user_id=body.get("user_id"),
            username=body.get("username"),
        )

    async def revoke_key(self, api_key: str) -> bool:
        body = await self._post("/keys/revoke", headers={"X-API-Key": api_key})
        return bool(body.get("revoked"))
