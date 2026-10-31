"""A small async client for the GoMobSec public API (``/api/v1``).

Every call carries the user's own API key, so the platform decides what the
key may see and enforces the account's plan (scan quota, scan modes,
concurrency) exactly as it does for the web app and CI.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from gomobsec_mcp import __version__

UPLOAD_TIMEOUT_SECONDS = 300.0
DOWNLOAD_TIMEOUT_SECONDS = 120.0


class GoMobSecError(Exception):
    """A failure worth telling the user about, already phrased for them."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _detail(resp: httpx.Response) -> str | None:
    """The API's ``detail`` when it is a plain sentence; structured validation
    errors are not relayed (they would reach the user as raw JSON)."""
    try:
        body = resp.json()
    except ValueError:
        return None
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, str) and detail.strip():
        text = " ".join(detail.split())
        return text if len(text) <= 400 else text[:399] + "…"
    return None


def _raise_for(resp: httpx.Response) -> None:
    code = resp.status_code
    if code < 400:
        return
    if code == 401:
        raise GoMobSecError(
            "GoMobSec did not accept the API key (wrong, revoked or expired). "
            "Create one in GoMobSec → API keys and set GOMOBSEC_API_KEY.", 401)
    detail = _detail(resp)
    if code in (403, 404) and detail in (None, "Scan not found", "Access denied"):
        # One answer for both: confirming that someone else's scan exists is a leak.
        raise GoMobSecError("No scan with that id on this account.", code)
    if code == 429:
        raise GoMobSecError(detail or "Rate limit reached for this API key — try again later.", 429)
    if code >= 500:
        raise GoMobSecError("GoMobSec returned an error — try again in a minute.", code)
    raise GoMobSecError(detail or f"GoMobSec refused the request ({code}).", code)


def check_scan_id(scan_id: str) -> str:
    try:
        return str(uuid.UUID(scan_id.strip()))
    except (ValueError, AttributeError):
        raise GoMobSecError("That is not a scan id — scan ids are UUIDs, e.g. from list_scans.") from None


@dataclass(frozen=True)
class Report:
    content: bytes
    filename: str


class GoMobSecClient:
    def __init__(self, base_url: str, api_key: str | None, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._http = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": f"gomobsec-mcp/{__version__}"},
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def _headers(self) -> dict[str, str]:
        if not self._api_key:
            raise GoMobSecError(
                "No API key configured. Create one in GoMobSec → API keys (Professional and Enterprise "
                "plans) and set GOMOBSEC_API_KEY in this MCP server's environment.")
        return {"X-API-Key": self._api_key}

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = self._headers()
        try:
            resp = await self._http.request(method, path, headers=headers, **kwargs)
        except httpx.TimeoutException as exc:
            raise GoMobSecError("GoMobSec did not answer in time — try again.") from exc
        except httpx.HTTPError as exc:
            raise GoMobSecError("Could not reach GoMobSec — check the network or GOMOBSEC_API_URL.") from exc
        _raise_for(resp)
        return resp

    async def _json(self, method: str, path: str, **kwargs: Any) -> dict:
        resp = await self._request(method, path, **kwargs)
        try:
            body = resp.json()
        except ValueError as exc:
            raise GoMobSecError("GoMobSec sent an unexpected response.") from exc
        if not isinstance(body, dict):
            raise GoMobSecError("GoMobSec sent an unexpected response.")
        return body

    # ── reads ────────────────────────────────────────────────────────────────
    async def me(self) -> dict:
        return await self._json("GET", "/api/v1/me")

    async def usage(self) -> dict:
        return await self._json("GET", "/api/v1/usage")

    async def list_scans(self, limit: int = 10) -> list[dict]:
        body = await self._json("GET", "/api/v1/scans", params={"limit": max(1, min(limit, 50))})
        return list(body.get("scans", []))

    async def get_scan(self, scan_id: str) -> dict:
        return await self._json("GET", f"/api/v1/scans/{check_scan_id(scan_id)}")

    async def get_findings(self, scan_id: str, severity: str | None = None, limit: int = 100) -> list[dict]:
        params: dict[str, Any] = {"limit": max(1, min(limit, 500))}
        if severity:
            params["severity"] = severity.upper()
        body = await self._json("GET", f"/api/v1/scans/{check_scan_id(scan_id)}/findings", params=params)
        return list(body.get("findings", []))

    async def download_report(self, scan_id: str, fmt: str) -> Report:
        sid = check_scan_id(scan_id)
        resp = await self._request("GET", f"/api/v1/scans/{sid}/report", params={"format": fmt},
                                   timeout=DOWNLOAD_TIMEOUT_SECONDS)
        return Report(content=resp.content, filename=f"gomobsec-report-{sid}.{fmt}")

    # ── writes ───────────────────────────────────────────────────────────────
    async def submit_scan(self, path: Path, scan_mode: str, project_name: str | None = None) -> dict:
        data = {"scan_mode": scan_mode}
        if project_name:
            data["project_name"] = project_name
        with path.open("rb") as fh:
            return await self._json(
                "POST", "/api/v1/scans",
                files={"file": (path.name, fh, "application/octet-stream")},
                data=data,
                timeout=UPLOAD_TIMEOUT_SECONDS,
            )
