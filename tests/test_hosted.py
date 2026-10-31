"""The hosted connector end to end: a real HTTP server on a free port, the
OAuth dance as Claude performs it, and tool calls over Streamable HTTP.

GoMobSec's side (link requests and the consent page) and its API are fakes;
nothing here touches the network or a real account.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import httpx2
import pytest
import uvicorn
from fakes import APK, KEY, FakeApi
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from gomobsec_mcp.hosted import app as app_mod
from gomobsec_mcp.hosted.app import create_app
from gomobsec_mcp.hosted.config import ConfigError, HostedSettings
from gomobsec_mcp.hosted.fetch import PublicFetcher
from gomobsec_mcp.hosted.platform import Claim, LinkRequest, PlatformClient
from gomobsec_mcp.hosted.provider import REUSE_GRACE_SECONDS
from gomobsec_mcp.hosted.store import MemoryKV

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
CIMD_URL = "https://claude.ai/oauth/mcp-client-metadata"


class FakePlatform(PlatformClient):
    """GoMobSec's /api/integrations/mcp, with the consent page as a method."""

    def __init__(self) -> None:
        self.requests: dict[str, dict] = {}
        self.revoked: list[str] = []
        self.plan_ok = True

    async def create_link(self, *, client_name: str, redirect_host: str) -> LinkRequest:
        code = secrets.token_urlsafe(24)
        self.requests[code] = {"client_name": client_name, "redirect_host": redirect_host, "decision": None}
        return LinkRequest(code=code, approve_url=f"https://gomobsec.test/integrations/mcp/approve?code={code}")

    def answer(self, code: str, approve: bool = True) -> str:
        """The user on the consent page; returns the URL GoMobSec sends them back to."""
        req = self.requests[code]
        if approve and not self.plan_ok:
            raise PermissionError("upgrade")
        req["decision"] = "approved" if approve else "declined"
        req["nonce"] = secrets.token_urlsafe(16) if approve else None
        query = f"request={code}" + (f"&nonce={req['nonce']}" if approve else "")
        return f"/oauth/callback?{query}"

    async def claim(self, code: str, nonce: str | None) -> Claim:
        req = self.requests.get(code)
        if req is None or req["decision"] is None:
            return Claim(status="pending")
        del self.requests[code]
        if req["decision"] == "declined":
            return Claim(status="declined")
        if nonce != req["nonce"]:
            return Claim(status="declined")
        return Claim(status="approved", api_key=KEY, user_id="user-1", username="sam")

    async def revoke_key(self, api_key: str) -> bool:
        self.revoked.append(api_key)
        return True


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Running:
    def __init__(self, base: str, platform: FakePlatform, api: FakeApi, kv: MemoryKV, cimd: dict) -> None:
        self.base, self.platform, self.api, self.kv, self.cimd = base, platform, api, kv, cimd
        self.resource = f"{base}/mcp"


@pytest.fixture
def running(monkeypatch):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    settings = HostedSettings(
        public_url=base, api_url="http://api.test", app_url="https://gomobsec.test", redis_url="unused",
        service_token="t" * 40, encryption_key=os.urandom(32),
    )
    api, platform, kv = FakeApi(), FakePlatform(), MemoryKV()
    cimd = {"client_id": CIMD_URL, "client_name": "Claude", "redirect_uris": [CLAUDE_CALLBACK],
            "token_endpoint_auth_method": "none"}
    downloads: dict[str, httpx.Response] = {}

    def internet(request: httpx.Request) -> httpx.Response:
        url = f"https://{request.headers['host']}{request.url.raw_path.decode()}"
        if url == CIMD_URL:
            return httpx.Response(200, json=cimd)
        return downloads.get(url) or httpx.Response(404)

    async def resolver(host: str, port: int) -> list[str]:
        return {"internal.example": ["10.0.0.5"], "rebind.example": ["93.184.216.34", "127.0.0.1"]}.get(
            host, ["93.184.216.34"])

    fetcher = PublicFetcher(resolver=resolver, transport=httpx.MockTransport(internet))
    app = create_app(settings, kv=kv, platform=platform, fetcher=fetcher,
                     api_transport=httpx.MockTransport(api.handler))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "server did not start"
        time.sleep(0.02)
    r = Running(base, platform, api, kv, cimd)
    r.downloads = downloads
    yield r
    server.should_exit = True
    thread.join(5)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def _register(http: httpx.AsyncClient, redirect=CLAUDE_CALLBACK) -> dict:
    resp = await http.post("/register", json={
        "client_name": "Claude", "redirect_uris": [redirect], "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _authorize(r: Running, http: httpx.AsyncClient, client_id: str, redirect=CLAUDE_CALLBACK,
                     **extra) -> tuple[str, str]:
    """Start a sign-in; returns (request code, PKCE verifier)."""
    verifier, challenge = _pkce()
    resp = await http.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect, "state": "st4te",
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": r.resource,
        "scope": "gomobsec", **extra,
    })
    assert resp.status_code == 302, resp.text
    consent = urlsplit(resp.headers["location"])
    assert consent.path == "/oauth/consent"
    return parse_qs(consent.query)["request"][0], verifier


async def _connect(r: Running, client_id: str | None = None, redirect=CLAUDE_CALLBACK) -> dict:
    """The whole sign-in, as Claude and the user's browser do it; returns the token response."""
    async with httpx.AsyncClient(base_url=r.base) as browser:
        if client_id is None:
            client_id = (await _register(browser, redirect))["client_id"]
        code, verifier = await _authorize(r, browser, client_id, redirect)
        resp = await browser.get("/oauth/consent", params={"request": code})
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("https://gomobsec.test/integrations/mcp/approve")
        resp = await browser.get(r.platform.answer(code))
        assert resp.status_code == 302, resp.text
        back = urlsplit(resp.headers["location"])
        q = parse_qs(back.query)
        assert f"{back.scheme}://{back.netloc}{back.path}" == redirect
        assert q["state"] == ["st4te"] and q["iss"] == [r.base]
        token = await browser.post("/token", data={
            "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": redirect,
            "client_id": client_id, "code_verifier": verifier, "resource": r.resource,
        })
        assert token.status_code == 200, token.text
        return {**token.json(), "client_id": client_id}


async def _call(r: Running, access_token: str, tool: str, args: dict | None = None) -> tuple[bool, str]:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {access_token}"})
    async with Client(streamable_http_client(r.resource, http_client=http)) as c:
        res = await c.call_tool(tool, args or {})
        return res.is_error, "\n".join(getattr(p, "text", "") for p in res.content)


async def _status(r: Running, access_token: str) -> int:
    """The HTTP status of a bare MCP request with this token."""
    async with httpx.AsyncClient(base_url=r.base) as http:
        resp = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                               headers={"Accept": "application/json, text/event-stream",
                                        "Authorization": f"Bearer {access_token}"})
        return resp.status_code


# ── discovery ────────────────────────────────────────────────────────────────
async def test_unauthenticated_mcp_request_points_at_metadata(running):
    async with httpx.AsyncClient(base_url=running.base) as http:
        resp = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                               headers={"Accept": "application/json, text/event-stream"})
        assert resp.status_code == 401
        challenge = resp.headers["www-authenticate"]
        assert "resource_metadata=" in challenge
        prm_url = challenge.split('resource_metadata="')[1].split('"')[0]
        prm = (await http.get(prm_url)).json()
        assert prm["resource"] == running.resource
        assert prm["authorization_servers"] == [running.base]
        assert prm["scopes_supported"] == ["gomobsec"]
        asm = (await http.get("/.well-known/oauth-authorization-server")).json()
    assert asm["issuer"] == running.base
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["client_id_metadata_document_supported"] is True
    assert "none" in asm["token_endpoint_auth_methods_supported"]
    assert "none" in asm["revocation_endpoint_auth_methods_supported"]
    assert asm["registration_endpoint"] == f"{running.base}/register"
    assert asm["revocation_endpoint"] == f"{running.base}/revoke"


# ── connecting ───────────────────────────────────────────────────────────────
async def test_full_sign_in_with_dcr_then_tools_work(running):
    tokens = await _connect(running)
    assert tokens["token_type"].lower() == "bearer" and tokens["expires_in"] == 3600
    assert tokens["access_token"].startswith("gmcp_at_") and tokens["refresh_token"].startswith("gmcp_rt_")
    req = running.platform  # the consent page was shown the client name and where it returns to
    is_error, text = await _call(running, tokens["access_token"], "whoami")
    assert not is_error and "**sam**" in text
    # The tool reached GoMobSec with the connection's key, never with Claude's token.
    assert {r.headers.get("X-API-Key") for r in running.api.requests} == {KEY}
    assert not any("gmcp_" in str(r.headers) for r in running.api.requests)
    assert req.revoked == []


async def test_sign_in_with_client_id_metadata_document(running):
    tokens = await _connect(running, client_id=CIMD_URL)
    assert not (await _call(running, tokens["access_token"], "get_usage"))[0]


async def test_consent_page_is_told_who_is_asking(running):
    async with httpx.AsyncClient(base_url=running.base) as http:
        code, _ = await _authorize(running, http, CIMD_URL)
    assert running.platform.requests[code]["client_name"] == "Claude"
    assert running.platform.requests[code]["redirect_host"] == "claude.ai"


async def test_metadata_document_must_name_itself(running):
    running.cimd["client_id"] = "https://evil.example/claude"
    async with httpx.AsyncClient(base_url=running.base) as http:
        resp = await http.get("/authorize", params={
            "response_type": "code", "client_id": CIMD_URL, "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": _pkce()[1], "code_challenge_method": "S256"})
    assert resp.status_code == 400 and "not found" in resp.text


async def test_claude_code_loopback_redirect_matches_any_port(running):
    tokens = await _connect(running, redirect="http://localhost:41234/callback")
    assert tokens["access_token"]
    async with httpx.AsyncClient(base_url=running.base) as http:
        client_id = (await _register(http, "http://127.0.0.1/callback"))["client_id"]
        code, _ = await _authorize(running, http, client_id, "http://127.0.0.1:5555/callback")
        assert code
        resp = await http.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": "http://127.0.0.1:5555/other",
            "code_challenge": _pkce()[1], "code_challenge_method": "S256"})
        assert resp.status_code == 400


@pytest.mark.parametrize("redirect", ["http://claude.ai/cb", "javascript:alert(1)", "myapp://cb",
                                      "https://claude.ai/cb#frag"])
async def test_registration_refuses_unsafe_redirects(running, redirect):
    async with httpx.AsyncClient(base_url=running.base) as http:
        resp = await http.post("/register", json={"client_name": "x", "redirect_uris": [redirect],
                                                  "token_endpoint_auth_method": "none"})
    assert resp.status_code == 400


async def test_token_for_another_resource_is_refused(running):
    async with httpx.AsyncClient(base_url=running.base) as http:
        client_id = (await _register(http))["client_id"]
        resp = await http.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CALLBACK, "state": "s",
            "code_challenge": _pkce()[1], "code_challenge_method": "S256", "resource": "https://other.example/mcp"})
    assert resp.status_code == 302
    assert parse_qs(urlsplit(resp.headers["location"]).query)["error"] == ["invalid_target"]


async def test_declining_returns_access_denied(running):
    async with httpx.AsyncClient(base_url=running.base) as browser:
        client_id = (await _register(browser))["client_id"]
        code, _ = await _authorize(running, browser, client_id)
        await browser.get("/oauth/consent", params={"request": code})
        resp = await browser.get(running.platform.answer(code, approve=False))
    q = parse_qs(urlsplit(resp.headers["location"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["st4te"] and "code" not in q


async def test_approval_cannot_be_finished_in_another_browser(running):
    """Someone who sends a victim the consent link cannot collect the result."""
    async with httpx.AsyncClient(base_url=running.base) as attacker:
        client_id = (await _register(attacker))["client_id"]
        code, _ = await _authorize(running, attacker, client_id)
        await attacker.get("/oauth/consent", params={"request": code})
    callback = running.platform.answer(code)  # the victim approves on GoMobSec
    async with httpx.AsyncClient(base_url=running.base) as victim:
        resp = await victim.get(callback)
    assert resp.status_code == 400 and "same browser" in resp.text
    async with httpx.AsyncClient(base_url=running.base) as attacker_again:  # new jar, no cookie, no nonce
        resp = await attacker_again.get(f"/oauth/callback?request={code}")
    assert resp.status_code == 400


async def test_consent_link_works_once(running):
    async with httpx.AsyncClient(base_url=running.base) as http:
        client_id = (await _register(http))["client_id"]
        code, _ = await _authorize(running, http, client_id)
        assert (await http.get("/oauth/consent", params={"request": code})).status_code == 302
        resp = await http.get("/oauth/consent", params={"request": code})
    assert resp.status_code == 400 and "already opened" in resp.text


async def test_wrong_pkce_verifier_and_code_reuse(running):
    async with httpx.AsyncClient(base_url=running.base) as browser:
        client_id = (await _register(browser))["client_id"]
        code, verifier = await _authorize(running, browser, client_id)
        await browser.get("/oauth/consent", params={"request": code})
        resp = await browser.get(running.platform.answer(code))
        auth_code = parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]
        form = {"grant_type": "authorization_code", "code": auth_code, "redirect_uri": CLAUDE_CALLBACK,
                "client_id": client_id, "code_verifier": "x" * 50}
        assert (await browser.post("/token", data=form)).status_code == 400
        form["code_verifier"] = verifier  # the first attempt burned the code
        assert (await browser.post("/token", data=form)).json()["error"] == "invalid_grant"


# ── tokens ───────────────────────────────────────────────────────────────────
async def test_bad_or_missing_tokens_get_401(running):
    for header in ({}, {"Authorization": "Bearer gmcp_at_nope"}, {"Authorization": f"Bearer {KEY}"}):
        async with httpx.AsyncClient(base_url=running.base) as http:
            resp = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                   headers={"Accept": "application/json, text/event-stream", **header})
        assert resp.status_code == 401


async def test_refresh_rotates_and_reuse_revokes_the_connection(running, monkeypatch):
    tokens = await _connect(running)
    async with httpx.AsyncClient(base_url=running.base) as http:
        form = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                "client_id": tokens["client_id"]}
        fresh = (await http.post("/token", data=form)).json()
        assert fresh["refresh_token"] != tokens["refresh_token"]
        assert not (await _call(running, fresh["access_token"], "whoami"))[0]
        # Replayed straight away (a client race): refused, connection kept.
        assert (await http.post("/token", data=form)).json()["error"] == "invalid_grant"
        assert not (await _call(running, fresh["access_token"], "whoami"))[0]
        # Replayed later: the old token leaked — end the connection and give the key back.
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + REUSE_GRACE_SECONDS + 1)
        assert (await http.post("/token", data=form)).json()["error"] == "invalid_grant"
        monkeypatch.setattr(time, "time", real)
    assert running.platform.revoked == [KEY]
    assert await _status(running, fresh["access_token"]) == 401


async def test_revocation_ends_the_connection(running):
    tokens = await _connect(running)
    async with httpx.AsyncClient(base_url=running.base) as http:
        resp = await http.post("/revoke", data={"token": tokens["refresh_token"], "client_id": tokens["client_id"]})
        assert resp.status_code == 200
    assert running.platform.revoked == [KEY]
    assert await _status(running, tokens["access_token"]) == 401


async def test_nothing_secret_is_stored_in_the_clear(running):
    tokens = await _connect(running)
    dump = json.dumps({k: running.kv._data[k][0] for k in running.kv.keys()})
    for secret in (tokens["access_token"], tokens["refresh_token"], KEY):
        assert secret not in dump


# ── plans and revoked keys ───────────────────────────────────────────────────
async def test_plan_without_api_access_gets_an_upgrade_message(running):
    tokens = await _connect(running)
    running.api.tier = "starter"
    is_error, text = await _call(running, tokens["access_token"], "list_scans")
    assert is_error and "Professional and Enterprise" in text and "starter" in text and "/pricing" in text


async def test_key_revoked_in_gomobsec_disconnects(running):
    tokens = await _connect(running)
    running.api.key = "mbsk_rotated"
    is_error, text = await _call(running, tokens["access_token"], "whoami")
    assert is_error and "Reconnect GoMobSec" in text
    assert await _status(running, tokens["access_token"]) == 401  # the connection is gone
    assert running.platform.revoked == []  # GoMobSec already deactivated it


# ── hosted tools ─────────────────────────────────────────────────────────────
async def test_hosted_tool_catalogue(running):
    tokens = await _connect(running)
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {tokens['access_token']}"})
    async with Client(streamable_http_client(running.resource, http_client=http)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert set(tools) == {"whoami", "get_usage", "list_scans", "get_scan", "get_findings", "start_scan",
                          "wait_for_scan", "get_upload_link", "get_report_link"}
    for name, tool in tools.items():
        assert tool.title, name
        if name == "start_scan":
            assert tool.annotations.read_only_hint is False and tool.annotations.destructive_hint is False
        else:
            assert tool.annotations.read_only_hint is True, name
    assert "file_url" in tools["start_scan"].input_schema["properties"]
    assert "file_path" not in tools["start_scan"].input_schema["properties"]
    assert "1-4 minutes" in tools["wait_for_scan"].description


async def test_start_scan_from_a_public_link(running):
    tokens = await _connect(running)
    running.downloads["https://cdn.example/builds/app-release.apk"] = httpx.Response(200, content=APK)
    is_error, text = await _call(running, tokens["access_token"], "start_scan",
                                 {"file_url": "https://cdn.example/builds/app-release.apk"})
    assert not is_error, text
    assert "Scan started" in text and "app-release.apk" in text
    upload = [r for r in running.api.requests if r.method == "POST"][0]
    assert APK in upload.content


@pytest.mark.parametrize("url,reason", [
    ("http://cdn.example/a.apk", "Only https"),
    ("https://internal.example/a.apk", "not a public internet address"),
    ("https://rebind.example/a.apk", "not a public internet address"),
    ("https://10.1.2.3/a.apk", "not a public internet address"),
    ("https://user:pw@cdn.example/a.apk", "username or password"),
    ("https://cdn.example:8443/a.apk", "port"),
    ("https://cdn.example/notes.txt", "does not point to an app package"),
])
async def test_start_scan_refuses_unsafe_links(running, url, reason):
    tokens = await _connect(running)
    running.downloads["https://cdn.example/notes.txt"] = httpx.Response(200, content=b"hi")
    is_error, text = await _call(running, tokens["access_token"], "start_scan", {"file_url": url})
    assert is_error and reason in text, text
    assert not [r for r in running.api.requests if r.method == "POST"]


async def test_start_scan_rechecks_redirect_targets(running):
    tokens = await _connect(running)
    running.downloads["https://cdn.example/latest.apk"] = httpx.Response(
        302, headers={"location": "https://internal.example/app.apk"})
    is_error, text = await _call(running, tokens["access_token"], "start_scan",
                                 {"file_url": "https://cdn.example/latest.apk"})
    assert is_error and "not a public internet address" in text


async def test_start_scan_refuses_non_zip_and_oversize(running, monkeypatch):
    tokens = await _connect(running)
    running.downloads["https://cdn.example/fake.apk"] = httpx.Response(200, content=b"MZ not a zip")
    is_error, text = await _call(running, tokens["access_token"], "start_scan",
                                 {"file_url": "https://cdn.example/fake.apk"})
    assert is_error and "not a zip archive" in text
    from gomobsec_mcp import files
    monkeypatch.setattr(files, "MAX_UPLOAD_BYTES", 100)
    running.downloads["https://cdn.example/big.apk"] = httpx.Response(200, content=APK)
    is_error, text = await _call(running, tokens["access_token"], "start_scan",
                                 {"file_url": "https://cdn.example/big.apk"})
    assert is_error and "MB limit" in text


async def test_upload_and_report_links(running):
    tokens = await _connect(running)
    sid = running.api.add_scan()
    assert "https://gomobsec.test/scan/new" in (await _call(running, tokens["access_token"], "get_upload_link"))[1]
    is_error, text = await _call(running, tokens["access_token"], "get_report_link", {"scan_id": sid})
    assert not is_error and f"https://gomobsec.test/scan/{sid}/results" in text and "SARIF" in text


async def test_transport_refuses_foreign_origins(running):
    tokens = await _connect(running)
    async with httpx.AsyncClient(base_url=running.base) as http:
        resp = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                               headers={"Accept": "application/json, text/event-stream",
                                        "Authorization": f"Bearer {tokens['access_token']}",
                                        "Origin": "https://evil.example"})
    assert resp.status_code == 403


# ── configuration ────────────────────────────────────────────────────────────
def test_settings_require_every_secret():
    with pytest.raises(ConfigError) as exc:
        HostedSettings.from_env({"GOMOBSEC_MCP_PUBLIC_URL": "http://mcp.example"})
    msg = str(exc.value)
    for name in ("GOMOBSEC_MCP_PUBLIC_URL", "GOMOBSEC_MCP_SERVICE_TOKEN", "GOMOBSEC_MCP_ENCRYPTION_KEY",
                 "GOMOBSEC_MCP_REDIS_URL"):
        assert name in msg


def test_settings_from_env():
    s = HostedSettings.from_env({
        "GOMOBSEC_MCP_PUBLIC_URL": "https://mcp.gomobsec.ai/",
        "GOMOBSEC_MCP_SERVICE_TOKEN": "s" * 40,
        "GOMOBSEC_MCP_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
        "GOMOBSEC_MCP_REDIS_URL": "redis://redis:6379/3",
        "GOMOBSEC_API_URL": "http://api:8000",
    })
    assert s.resource_url == "https://mcp.gomobsec.ai/mcp" and s.public_host == "mcp.gomobsec.ai"
    assert s.api_url == "http://api:8000" and "https://claude.ai" in s.allowed_origins


def test_hosted_key_help_says_how_to_reconnect():
    assert "Reconnect" in app_mod.HOSTED_KEY_HELP
