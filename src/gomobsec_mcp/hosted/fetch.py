"""Fetching from links a model passed in, without reaching anything private.

The hosted connector downloads two kinds of things from URLs it did not
choose: apps to scan (``start_scan``'s ``file_url``) and OAuth Client ID
Metadata Documents (the ``client_id`` *is* a URL). Both come from the
internet's side of the trust boundary, and the server sits next to Redis and
the GoMobSec API. So every request:

- is ``https`` on port 443, with no credentials in the URL;
- resolves the host itself and refuses unless **every** address is public
  (no loopback, private, link-local, CGNAT, multicast or reserved ranges, and
  no IPv4 hidden in IPv6);
- connects to the address it checked — the URL host is replaced by the IP,
  with the real name kept for SNI, certificate checks and ``Host`` — so a DNS
  answer that changes between the check and the connection cannot redirect it;
- follows at most three redirects, each checked the same way;
- stops at a size cap and an overall deadline.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import unquote

import anyio
import httpx

from gomobsec_mcp import __version__, files
from gomobsec_mcp.client import GoMobSecError

Resolver = Callable[[str, int], Awaitable[list[str]]]

MAX_REDIRECTS = 3
DOWNLOAD_DEADLINE_SECONDS = 600
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_DISPOSITION_NAME = re.compile(r"""filename\*?=(?:UTF-8'')?["']?([^"';]+)""", re.IGNORECASE)


class FetchError(GoMobSecError):
    """A refusal or failure, phrased for the user."""


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def is_public_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None:
            ip = embedded
    return ip.is_global and not ip.is_multicast


def check_url(url: str) -> httpx.URL:
    try:
        u = httpx.URL(url.strip())
    except (httpx.InvalidURL, TypeError, AttributeError):
        raise FetchError("That is not a valid link.") from None
    if u.scheme != "https":
        raise FetchError("Only https links can be used.")
    if not u.host:
        raise FetchError("That is not a valid link.")
    if u.userinfo:
        raise FetchError("Links with a username or password in them are not accepted.")
    if u.port not in (None, 443):
        raise FetchError("Only links on the standard https port (443) can be used.")
    return u


class PublicFetcher:
    def __init__(self, *, resolver: Resolver = system_resolver,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._resolve = resolver
        self._http = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"User-Agent": f"gomobsec-mcp/{__version__} (+https://gomobsec.ai)"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _pinned(self, u: httpx.URL) -> httpx.Response:
        host = u.host
        try:
            # An IP-literal host is its own (only) address.
            addrs = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addrs = await self._resolve(host, 443)
            except OSError:
                raise FetchError(f"Could not find the host {host!r}.") from None
        if not addrs or not all(is_public_address(a) for a in addrs):
            raise FetchError(f"{host!r} is not a public internet address, so it cannot be fetched.")
        request = self._http.build_request(
            "GET", u.copy_with(host=addrs[0]),
            headers={"Host": host},
            extensions={"sni_hostname": host},
        )
        try:
            return await self._http.send(request, stream=True)
        except httpx.TimeoutException:
            raise FetchError(f"{host} did not answer in time.") from None
        except httpx.HTTPError:
            raise FetchError(f"Could not download from {host}.") from None

    @asynccontextmanager
    async def get(self, url: str) -> AsyncIterator[tuple[httpx.URL, httpx.Response]]:
        """``GET`` a public https URL; yields the final URL and the streaming response."""
        u = check_url(url)
        for _ in range(MAX_REDIRECTS + 1):
            resp = await self._pinned(u)
            if not resp.is_redirect:
                break
            location = resp.headers.get("location", "")
            await resp.aclose()
            u = check_url(str(u.join(location)))
        else:
            raise FetchError("The link redirects too many times.")
        try:
            yield u, resp
        finally:
            await resp.aclose()

    async def get_small(self, url: str, max_bytes: int) -> bytes:
        """A small document (e.g. JSON metadata), refusing anything larger."""
        async with self.get(url) as (_, resp):
            if resp.status_code != 200:
                raise FetchError(f"The link answered HTTP {resp.status_code}.")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise FetchError("The document is too large.")
            return bytes(body)

    @asynccontextmanager
    async def fetch_app(self, url: str) -> AsyncIterator[Path]:
        """Download an app package into a private temp dir; yields its path."""
        limit = files.MAX_UPLOAD_BYTES
        with tempfile.TemporaryDirectory(prefix="gomobsec-") as tmp:
            try:
                with anyio.fail_after(DOWNLOAD_DEADLINE_SECONDS):
                    async with self.get(url) as (final, resp):
                        if resp.status_code != 200:
                            raise FetchError(
                                f"The link answered HTTP {resp.status_code}. Use a direct download link "
                                "that works without signing in.")
                        declared = resp.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > limit:
                            raise FetchError(f"The file is over GoMobSec's {limit // 1_048_576} MB limit.")
                        path = Path(tmp) / _app_name(final, resp.headers.get("content-disposition", ""))
                        size = 0
                        with path.open("wb") as out:
                            async for chunk in resp.aiter_bytes():
                                size += len(chunk)
                                if size > limit:
                                    raise FetchError(f"The file is over GoMobSec's {limit // 1_048_576} MB limit.")
                                out.write(chunk)
            except TimeoutError:
                raise FetchError("The download took too long.") from None
            yield path


def _app_name(final: httpx.URL, disposition: str) -> str:
    """A safe local file name with the package's extension, or a clear refusal."""
    candidates = []
    m = _DISPOSITION_NAME.search(disposition)
    if m:
        candidates.append(unquote(m.group(1)))
    candidates.append(unquote(final.path.rsplit("/", 1)[-1]))
    for name in candidates:
        name = _SAFE_NAME.sub("_", name.strip()).strip("._")[-100:]
        if name.lower().endswith(files.ALLOWED_EXTENSIONS):
            return name
    raise FetchError(
        "The link does not point to an app package. It must download an .apk, .xapk, .apks, .apkm "
        "or .ipa file directly.")
