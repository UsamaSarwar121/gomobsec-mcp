"""Settings for the hosted connector, read from the environment.

Unlike the local server, a hosted server that is missing a secret must not
start: it would accept sign-ins it can never complete.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from gomobsec_mcp.config import DEFAULT_API_URL, DEFAULT_APP_URL

# The one OAuth scope: use GoMobSec through this connector as the signed-in user.
SCOPE = "gomobsec"
# Origins whose browsers may call /mcp directly. Claude calls from its servers
# (no Origin header); these cover browser-based MCP clients on Anthropic's sites.
DEFAULT_ALLOWED_ORIGINS = ("https://claude.ai", "https://claude.com")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class HostedSettings:
    # Where users reach this server, without a trailing slash; also the OAuth issuer.
    public_url: str
    # Where this server reaches the GoMobSec API (inside compose: http://api:8000).
    api_url: str
    # The web app, for links shown to users.
    app_url: str
    redis_url: str
    # Shared with the platform (MCP_CONNECTOR_SERVICE_TOKEN there).
    service_token: str
    # 32 bytes; seals the API keys this server holds.
    encryption_key: bytes
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    host: str = "0.0.0.0"
    port: int = 8080

    @property
    def resource_url(self) -> str:
        """The MCP endpoint, and the resource every token is bound to (RFC 8707)."""
        return f"{self.public_url}/mcp"

    @property
    def public_host(self) -> str:
        return urlsplit(self.public_url).netloc

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> HostedSettings:
        def get(name: str, default: str = "") -> str:
            return env.get(name, default).strip()

        problems: list[str] = []
        public_url = get("GOMOBSEC_MCP_PUBLIC_URL").rstrip("/")
        parts = urlsplit(public_url)
        local = parts.hostname in ("localhost", "127.0.0.1")
        if not parts.netloc or parts.path or (parts.scheme != "https" and not (local and parts.scheme == "http")):
            problems.append("GOMOBSEC_MCP_PUBLIC_URL must be an https origin, e.g. https://mcp.gomobsec.ai")

        token = get("GOMOBSEC_MCP_SERVICE_TOKEN")
        if len(token) < 32:
            problems.append("GOMOBSEC_MCP_SERVICE_TOKEN must be at least 32 characters "
                            "(the platform's MCP_CONNECTOR_SERVICE_TOKEN)")

        key = b""
        try:
            key = base64.urlsafe_b64decode(get("GOMOBSEC_MCP_ENCRYPTION_KEY") + "==")
        except (binascii.Error, ValueError):
            pass
        if len(key) != 32:
            problems.append("GOMOBSEC_MCP_ENCRYPTION_KEY must be 32 random bytes, urlsafe-base64 encoded")

        redis_url = get("GOMOBSEC_MCP_REDIS_URL")
        if not redis_url:
            problems.append("GOMOBSEC_MCP_REDIS_URL is required")

        if problems:
            raise ConfigError("Cannot start the hosted GoMobSec connector:\n- " + "\n- ".join(problems))

        extra = tuple(o.strip().rstrip("/") for o in get("GOMOBSEC_MCP_ALLOWED_ORIGINS").split(",") if o.strip())
        return cls(
            public_url=public_url,
            api_url=get("GOMOBSEC_API_URL", DEFAULT_API_URL).rstrip("/"),
            app_url=get("GOMOBSEC_APP_URL", DEFAULT_APP_URL).rstrip("/"),
            redis_url=redis_url,
            service_token=token,
            encryption_key=key,
            allowed_origins=tuple(dict.fromkeys((*DEFAULT_ALLOWED_ORIGINS, public_url, *extra))),
            host=get("GOMOBSEC_MCP_HOST", "0.0.0.0"),
            port=int(get("GOMOBSEC_MCP_PORT", "8080")),
        )
