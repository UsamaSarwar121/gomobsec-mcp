"""Settings, read from the environment the MCP client starts the server with.

``GOMOBSEC_API_KEY`` is not required at start-up: a server that refuses to
start shows up in most MCP clients as an unexplained red dot, whereas a tool
that answers "set GOMOBSEC_API_KEY" tells the user exactly what to do.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_API_URL = "https://api.gomobsec.ai"
DEFAULT_APP_URL = "https://gomobsec.ai"


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    api_url: str
    app_url: str
    # The only directory download_report writes to.
    download_dir: Path

    def report_url(self, scan_id: str) -> str:
        return f"{self.app_url}/scan/{scan_id}/results"

    @classmethod
    def from_env(cls) -> "Settings":
        key = os.environ.get("GOMOBSEC_API_KEY", "").strip() or None
        download = os.environ.get("GOMOBSEC_DOWNLOAD_DIR", "").strip()
        return cls(
            api_key=key,
            api_url=os.environ.get("GOMOBSEC_API_URL", DEFAULT_API_URL).strip().rstrip("/"),
            app_url=os.environ.get("GOMOBSEC_APP_URL", DEFAULT_APP_URL).strip().rstrip("/"),
            download_dir=Path(download).expanduser() if download else Path.home() / "Downloads" / "gomobsec",
        )
