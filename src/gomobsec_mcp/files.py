"""Local file handling: what may be uploaded, and where reports are written.

An MCP tool's arguments come from a model, and a model can be steered by text
it has read. So the file rules are deliberately narrow:

- ``start_scan`` only sends files that *are* mobile app packages: the right
  extension, a zip archive (APK, IPA and every split-bundle format is one), and
  within the platform's size cap. It cannot be talked into uploading
  ``~/.ssh/id_rsa``.
- ``download_report`` never takes a path. It writes a fixed file name into one
  configured directory (``GOMOBSEC_DOWNLOAD_DIR``) and never overwrites.
"""

from __future__ import annotations

import os
from pathlib import Path

from gomobsec_mcp.client import GoMobSecError

# What the GoMobSec web app accepts.
ALLOWED_EXTENSIONS = (".apk", ".xapk", ".apks", ".apkm", ".ipa")
MAX_UPLOAD_BYTES = 250 * 1024 * 1024  # the platform's cap (ingestion.validator.MAX_FILE_SIZE)
REPORT_FORMATS = ("docx", "xlsx", "json", "sarif")
_ZIP_MAGIC = b"PK\x03\x04"


def check_upload(file_path: str) -> Path:
    """Resolve and vet a file the user wants scanned, or raise a clear refusal."""
    if not file_path or not file_path.strip():
        raise GoMobSecError("Give the path of an .apk or .ipa file to scan.")
    path = Path(file_path.strip()).expanduser()
    try:
        path = path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError):
        raise GoMobSecError(f"No file at {file_path!r}.") from None
    if not path.is_file():
        raise GoMobSecError(f"{path} is not a file.")
    if not path.name.lower().endswith(ALLOWED_EXTENSIONS):
        raise GoMobSecError(
            "Only mobile app packages can be scanned: .apk, .xapk, .apks, .apkm (Android) or .ipa (iOS).")
    size = path.stat().st_size
    if size == 0:
        raise GoMobSecError(f"{path.name} is empty.")
    if size > MAX_UPLOAD_BYTES:
        raise GoMobSecError(
            f"{path.name} is {size / 1_048_576:.0f} MB; GoMobSec accepts up to {MAX_UPLOAD_BYTES // 1_048_576} MB.")
    with path.open("rb") as fh:
        if fh.read(4) != _ZIP_MAGIC:
            raise GoMobSecError(f"{path.name} is not an APK or IPA (it is not a zip archive).")
    return path


def save_report(download_dir: Path, filename: str, content: bytes) -> Path:
    """Write a report into ``download_dir`` without overwriting anything."""
    download_dir.mkdir(parents=True, exist_ok=True)
    stem, dot, ext = filename.rpartition(".")
    candidate = download_dir / filename
    n = 1
    while True:
        try:
            # O_EXCL: never follow or replace something already there.
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            n += 1
            candidate = download_dir / f"{stem}-{n}{dot}{ext}"
    with os.fdopen(fd, "wb") as out:
        out.write(content)
    return candidate
