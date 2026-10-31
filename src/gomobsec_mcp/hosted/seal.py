"""Sealing the API keys the connector holds (AES-256-GCM).

A Redis dump alone does not hand out working GoMobSec keys. Each sealed value
is bound to the connection it belongs to (associated data), so one cannot be
moved under another connection's id.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Sealer:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the sealing key must be 32 bytes")
        self._aead = AESGCM(key)

    def seal(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext.encode(), context.encode())
        return base64.urlsafe_b64encode(nonce + ct).decode()

    def open(self, sealed: str, context: str) -> str | None:
        """The plaintext, or ``None`` if the value is damaged or not for ``context``."""
        try:
            raw = base64.urlsafe_b64decode(sealed.encode())
            return self._aead.decrypt(raw[:12], raw[12:], context.encode()).decode()
        except (InvalidTag, ValueError, UnicodeDecodeError):
            return None
