"""Where OAuth state lives: Redis in production, a dict in tests.

Everything stored is short-lived and expires on its own: pending sign-ins (10
minutes), authorization codes (5 minutes), access tokens (1 hour), refresh
tokens and connections (30 days of inactivity), registered clients (90 days).
Tokens are stored under their SHA-256, never in the clear; the API key each
connection holds is sealed (see :mod:`gomobsec_mcp.hosted.seal`).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

PREFIX = "gmcp:"


class KV(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, *, ttl: int, nx: bool = False) -> bool: ...

    async def getdel(self, key: str) -> str | None: ...

    async def delete(self, *keys: str) -> None: ...

    async def expire(self, key: str, ttl: int) -> None: ...

    async def ping(self) -> bool: ...


class RedisKV:
    def __init__(self, url: str) -> None:
        import redis.asyncio as aioredis

        self._r = aioredis.from_url(url, decode_responses=True, socket_timeout=5, socket_connect_timeout=5)

    async def get(self, key: str) -> str | None:
        return await self._r.get(PREFIX + key)

    async def set(self, key: str, value: str, *, ttl: int, nx: bool = False) -> bool:
        return bool(await self._r.set(PREFIX + key, value, ex=ttl, nx=nx))

    async def getdel(self, key: str) -> str | None:
        return await self._r.getdel(PREFIX + key)

    async def delete(self, *keys: str) -> None:
        if keys:
            await self._r.delete(*(PREFIX + k for k in keys))

    async def expire(self, key: str, ttl: int) -> None:
        await self._r.expire(PREFIX + key, ttl)

    async def ping(self) -> bool:
        try:
            return bool(await self._r.ping())
        except Exception:  # noqa: BLE001 - a health check reports, it does not raise
            return False


class MemoryKV:
    """The same contract in memory, with an injectable clock (tests, local dev)."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._clock = clock

    def _live(self, key: str) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        if item[1] <= self._clock():
            del self._data[key]
            return None
        return item[0]

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def set(self, key: str, value: str, *, ttl: int, nx: bool = False) -> bool:
        if nx and self._live(key) is not None:
            return False
        self._data[key] = (value, self._clock() + ttl)
        return True

    async def getdel(self, key: str) -> str | None:
        value = self._live(key)
        self._data.pop(key, None)
        return value

    async def delete(self, *keys: str) -> None:
        for k in keys:
            self._data.pop(k, None)

    async def expire(self, key: str, ttl: int) -> None:
        value = self._live(key)
        if value is not None:
            self._data[key] = (value, self._clock() + ttl)

    async def ping(self) -> bool:
        return True

    def keys(self) -> list[str]:
        return [k for k in list(self._data) if self._live(k) is not None]
