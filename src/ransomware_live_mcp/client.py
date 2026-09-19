"""HTTP client for the ransomware.live PRO API.

Handles auth, retries, and an in-memory TTL cache. The PRO tier allows
500k calls/month but applies a fair-use policy, so repeated identical
lookups inside a session are served from cache.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api-pro.ransomware.live"
USER_AGENT = "ransomware-live-mcp/0.1.0"


class ApiError(RuntimeError):
    """Raised when the API returns an error the caller should see verbatim."""


class MissingApiKey(ApiError):
    pass


class _TTLCache:
    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        hit = self._data.get(key)
        if hit is None:
            return None
        expires, value = hit
        if expires < time.monotonic():
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if self._ttl > 0:
            self._data[key] = (time.monotonic() + self._ttl, value)

    def clear(self) -> None:
        self._data.clear()


class RansomwareLiveClient:
    """Thin async wrapper around the PRO API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv("RANSOMWARE_LIVE_API_KEY", "")
        self._base_url = (base_url or os.getenv("RANSOMWARE_LIVE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout if timeout is not None else float(os.getenv("RANSOMWARE_LIVE_TIMEOUT", "30"))
        ttl = cache_ttl if cache_ttl is not None else float(os.getenv("RANSOMWARE_LIVE_CACHE_TTL", "300"))
        self._cache = _TTLCache(ttl)
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    async def _get_client(self) -> httpx.AsyncClient:
        async with self._lock:
            if self._client is None or self._client.is_closed:
                self._client = httpx.AsyncClient(
                    base_url=self._base_url,
                    timeout=self._timeout,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                    follow_redirects=True,
                )
            return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    def _auth_headers(self) -> dict[str, str]:
        if not self._api_key:
            raise MissingApiKey(
                "No API key configured. Set RANSOMWARE_LIVE_API_KEY in the environment "
                "or in a .env file next to the server. Get a free key at https://my.ransomware.live"
            )
        return {"X-API-KEY": self._api_key}

    @staticmethod
    def _cache_key(path: str, params: dict[str, Any] | None) -> str:
        if not params:
            return path
        rendered = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        return f"{path}?{rendered}"

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        use_cache: bool = True,
        max_retries: int = 3,
    ) -> Any:
        """GET a path and return decoded JSON, retrying transient failures."""
        params = {k: v for k, v in (params or {}).items() if v is not None}
        key = self._cache_key(path, params)

        if use_cache:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        client = await self._get_client()
        headers = self._auth_headers()
        last_error: str = "request failed"

        for attempt in range(max_retries):
            try:
                response = await client.get(path, params=params, headers=headers)
            except httpx.TimeoutException:
                last_error = f"request to {path} timed out after {self._timeout}s"
            except httpx.HTTPError as exc:
                last_error = f"network error calling {path}: {exc}"
            else:
                if response.status_code == 200:
                    payload = self._decode(response, path)
                    if use_cache:
                        self._cache.set(key, payload)
                    return payload

                if response.status_code in (401, 403):
                    raise ApiError(
                        f"API key rejected ({response.status_code}). Verify the key with the "
                        f"`validate_api_key` tool or regenerate it at https://my.ransomware.live"
                    )
                if response.status_code == 404:
                    raise ApiError(f"Not found: {path} returned 404. Check the name or ID is correct.")
                if response.status_code == 429:
                    delay = self._retry_after(response, attempt)
                    last_error = f"rate limited on {path} (HTTP 429)"
                    if attempt < max_retries - 1:
                        await asyncio.sleep(delay)
                        continue
                    raise ApiError(
                        f"{last_error}. The free tier allows 1 request/minute per endpoint; "
                        f"PRO allows 500k calls/month. Wait and retry."
                    )
                if response.status_code >= 500:
                    last_error = f"server error {response.status_code} on {path}"
                else:
                    raise ApiError(
                        f"HTTP {response.status_code} on {path}: {response.text[:300]}"
                    )

            if attempt < max_retries - 1:
                await asyncio.sleep(2**attempt)

        raise ApiError(last_error)

    @staticmethod
    def _retry_after(response: httpx.Response, attempt: int) -> float:
        raw = response.headers.get("Retry-After")
        if raw:
            try:
                return min(float(raw), 60.0)
            except ValueError:
                pass
        return float(2**attempt)

    @staticmethod
    def _decode(response: httpx.Response, path: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise ApiError(f"{path} returned non-JSON content: {response.text[:200]}") from exc
