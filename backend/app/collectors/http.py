"""Shared outbound HTTP client for collectors (docs/architettura.md §5.4, §7.1).

Every request a collector makes goes through `SourceHttpClient`, which applies:
- the per-source cache with TTL, including conditional requests (ETag/Last-Modified);
- the declared quota, checked before each request and counted per attempt;
- the rate limit (sliding window);
- retries with backoff on network errors, 429 and 5xx (honouring Retry-After).

Secrets (API keys) must be passed as `secret_headers`: they are sent but never
used in the cache key, stored or included in error messages.
"""

import asyncio
import hashlib
import json
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

from app import __version__
from app.collectors.base import Quota, QuotaPeriod, RateLimit
from app.core.classification import Classification
from app.core.config import Settings

USER_AGENT = f"SpeculaThreat/{__version__} (+https://github.com/sandrosana/specula-platform)"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 300.0


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class CachedResponse:
    key: str
    source: str
    url: str
    status: int
    content_type: str | None
    body: bytes
    etag: str | None
    last_modified: str | None
    fetched_at: datetime
    expires_at: datetime
    classification: Classification


@dataclass(frozen=True)
class HttpResult:
    status: int
    content: bytes
    content_type: str | None
    from_cache: bool

    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.content)


class CacheStore(Protocol):
    async def get(self, key: str) -> CachedResponse | None: ...

    async def put(self, entry: CachedResponse) -> None: ...


class UsageStore(Protocol):
    async def increment(self, source: str, day: date) -> None: ...

    async def total(self, source: str, since: date) -> int: ...


class SourceHttpError(Exception):
    """The source answered with an error, or could not be reached after retries."""

    def __init__(self, source: str, url: str, status: int | None) -> None:
        reason = f"HTTP {status}" if status is not None else "network error"
        # Only the URL without query string: parameters may contain identifiers.
        super().__init__(f"{source}: GET {url.split('?', 1)[0]} failed ({reason})")
        self.source = source
        self.status = status


class QuotaExceededError(Exception):
    """The declared quota of the source is used up for the current period."""


def cache_key(method: str, url: str, params: Mapping[str, str]) -> str:
    """Stable key: method, URL and sorted query parameters. Secrets are never part of it."""
    canonical = f"{method.upper()} {url}?{urlencode(sorted(params.items()))}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def period_start(day: date, period: QuotaPeriod) -> date:
    return day if period == "day" else day.replace(day=1)


def create_http_client(settings: Settings) -> httpx.AsyncClient:
    """The underlying client. Proxy comes only from Settings, never from the environment."""
    return httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        proxy=settings.https_proxy,
        trust_env=False,
        follow_redirects=True,
    )


class RateLimiter:
    """Sliding window: at most `limit.requests` acquisitions per `limit.per`."""

    def __init__(
        self,
        limit: RateLimit,
        monotonic: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
    ) -> None:
        self._limit = limit
        self._monotonic = monotonic
        self._sleep = sleep
        self._stamps: deque[float] = deque()

    async def acquire(self) -> None:
        window = self._limit.per.total_seconds()
        while True:
            now = self._monotonic()
            while self._stamps and now - self._stamps[0] >= window:
                self._stamps.popleft()
            if len(self._stamps) < self._limit.requests:
                self._stamps.append(now)
                return
            await self._sleep(window - (now - self._stamps[0]))


class SourceHttpClient:
    def __init__(
        self,
        *,
        source: str,
        client: httpx.AsyncClient,
        cache: CacheStore,
        usage: UsageStore,
        cache_ttl: timedelta,
        classification: Classification,
        rate_limit: RateLimit | None = None,
        quota: Quota | None = None,
        max_attempts: int = 4,
        backoff_seconds: float = 2.0,
        now: Callable[[], datetime] = utcnow,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._source = source
        self._client = client
        self._cache = cache
        self._usage = usage
        self._cache_ttl = cache_ttl
        self._classification = classification
        self._quota = quota
        self._max_attempts = max_attempts
        self._backoff_seconds = backoff_seconds
        self._now = now
        self._sleep = sleep
        self._limiter = RateLimiter(rate_limit, monotonic, sleep) if rate_limit else None

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        secret_headers: Mapping[str, str] | None = None,
        use_cache: bool = True,
        store: bool = True,
        read_timeout: float | None = None,
    ) -> HttpResult:
        """GET with cache.

        `use_cache=False` (forced runs) ignores and refreshes the cache. `store=False`
        bypasses the cache entirely, for large one-off responses (e.g. NVD pages).
        `read_timeout` (seconds) overrides the default read timeout for slow sources.
        """
        query = dict(params or {})
        key = cache_key("GET", url, query)
        cached = await self._cache.get(key) if use_cache and store else None
        if cached is not None and cached.expires_at > self._now():
            return self._result(cached, from_cache=True)

        request_headers = dict(headers or {})
        if cached is not None:
            if cached.etag:
                request_headers["If-None-Match"] = cached.etag
            if cached.last_modified:
                request_headers["If-Modified-Since"] = cached.last_modified
        request_headers.update(secret_headers or {})

        response = await self._send(url, query, request_headers, read_timeout)
        now = self._now()
        if response.status_code == 304 and cached is not None:
            renewed = replace(cached, fetched_at=now, expires_at=now + self._cache_ttl)
            await self._cache.put(renewed)
            return self._result(renewed, from_cache=True)
        if response.status_code != 200:
            raise SourceHttpError(self._source, url, response.status_code)

        entry = CachedResponse(
            key=key,
            source=self._source,
            url=url,
            status=response.status_code,
            content_type=response.headers.get("content-type"),
            body=response.content,
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
            fetched_at=now,
            expires_at=now + self._cache_ttl,
            classification=self._classification,
        )
        if store:
            await self._cache.put(entry)
        return self._result(entry, from_cache=False)

    async def _send(
        self,
        url: str,
        params: Mapping[str, str],
        headers: Mapping[str, str],
        read_timeout: float | None = None,
    ) -> httpx.Response:
        request_timeout = (
            httpx.Timeout(read_timeout, connect=DEFAULT_TIMEOUT.connect) if read_timeout else None
        )
        for attempt in range(1, self._max_attempts + 1):
            await self._check_quota()
            if self._limiter is not None:
                await self._limiter.acquire()
            # Every attempt counts towards the quota, including failed ones.
            await self._usage.increment(self._source, self._now().date())
            last_attempt = attempt == self._max_attempts
            try:
                if request_timeout is None:
                    response = await self._client.get(url, params=params, headers=headers)
                else:
                    response = await self._client.get(
                        url, params=params, headers=headers, timeout=request_timeout
                    )
            except httpx.TransportError as exc:
                if last_attempt:
                    raise SourceHttpError(self._source, url, None) from exc
                await self._sleep(self._backoff(attempt))
                continue
            if response.status_code in RETRY_STATUSES and not last_attempt:
                await self._sleep(self._retry_delay(response, attempt))
                continue
            return response
        raise AssertionError("unreachable")  # pragma: no cover

    async def _check_quota(self) -> None:
        if self._quota is None:
            return
        since = period_start(self._now().date(), self._quota.period)
        used = await self._usage.total(self._source, since)
        if used >= self._quota.limit:
            raise QuotaExceededError(
                f"{self._source}: quota of {self._quota.limit} requests per "
                f"{self._quota.period} reached"
            )

    def _backoff(self, attempt: int) -> float:
        return float(self._backoff_seconds * 2 ** (attempt - 1))

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("retry-after", "")
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
        return self._backoff(attempt)

    @staticmethod
    def _result(entry: CachedResponse, *, from_cache: bool) -> HttpResult:
        return HttpResult(
            status=entry.status,
            content=entry.body,
            content_type=entry.content_type,
            from_cache=from_cache,
        )
