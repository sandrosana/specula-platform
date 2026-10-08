from collections.abc import AsyncIterator
from datetime import date, timedelta

import httpx
import pytest
import respx
from pydantic import SecretStr

from app.collectors.base import Quota, RateLimit
from app.collectors.http import (
    USER_AGENT,
    QuotaExceededError,
    SourceHttpClient,
    SourceHttpError,
    cache_key,
    create_http_client,
    period_start,
)
from app.core.classification import Classification
from app.core.config import Settings
from tests.collectors.fakes import FakeClock, MemoryCacheStore, MemoryUsageStore

FEED = "https://feeds.example.test/feed.json"
TTL = timedelta(hours=1)
SECRET = "s3cret-key-value"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache() -> MemoryCacheStore:
    return MemoryCacheStore()


@pytest.fixture
def usage() -> MemoryUsageStore:
    return MemoryUsageStore()


@pytest.fixture
async def raw_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
def make_client(
    raw_client: httpx.AsyncClient,
    cache: MemoryCacheStore,
    usage: MemoryUsageStore,
    clock: FakeClock,
) -> "ClientFactory":
    return ClientFactory(raw_client, cache, usage, clock)


class ClientFactory:
    def __init__(
        self,
        raw_client: httpx.AsyncClient,
        cache: MemoryCacheStore,
        usage: MemoryUsageStore,
        clock: FakeClock,
    ) -> None:
        self._args = (raw_client, cache, usage, clock)

    def __call__(
        self, *, rate_limit: RateLimit | None = None, quota: Quota | None = None
    ) -> SourceHttpClient:
        raw_client, cache, usage, clock = self._args
        return SourceHttpClient(
            source="example_feed",
            client=raw_client,
            cache=cache,
            usage=usage,
            cache_ttl=TTL,
            classification=Classification.PUBLIC,
            rate_limit=rate_limit,
            quota=quota,
            now=clock.now,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )


def used(usage: MemoryUsageStore) -> int:
    return sum(usage.counts.values())


@pytest.mark.anyio
async def test_response_is_cached_within_ttl(
    respx_mock: respx.MockRouter,
    make_client: ClientFactory,
    cache: MemoryCacheStore,
    usage: MemoryUsageStore,
    clock: FakeClock,
) -> None:
    route = respx_mock.get(FEED).mock(return_value=httpx.Response(200, json={"items": [1]}))
    client = make_client()

    first = await client.get(FEED)
    clock.advance(TTL.total_seconds() - 1)
    second = await client.get(FEED)

    assert first.from_cache is False
    assert first.json() == {"items": [1]}
    assert second.from_cache is True
    assert second.content == first.content
    assert route.call_count == 1
    assert used(usage) == 1
    entry = next(iter(cache.entries.values()))
    assert entry.classification is Classification.PUBLIC


@pytest.mark.anyio
async def test_expired_entry_is_revalidated_with_etag(
    respx_mock: respx.MockRouter,
    make_client: ClientFactory,
    cache: MemoryCacheStore,
    clock: FakeClock,
) -> None:
    route = respx_mock.get(FEED).mock(
        side_effect=[
            httpx.Response(200, content=b"v1", headers={"ETag": '"abc"'}),
            httpx.Response(304),
        ]
    )
    client = make_client()

    await client.get(FEED)
    clock.advance(TTL.total_seconds() + 1)
    revalidated = await client.get(FEED)

    assert route.call_count == 2
    assert route.calls.last.request.headers["If-None-Match"] == '"abc"'
    assert revalidated.content == b"v1"
    assert revalidated.from_cache is True
    entry = next(iter(cache.entries.values()))
    assert entry.expires_at == clock.now() + TTL


@pytest.mark.anyio
async def test_forced_request_ignores_cache(
    respx_mock: respx.MockRouter, make_client: ClientFactory
) -> None:
    route = respx_mock.get(FEED).mock(
        return_value=httpx.Response(200, content=b"fresh", headers={"ETag": '"abc"'})
    )
    client = make_client()

    await client.get(FEED)
    forced = await client.get(FEED, use_cache=False)

    assert route.call_count == 2
    assert "If-None-Match" not in route.calls.last.request.headers
    assert forced.from_cache is False


@pytest.mark.anyio
async def test_secret_headers_are_sent_but_not_stored(
    respx_mock: respx.MockRouter, make_client: ClientFactory, cache: MemoryCacheStore
) -> None:
    route = respx_mock.get(FEED).mock(return_value=httpx.Response(200, content=b"ok"))
    client = make_client()

    await client.get(FEED, params={"page": "1"}, secret_headers={"X-Api-Key": SECRET})

    assert route.calls.last.request.headers["X-Api-Key"] == SECRET
    assert list(cache.entries) == [cache_key("GET", FEED, {"page": "1"})]
    assert SECRET not in repr(cache.entries)


@pytest.mark.anyio
async def test_errors_never_contain_secrets_or_query(
    respx_mock: respx.MockRouter, make_client: ClientFactory
) -> None:
    respx_mock.get(FEED).mock(return_value=httpx.Response(403))
    client = make_client()

    with pytest.raises(SourceHttpError) as error:
        await client.get(
            FEED, params={"token": "query-secret"}, secret_headers={"X-Api-Key": SECRET}
        )

    assert error.value.status == 403
    assert SECRET not in str(error.value)
    assert "query-secret" not in str(error.value)


@pytest.mark.anyio
async def test_client_errors_are_not_retried_or_cached(
    respx_mock: respx.MockRouter, make_client: ClientFactory, cache: MemoryCacheStore
) -> None:
    route = respx_mock.get(FEED).mock(return_value=httpx.Response(404))
    client = make_client()

    with pytest.raises(SourceHttpError):
        await client.get(FEED)

    assert route.call_count == 1
    assert cache.entries == {}


@pytest.mark.anyio
@pytest.mark.respx(assert_all_called=False)
async def test_quota_blocks_requests_before_sending(
    respx_mock: respx.MockRouter,
    make_client: ClientFactory,
    usage: MemoryUsageStore,
    clock: FakeClock,
) -> None:
    route = respx_mock.get(FEED).mock(return_value=httpx.Response(200, content=b"ok"))
    usage.counts[("example_feed", clock.now().date())] = 3
    client = make_client(quota=Quota(limit=3, period="day"))

    with pytest.raises(QuotaExceededError, match="3 requests per day"):
        await client.get(FEED)

    assert route.call_count == 0


@pytest.mark.anyio
async def test_rate_limit_waits_for_the_window(
    respx_mock: respx.MockRouter, make_client: ClientFactory, clock: FakeClock
) -> None:
    respx_mock.get(url__startswith=FEED).mock(return_value=httpx.Response(200, content=b"ok"))
    client = make_client(rate_limit=RateLimit(requests=2, per=timedelta(seconds=10)))

    for page in ("1", "2", "3"):
        await client.get(FEED, params={"page": page})

    assert clock.slept == [10.0]


@pytest.mark.anyio
async def test_server_errors_are_retried_with_backoff(
    respx_mock: respx.MockRouter,
    make_client: ClientFactory,
    usage: MemoryUsageStore,
    clock: FakeClock,
) -> None:
    route = respx_mock.get(FEED).mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(502),
            httpx.Response(200, content=b"ok"),
        ]
    )
    client = make_client()

    result = await client.get(FEED)

    assert result.content == b"ok"
    assert route.call_count == 3
    assert clock.slept == [2.0, 4.0]
    assert used(usage) == 3


@pytest.mark.anyio
async def test_retry_after_is_honoured(
    respx_mock: respx.MockRouter, make_client: ClientFactory, clock: FakeClock
) -> None:
    respx_mock.get(FEED).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, content=b"ok"),
        ]
    )
    client = make_client()

    await client.get(FEED)

    assert clock.slept == [7.0]


@pytest.mark.anyio
async def test_network_errors_give_up_after_max_attempts(
    respx_mock: respx.MockRouter, make_client: ClientFactory, usage: MemoryUsageStore
) -> None:
    route = respx_mock.get(FEED).mock(side_effect=httpx.ConnectError("unreachable"))
    client = make_client()

    with pytest.raises(SourceHttpError) as error:
        await client.get(FEED)

    assert error.value.status is None
    assert route.call_count == 4
    assert used(usage) == 4


def test_period_start() -> None:
    assert period_start(date(2026, 10, 8), "day") == date(2026, 10, 8)
    assert period_start(date(2026, 10, 8), "month") == date(2026, 10, 1)


def test_cache_key_ignores_parameter_order_and_method_case() -> None:
    forward = cache_key("GET", FEED, {"a": "1", "b": "2"})

    assert forward == cache_key("get", FEED, {"b": "2", "a": "1"})
    assert forward != cache_key("GET", FEED, {"a": "1", "b": "3"})


@pytest.mark.anyio
async def test_http_client_takes_proxy_only_from_settings() -> None:
    settings = Settings(
        environment="test",
        database_url=SecretStr("postgresql+asyncpg://u:p@h/d"),
        https_proxy=None,
    )

    async with create_http_client(settings) as client:
        assert client.headers["User-Agent"] == USER_AGENT
        assert client.trust_env is False
