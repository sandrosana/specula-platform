import asyncio
from datetime import UTC, date, datetime, timedelta
from typing import Any

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.collectors.http import CachedResponse
from app.collectors.storage import SqlCacheStore, SqlUsageStore
from app.core.classification import Classification
from app.models import Base
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def _entry(key: str, body: bytes, expires_at: datetime) -> CachedResponse:
    return CachedResponse(
        key=key,
        source="example_feed",
        url="https://feeds.example.test/feed.json",
        status=200,
        content_type="application/json",
        body=body,
        etag='"abc"',
        last_modified=None,
        fetched_at=NOW,
        expires_at=expires_at,
        classification=Classification.PUBLIC,
    )


def _schema_differences(sync_connection: Connection) -> list[Any]:
    context = MigrationContext.configure(sync_connection)
    return list(compare_metadata(context, Base.metadata))


def test_models_match_migrations(migrated_database_url: str) -> None:
    async def differences() -> list[Any]:
        engine = create_async_engine(migrated_database_url)
        try:
            async with engine.connect() as connection:
                return await connection.run_sync(_schema_differences)
        finally:
            await engine.dispose()

    assert asyncio.run(differences()) == []


def test_cache_store_roundtrip_and_upsert(migrated_database_url: str) -> None:
    async def scenario() -> tuple[CachedResponse | None, CachedResponse | None, int]:
        engine = create_async_engine(migrated_database_url)
        try:
            store = SqlCacheStore(async_sessionmaker(engine, expire_on_commit=False))
            await store.put(_entry("k1", b'{"v": 1}' * 100, NOW + timedelta(hours=1)))
            first = await store.get("k1")
            await store.put(_entry("k1", b'{"v": 2}', NOW + timedelta(hours=2)))
            second = await store.get("k1")
            await store.put(_entry("old", b"x", NOW - timedelta(days=8)))
            purged = await store.purge_expired(NOW - timedelta(days=7))
            return first, second, purged
        finally:
            await engine.dispose()

    first, second, purged = asyncio.run(scenario())

    assert first is not None and first.body == b'{"v": 1}' * 100
    assert first.classification is Classification.PUBLIC
    assert second is not None and second.body == b'{"v": 2}'
    assert second.expires_at == NOW + timedelta(hours=2)
    assert purged == 1


def test_usage_store_counts_per_day(migrated_database_url: str) -> None:
    async def scenario() -> tuple[int, int, int]:
        engine = create_async_engine(migrated_database_url)
        try:
            store = SqlUsageStore(async_sessionmaker(engine, expire_on_commit=False))
            await store.increment("example_feed", date(2026, 9, 30))
            await store.increment("example_feed", date(2026, 10, 7))
            await store.increment("example_feed", date(2026, 10, 8))
            await store.increment("example_feed", date(2026, 10, 8))
            await store.increment("other_feed", date(2026, 10, 8))
            return (
                await store.total("example_feed", date(2026, 10, 8)),
                await store.total("example_feed", date(2026, 10, 1)),
                await store.total("missing_feed", date(2026, 10, 1)),
            )
        finally:
            await engine.dispose()

    assert asyncio.run(scenario()) == (2, 3, 0)
