"""PostgreSQL implementations of the HTTP client stores (docs/architettura.md §7.1)."""

import zlib
from datetime import date, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.collectors.http import CachedResponse
from app.models import HttpCacheEntry, SourceUsage


class SqlCacheStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def get(self, key: str) -> CachedResponse | None:
        async with self._sessions() as session:
            row = await session.get(HttpCacheEntry, key)
            if row is None:
                return None
            return CachedResponse(
                key=row.key,
                source=row.source,
                url=row.url,
                status=row.status,
                content_type=row.content_type,
                body=zlib.decompress(row.body),
                etag=row.etag,
                last_modified=row.last_modified,
                fetched_at=row.fetched_at,
                expires_at=row.expires_at,
                classification=row.classification,
            )

    async def put(self, entry: CachedResponse) -> None:
        values = {
            "key": entry.key,
            "source": entry.source,
            "url": entry.url,
            "status": entry.status,
            "content_type": entry.content_type,
            "body": zlib.compress(entry.body),
            "etag": entry.etag,
            "last_modified": entry.last_modified,
            "fetched_at": entry.fetched_at,
            "expires_at": entry.expires_at,
            "classification": entry.classification,
        }
        statement = insert(HttpCacheEntry).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=[HttpCacheEntry.key],
            set_={name: statement.excluded[name] for name in values if name != "key"},
        )
        async with self._sessions.begin() as session:
            await session.execute(statement)

    async def purge_expired(self, before: datetime) -> int:
        """Delete entries expired before `before` (daily cleanup, §7.1)."""
        async with self._sessions.begin() as session:
            deleted = await session.scalars(
                delete(HttpCacheEntry)
                .where(HttpCacheEntry.expires_at < before)
                .returning(HttpCacheEntry.key)
            )
            return len(deleted.all())


class SqlUsageStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def increment(self, source: str, day: date) -> None:
        statement = insert(SourceUsage).values(source=source, day=day, requests=1)
        statement = statement.on_conflict_do_update(
            index_elements=[SourceUsage.source, SourceUsage.day],
            set_={"requests": SourceUsage.requests + 1},
        )
        async with self._sessions.begin() as session:
            await session.execute(statement)

    async def total(self, source: str, since: date) -> int:
        async with self._sessions() as session:
            result = await session.scalar(
                select(func.coalesce(func.sum(SourceUsage.requests), 0)).where(
                    SourceUsage.source == source, SourceUsage.day >= since
                )
            )
            return int(result or 0)
