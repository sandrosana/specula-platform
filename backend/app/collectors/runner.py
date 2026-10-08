"""Collector runner (docs/architettura.md §5.4, §5.6).

One run of a periodic collector:
1. resolve its configuration; a disabled collector (configuration or missing
   required settings) does not run;
2. take a PostgreSQL advisory lock, so the same collector never runs twice at once;
3. record the run in collector_runs;
4. fetch -> normalize -> write in batches (idempotent upserts) -> inline post-processing;
5. on success save the next cursor; on failure keep the previous one, so the
   next run fetches the same data again (writes are idempotent).
"""

import logging
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

import httpx
from pydantic import BaseModel
from sqlalchemy import insert, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from app.collectors.base import CollectorContext, Cursor, PeriodicCollector
from app.collectors.http import QuotaExceededError, SourceHttpClient, SourceHttpError, utcnow
from app.collectors.registry import CollectorConfig, get_collector, resolve
from app.collectors.storage import SqlCacheStore, SqlUsageStore
from app.collectors.writers import WriteStats, writer_for
from app.core.classification import Classification
from app.core.config import Settings
from app.core.db import create_session_factory
from app.models import CollectorRun, CollectorState
from app.processing.base import inline_processors

RunStatus = Literal["success", "failed", "quota_exceeded", "skipped_locked", "disabled"]
Trigger = Literal["schedule", "manual", "cli"]

BATCH_SIZE = 500
CACHE_RETENTION = timedelta(days=7)


@dataclass(frozen=True)
class RunResult:
    collector: str
    status: RunStatus
    run_id: int | None = None
    read: int = 0
    inserted: int = 0
    updated: int = 0
    errors: int = 0
    message: str | None = None


class CollectorRunner:
    def __init__(
        self,
        *,
        engine: AsyncEngine,
        settings: Settings,
        http_client: httpx.AsyncClient,
        now: Callable[[], datetime] = utcnow,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        self._engine = engine
        self._settings = settings
        self._http_client = http_client
        self._now = now
        self._batch_size = batch_size
        self._sessions = create_session_factory(engine)
        self._cache = SqlCacheStore(self._sessions)
        self._usage = SqlUsageStore(self._sessions)

    async def run(
        self,
        name: str,
        *,
        trigger: Trigger = "schedule",
        full: bool = False,
        use_cache: bool = True,
    ) -> RunResult:
        cls = get_collector(name)
        if not issubclass(cls, PeriodicCollector):
            raise ValueError(f"{name} is a listener: it runs under the supervisor, not the runner")
        logger = logging.getLogger(f"app.collectors.{name}")
        config = resolve(cls, self._settings)
        if not config.enabled:
            logger.info("collector %s not run: %s", name, config.disabled_reason)
            return RunResult(name, "disabled", message=config.disabled_reason)

        lock_key = {"key": f"specula:collector:{name}"}
        async with self._engine.connect() as lock_connection:
            locked = await lock_connection.scalar(
                text("SELECT pg_try_advisory_lock(hashtext(:key))"), lock_key
            )
            if not locked:
                logger.warning("collector %s not run: another run is in progress", name)
                return RunResult(name, "skipped_locked", message="another run is in progress")
            try:
                return await self._run_locked(cls, config, logger, trigger, full, use_cache)
            finally:
                await lock_connection.execute(
                    text("SELECT pg_advisory_unlock(hashtext(:key))"), lock_key
                )

    async def _run_locked(
        self,
        cls: type[PeriodicCollector],
        config: CollectorConfig,
        logger: logging.Logger,
        trigger: Trigger,
        full: bool,
        use_cache: bool,
    ) -> RunResult:
        name = cls.name
        if config.cache_ttl is None:  # pragma: no cover - resolve() always sets it for periodic
            raise ValueError(f"{name}: periodic collector without cache_ttl")
        run_id = await self._start_run(name, trigger, full)
        previous_cursor = None if full else await self._load_cursor(name)
        http = SourceHttpClient(
            source=name,
            client=self._http_client,
            cache=self._cache if use_cache else _NoCache(),
            usage=self._usage,
            cache_ttl=config.cache_ttl,
            classification=cls.classification,
            rate_limit=cls.rate_limit,
            quota=cls.quota,
            now=self._now,
        )
        ctx = CollectorContext(
            http=http, cursor=previous_cursor, secrets=config.secrets, logger=logger, full=full
        )
        collector = cls()
        read = errors = 0
        stats = WriteStats()
        status: RunStatus = "success"
        message: str | None = None
        next_cursor: Cursor | None = None
        batch: list[BaseModel] = []
        try:
            async for raw in collector.fetch(ctx):
                read += 1
                try:
                    batch.extend(collector.normalize(raw))
                except Exception as exc:
                    errors += 1
                    logger.warning("record %d skipped: %s", read, type(exc).__name__)
                    continue
                if len(batch) >= self._batch_size:
                    stats += await self._write(batch, cls.classification)
                    batch = []
            if batch:
                stats += await self._write(batch, cls.classification)
            next_cursor = collector.next_cursor(ctx)
        except QuotaExceededError as exc:
            status, message = "quota_exceeded", str(exc)
        except SourceHttpError as exc:
            status, message = "failed", str(exc)
        except Exception as exc:
            status, message = "failed", f"unexpected error: {type(exc).__name__}"
            logger.exception("collector %s failed", name)

        result = RunResult(
            collector=name,
            status=status,
            run_id=run_id,
            read=read,
            inserted=stats.inserted,
            updated=stats.updated,
            errors=errors,
            message=message,
        )
        await self._finish_run(result, next_cursor if status == "success" else None)
        logger.info(
            "collector %s %s: read=%d inserted=%d updated=%d errors=%d",
            name,
            status,
            read,
            stats.inserted,
            stats.updated,
            errors,
        )
        return result

    async def _write(
        self, entities: Sequence[BaseModel], classification: Classification
    ) -> WriteStats:
        by_type: dict[type[BaseModel], list[BaseModel]] = defaultdict(list)
        for entity in entities:
            by_type[type(entity)].append(entity)
        stats = WriteStats()
        async with self._sessions.begin() as session:
            for entity_type, items in by_type.items():
                stats += await writer_for(entity_type)(session, items, classification)
            for processor in inline_processors():
                matching = [e for e in entities if type(e) in processor.applies_to]
                if matching:
                    await processor.process(session, matching)
        return stats

    async def _start_run(self, name: str, trigger: Trigger, full: bool) -> int:
        async with self._sessions.begin() as session:
            run_id = await session.scalar(
                insert(CollectorRun)
                .values(
                    collector=name,
                    trigger=trigger,
                    full=full,
                    status="running",
                    started_at=self._now(),
                )
                .returning(CollectorRun.id)
            )
        if run_id is None:  # pragma: no cover - INSERT ... RETURNING always yields the id
            raise RuntimeError("collector run was not recorded")
        return int(run_id)

    async def _load_cursor(self, name: str) -> Cursor | None:
        async with self._sessions() as session:
            state = await session.get(CollectorState, name)
            return dict(state.cursor) if state is not None and state.cursor is not None else None

    async def _finish_run(self, result: RunResult, next_cursor: Cursor | None) -> None:
        finished = self._now()
        state_values: dict[str, object] = {
            "collector": result.collector,
            "last_run_at": finished,
            "last_status": result.status,
        }
        if result.status == "success":
            state_values.update(cursor=next_cursor, last_success_at=finished)
        upsert = pg_insert(CollectorState).values(**state_values)
        upsert = upsert.on_conflict_do_update(
            index_elements=[CollectorState.collector],
            set_={key: upsert.excluded[key] for key in state_values if key != "collector"},
        )
        async with self._sessions.begin() as session:
            await session.execute(
                update(CollectorRun)
                .where(CollectorRun.id == result.run_id)
                .values(
                    status=result.status,
                    finished_at=finished,
                    records_read=result.read,
                    records_inserted=result.inserted,
                    records_updated=result.updated,
                    errors=result.errors,
                    message=result.message,
                )
            )
            await session.execute(upsert)

    async def purge_http_cache(self) -> int:
        """Daily cleanup: drop cache entries expired more than 7 days ago (§7.1)."""
        return await self._cache.purge_expired(self._now() - CACHE_RETENTION)


class _NoCache:
    """Cache store used by forced runs (--no-cache): never returns or keeps entries."""

    async def get(self, key: str) -> None:
        return None

    async def put(self, entry: object) -> None:
        return None
