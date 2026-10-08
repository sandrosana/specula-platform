import asyncio
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.collectors import registry
from app.collectors.http import QuotaExceededError, SourceHttpError
from app.collectors.runner import CollectorRunner, RunResult
from app.core.config import Settings
from app.core.db import create_session_factory
from app.models import CollectorRun, CollectorState
from tests.collectors.scripted import PROBE_TABLE_DDL, KeyedCollector, ScriptedCollector
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

RECORDS = [{"id": 1, "value": "a"}, {"id": 2, "value": "b"}]


@pytest.fixture(autouse=True)
def scripted() -> Iterator[None]:
    registry.register(ScriptedCollector)
    registry.register(KeyedCollector)
    ScriptedCollector.records = list(RECORDS)
    ScriptedCollector.fail_with = None
    ScriptedCollector.seen_cursor = None
    yield
    registry.unregister(ScriptedCollector.name)
    registry.unregister(KeyedCollector.name)


Scenario = Callable[[CollectorRunner, AsyncEngine], Awaitable[Any]]


def run_scenario(database_url: str, scenario: Scenario) -> Any:
    async def main() -> Any:
        engine = create_async_engine(database_url)
        settings = Settings(
            environment="test", database_url=SecretStr(database_url), collector_env={}
        )
        try:
            async with engine.begin() as connection:
                await connection.execute(text(PROBE_TABLE_DDL))
            async with httpx.AsyncClient() as http_client:
                runner = CollectorRunner(engine=engine, settings=settings, http_client=http_client)
                return await scenario(runner, engine)
        finally:
            async with engine.begin() as connection:
                await connection.execute(text("DROP TABLE IF EXISTS probe_items"))
            await engine.dispose()

    return asyncio.run(main())


async def probe_rows(engine: AsyncEngine) -> list[tuple[int, str, str]]:
    async with engine.connect() as connection:
        result = await connection.execute(
            text("SELECT id, value, classification::text FROM probe_items ORDER BY id")
        )
        return [(row[0], row[1], row[2]) for row in result]


async def state_of(engine: AsyncEngine, name: str) -> CollectorState | None:
    async with create_session_factory(engine)() as session:
        return await session.get(CollectorState, name)


async def run_row(engine: AsyncEngine, run_id: int | None) -> CollectorRun:
    async with create_session_factory(engine)() as session:
        row = await session.scalar(select(CollectorRun).where(CollectorRun.id == run_id))
        assert row is not None
        return row


def test_successful_run_writes_entities_and_saves_cursor(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        result = await runner.run("test_scripted")
        return (
            result,
            await probe_rows(engine),
            await state_of(engine, "test_scripted"),
            (await run_row(engine, result.run_id)),
        )

    result, rows, state, run = run_scenario(migrated_database_url, scenario)

    assert (result.status, result.read, result.inserted, result.updated) == ("success", 2, 2, 0)
    assert rows == [(1, "a", "public"), (2, "b", "public")]
    assert state.cursor == {"last_id": 2}
    assert state.last_status == "success" and state.last_success_at is not None
    assert (run.status, run.trigger, run.records_read, run.finished_at is not None) == (
        "success",
        "schedule",
        2,
        True,
    )


def test_rerun_is_idempotent_and_uses_cursor(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        await runner.run("test_scripted")
        second = await runner.run("test_scripted", trigger="manual")
        return second, ScriptedCollector.seen_cursor, await probe_rows(engine)

    second, seen_cursor, rows = run_scenario(migrated_database_url, scenario)

    assert (second.status, second.inserted, second.updated) == ("success", 0, 2)
    assert seen_cursor == {"last_id": 2}
    assert len(rows) == 2


def test_full_run_ignores_cursor(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        await runner.run("test_scripted")
        await runner.run("test_scripted", full=True)
        return ScriptedCollector.seen_cursor

    assert run_scenario(migrated_database_url, scenario) is None


def test_malformed_record_is_skipped(migrated_database_url: str) -> None:
    ScriptedCollector.records = [{"id": 1, "value": "a"}, {"bad": True}, {"id": 3, "value": "c"}]

    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        return await runner.run("test_scripted"), await probe_rows(engine)

    result, rows = run_scenario(migrated_database_url, scenario)

    assert (result.status, result.read, result.errors, result.inserted) == ("success", 3, 1, 2)
    assert [row[0] for row in rows] == [1, 3]


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (SourceHttpError("test_scripted", "https://feeds.example.test/x", 503), "failed"),
        (QuotaExceededError("quota of 10 requests per day reached"), "quota_exceeded"),
        (RuntimeError("boom with details"), "failed"),
    ],
)
def test_failure_keeps_previous_cursor(
    migrated_database_url: str, error: Exception, status: str
) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        await runner.run("test_scripted")
        ScriptedCollector.records = [{"id": 9, "value": "z"}]
        ScriptedCollector.fail_with = error
        result = await runner.run("test_scripted")
        return result, await state_of(engine, "test_scripted"), await run_row(engine, result.run_id)

    result, state, run = run_scenario(migrated_database_url, scenario)

    assert result.status == status
    assert state.cursor == {"last_id": 2}
    assert state.last_status == status
    assert run.status == status and run.message
    assert "boom with details" not in run.message


def test_missing_key_disables_without_recording_a_run(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        result = await runner.run("test_keyed")
        async with engine.connect() as connection:
            runs = await connection.scalar(text("SELECT count(*) FROM collector_runs"))
        return result, runs

    result, runs = run_scenario(migrated_database_url, scenario)

    assert result == RunResult(
        "test_keyed", "disabled", message="missing required settings: OTX_API_KEY"
    )
    assert runs == 0


def test_concurrent_run_is_skipped(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        key = {"key": "specula:collector:test_scripted"}
        async with engine.connect() as holder:
            await holder.execute(text("SELECT pg_advisory_lock(hashtext(:key))"), key)
            skipped = await runner.run("test_scripted")
            await holder.execute(text("SELECT pg_advisory_unlock(hashtext(:key))"), key)
        after = await runner.run("test_scripted")
        return skipped, after

    skipped, after = run_scenario(migrated_database_url, scenario)

    assert skipped.status == "skipped_locked" and skipped.run_id is None
    assert after.status == "success"


def test_forced_run_without_cache(migrated_database_url: str) -> None:
    async def scenario(runner: CollectorRunner, engine: AsyncEngine) -> Any:
        return await runner.run("test_scripted", trigger="cli", use_cache=False)

    assert run_scenario(migrated_database_url, scenario).status == "success"
