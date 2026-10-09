"""EPSS collector end to end: runner, HTTP client, writer and PostgreSQL."""

import asyncio
import gzip
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.collectors.epss import FEED_URL
from app.collectors.runner import CollectorRunner, RunResult
from app.core.config import Settings
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "epss" / "epss_scores.csv"


def next_day() -> bytes:
    """The fixture one day later: one small drift, one change, one threshold crossing."""
    content = FIXTURE.read_text("utf-8")
    content = content.replace("score_date:2026-10-08", "score_date:2026-10-09")
    content = content.replace("CVE-1999-0001,0.03351,0.88354", "CVE-1999-0001,0.03400,0.88400")
    content = content.replace("CVE-1999-0002,0.27858,0.98053", "CVE-1999-0002,0.51000,0.99000")
    content = content.replace("CVE-2026-59310,0.02565,0.84658", "CVE-2026-59310,0.04000,0.88000")
    return gzip.compress(content.encode("utf-8"))


def run_epss(
    database_url: str, responses: list[bytes], runs: list[dict[str, Any]]
) -> list[RunResult]:
    async def main() -> list[RunResult]:
        engine = create_async_engine(database_url)
        settings = Settings(
            environment="test", database_url=SecretStr(database_url), collector_env={}
        )
        results: list[RunResult] = []
        try:
            with respx.mock(assert_all_called=False) as router:
                router.get(FEED_URL).mock(
                    side_effect=[httpx.Response(200, content=body) for body in responses]
                )
                async with httpx.AsyncClient() as http_client:
                    runner = CollectorRunner(
                        engine=engine, settings=settings, http_client=http_client
                    )
                    for options in runs:
                        # Every run downloads again: the HTTP cache is not under test here.
                        results.append(await runner.run("epss", use_cache=False, **options))
        finally:
            await engine.dispose()
        return results

    return asyncio.run(main())


async def query(database_url: str, sql: str) -> list[tuple[Any, ...]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            return [tuple(row) for row in await connection.execute(text(sql))]
    finally:
        await engine.dispose()


def history(database_url: str) -> list[tuple[Any, ...]]:
    return asyncio.run(
        query(
            database_url,
            "SELECT cve_id, score_date::text, reason FROM epss_history ORDER BY cve_id, score_date",
        )
    )


def test_first_load_stores_scores_and_history(migrated_database_url: str) -> None:
    [result] = run_epss(migrated_database_url, [gzip.compress(FIXTURE.read_bytes())], [{}])

    assert (result.status, result.read, result.inserted, result.updated) == ("success", 5, 5, 0)
    rows = asyncio.run(
        query(
            migrated_database_url,
            "SELECT cve_id, epss, model_version, score_date::text, classification::text "
            "FROM epss_scores WHERE cve_id = 'CVE-2021-44228'",
        )
    )
    assert rows == [("CVE-2021-44228", 0.99999, "v2026.06.15", "2026-10-08", "public")]
    assert {reason for _cve, _day, reason in history(migrated_database_url)} == {"first"}
    [(cursor,)] = asyncio.run(
        query(
            migrated_database_url,
            "SELECT cursor->>'score_date' FROM collector_state WHERE collector = 'epss'",
        )
    )
    assert cursor == "2026-10-08"


def test_same_day_rerun_reads_nothing(migrated_database_url: str) -> None:
    body = gzip.compress(FIXTURE.read_bytes())
    _first, second = run_epss(migrated_database_url, [body, body], [{}, {"trigger": "manual"}])

    assert (second.status, second.read, second.inserted, second.updated) == ("success", 0, 0, 0)


def test_forced_rerun_is_idempotent(migrated_database_url: str) -> None:
    body = gzip.compress(FIXTURE.read_bytes())
    _first, second = run_epss(migrated_database_url, [body, body], [{}, {"full": True}])

    assert (second.read, second.inserted, second.updated) == (5, 0, 0)
    assert len(history(migrated_database_url)) == 5


def test_next_day_keeps_only_relevant_changes(
    migrated_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EPSS_THRESHOLD", "0.5")
    body = gzip.compress(FIXTURE.read_bytes())
    _first, second = run_epss(migrated_database_url, [body, next_day()], [{}, {}])

    assert (second.read, second.inserted, second.updated) == (5, 0, 3)
    day_two = [
        (cve, reason) for cve, day, reason in history(migrated_database_url) if day == "2026-10-09"
    ]
    # CVE-1999-0001 moved by 0.0005 only: current score updated, no history entry.
    assert day_two == [("CVE-1999-0002", "threshold"), ("CVE-2026-59310", "change")]
    rows = asyncio.run(
        query(
            migrated_database_url,
            "SELECT cve_id, epss, history_epss, score_date::text FROM epss_scores "
            "WHERE cve_id IN ('CVE-1999-0001', 'CVE-2021-44228') ORDER BY cve_id",
        )
    )
    assert rows == [
        ("CVE-1999-0001", 0.034, 0.03351, "2026-10-09"),
        ("CVE-2021-44228", 0.99999, 0.99999, "2026-10-08"),
    ]
