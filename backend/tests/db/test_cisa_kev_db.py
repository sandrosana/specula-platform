"""CISA KEV collector end to end: runner, HTTP client, writer and PostgreSQL."""

import asyncio
import copy
import json
from pathlib import Path
from typing import Any

import httpx
import respx
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.collectors.cisa_kev import FEED_URL
from app.collectors.runner import CollectorRunner, RunResult
from app.core.config import Settings
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cisa_kev" / "kev_catalog.json"


def catalog() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text("utf-8"))
    return data


def updated_catalog() -> dict[str, Any]:
    data = copy.deepcopy(catalog())
    data["catalogVersion"] = "2026.10.05"
    data["vulnerabilities"][2]["dueDate"] = "2026-10-09"
    return data


async def kev_rows(database_url: str) -> list[tuple[str, str, str, str | None]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT cve_id, classification::text, due_date::text, "
                    "known_ransomware_campaign_use FROM kev_entries ORDER BY cve_id"
                )
            )
            return [(row[0], row[1], row[2], row[3]) for row in result]
    finally:
        await engine.dispose()


def run_kev(
    database_url: str,
    responses: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    collector_env: dict[str, str] | None = None,
) -> list[RunResult]:
    async def main() -> list[RunResult]:
        engine = create_async_engine(database_url)
        settings = Settings(
            environment="test",
            database_url=SecretStr(database_url),
            collector_env=collector_env or {},
        )
        results: list[RunResult] = []
        try:
            with respx.mock(assert_all_called=False) as router:
                router.get(FEED_URL).mock(
                    side_effect=[httpx.Response(200, json=body) for body in responses]
                )
                async with httpx.AsyncClient() as http_client:
                    runner = CollectorRunner(
                        engine=engine, settings=settings, http_client=http_client
                    )
                    for options in runs:
                        results.append(await runner.run("cisa_kev", **options))
        finally:
            await engine.dispose()
        return results

    return asyncio.run(main())


def test_first_run_stores_the_catalog(migrated_database_url: str) -> None:
    [result] = run_kev(migrated_database_url, [catalog()], [{}])

    assert (result.status, result.read, result.inserted, result.updated) == ("success", 3, 3, 0)
    rows = asyncio.run(kev_rows(migrated_database_url))
    assert [row[0] for row in rows] == ["CVE-2026-102489", "CVE-2026-59310", "CVE-2026-88779"]
    assert {row[1] for row in rows} == {"public"}
    assert [row[3] for row in rows].count("Known") == 1


def test_rerun_within_ttl_does_nothing(migrated_database_url: str) -> None:
    first, second = run_kev(migrated_database_url, [catalog()], [{}, {"trigger": "manual"}])

    assert first.inserted == 3
    # Served from the HTTP cache and same catalog version: nothing to process.
    assert (second.status, second.read, second.inserted, second.updated) == ("success", 0, 0, 0)


def test_new_catalog_version_updates_only_changed_entries(migrated_database_url: str) -> None:
    first, second = run_kev(
        migrated_database_url,
        [catalog(), updated_catalog()],
        [{}, {"use_cache": False}],
    )

    assert first.inserted == 3
    assert (second.status, second.read, second.inserted, second.updated) == ("success", 3, 0, 1)
    rows = asyncio.run(kev_rows(migrated_database_url))
    assert len(rows) == 3
    assert ("CVE-2026-88779", "public", "2026-10-09", "Unknown") in rows


def test_full_run_rewrites_nothing_when_unchanged(migrated_database_url: str) -> None:
    _first, second = run_kev(
        migrated_database_url,
        [catalog(), catalog()],
        [{}, {"full": True, "use_cache": False}],
    )

    assert (second.read, second.inserted, second.updated) == (3, 0, 0)


def test_disabled_by_configuration(migrated_database_url: str) -> None:
    [result] = run_kev(
        migrated_database_url,
        [catalog()],
        [{}],
        collector_env={"COLLECTOR_CISA_KEV_ENABLED": "false"},
    )

    assert result.status == "disabled"
    assert asyncio.run(kev_rows(migrated_database_url)) == []
