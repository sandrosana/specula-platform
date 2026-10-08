"""GET /kev and GET /sources against PostgreSQL."""

import asyncio
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.registry import resolve
from app.collectors.status import publish_configs, publish_next_run
from app.core.config import Settings
from app.core.db import create_session_factory
from app.main import create_app
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

KEV_ROWS = [
    # cve_id, vendor, product, date_added, ransomware, classification
    ("CVE-2026-0001", "Microsoft", "Windows", "2026-10-01", "Known", "public"),
    ("CVE-2026-0002", "Microsoft", "Exchange", "2026-10-02", "Unknown", "public"),
    ("CVE-2026-0003", "Fortinet", "FortiOS", "2026-10-02", "Known", "public"),
    ("CVE-2026-0004", "Cisco", "IOS XE", "2026-10-03", "Unknown", "public"),
    ("CVE-2026-0005", "Internal Vendor", "Hidden", "2026-10-04", "Known", "internal"),
]
NOW = datetime.now(UTC)


async def seed(database_url: str) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            for cve, vendor, product, added, ransomware, classification in KEV_ROWS:
                await connection.execute(
                    text(
                        "INSERT INTO kev_entries (cve_id, vendor_project, product, "
                        "vulnerability_name, date_added, short_description, required_action, "
                        "due_date, known_ransomware_campaign_use, forensic_triage, notes, cwes, "
                        "catalog_version, raw, classification) VALUES (:cve, :vendor, :product, "
                        "'name', CAST(:added AS date), 'description', 'action', NULL, "
                        ":ransomware, true, NULL, ARRAY['CWE-79'], '2026.10.04', '{}', "
                        "CAST(:classification AS classification))"
                    ),
                    {
                        "cve": cve,
                        "vendor": vendor,
                        "product": product,
                        "added": date.fromisoformat(added),
                        "ransomware": ransomware,
                        "classification": classification,
                    },
                )
            await connection.execute(
                text(
                    'INSERT INTO collector_runs (collector, trigger, "full", status, started_at, '
                    "finished_at, records_read, records_inserted, records_updated, errors) "
                    "VALUES ('cisa_kev', 'schedule', false, 'success', :started, :finished, "
                    "1734, 5, 2, 0)"
                ),
                {"started": NOW - timedelta(minutes=10), "finished": NOW - timedelta(minutes=9)},
            )
            await connection.execute(
                text(
                    "INSERT INTO collector_state (collector, last_run_at, last_status, "
                    "last_success_at) VALUES ('cisa_kev', :at, 'success', :at)"
                ),
                {"at": NOW - timedelta(minutes=9)},
            )
            await connection.execute(
                text("INSERT INTO source_usage (source, day, requests) VALUES ('cisa_kev', :d, 3)"),
                {"d": NOW.date()},
            )
        settings = Settings(
            environment="test", database_url=SecretStr(database_url), collector_env={}
        )
        await publish_configs(
            create_session_factory(engine),
            [resolve(CisaKevCollector, settings)],
            {"cisa_kev": NOW + timedelta(hours=6)},
            NOW,
        )
    finally:
        await engine.dispose()


@pytest.fixture
def api(migrated_database_url: str) -> Iterator[TestClient]:
    asyncio.run(seed(migrated_database_url))
    settings = Settings(
        environment="test",
        log_level="WARNING",
        database_url=SecretStr(migrated_database_url),
        otx_api_key=SecretStr("never-exposed-key"),
        collector_env={},
    )
    with TestClient(create_app(settings)) as client:
        yield client


def cves(page: dict[str, Any]) -> list[str]:
    return [item["cve_id"] for item in page["items"]]


def test_kev_lists_public_entries_newest_first(api: TestClient) -> None:
    response = api.get("/api/v1/kev")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, max-age=60"
    page = response.json()
    assert cves(page) == ["CVE-2026-0004", "CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]
    # The internal entry is neither listed nor counted for an anonymous caller.
    assert page["total"] == 4
    assert page["next_cursor"] is None
    assert page["data_as_of"] is not None
    first = page["items"][0]
    assert first["classification"] == "public"
    assert first["ransomware_known"] is False
    assert first["cwes"] == ["CWE-79"]


def test_kev_pagination_walks_every_entry_once(api: TestClient) -> None:
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, Any] = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        page = api.get("/api/v1/kev", params=params).json()
        seen += cves(page)
        cursor = page["next_cursor"]
        if cursor is None:
            break

    assert seen == ["CVE-2026-0004", "CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"vendor": "micro"}, ["CVE-2026-0002", "CVE-2026-0001"]),
        ({"product": "fortios"}, ["CVE-2026-0003"]),
        ({"ransomware": "true"}, ["CVE-2026-0003", "CVE-2026-0001"]),
        ({"ransomware": "false"}, ["CVE-2026-0004", "CVE-2026-0002"]),
        (
            {"added_from": "2026-10-02", "added_to": "2026-10-02"},
            ["CVE-2026-0003", "CVE-2026-0002"],
        ),
        ({"vendor": "%"}, []),
        ({"vendor": "Internal"}, []),
    ],
)
def test_kev_filters(api: TestClient, params: dict[str, str], expected: list[str]) -> None:
    page = api.get("/api/v1/kev", params=params).json()

    assert cves(page) == expected
    assert page["total"] == len(expected)


def test_sources_reports_status_license_and_usage(api: TestClient) -> None:
    response = api.get("/api/v1/sources")

    assert response.status_code == 200
    sources = {item["name"]: item for item in response.json()["items"]}
    kev = sources["cisa_kev"]
    assert kev["status"] == "ok"
    assert kev["enabled"] is True and kev["configured"] is True
    assert kev["schedule"] == "every 6h"
    assert kev["classification"] == "public"
    assert kev["next_run_at"] is not None
    assert kev["license"]["kind"] == "CC0 1.0 Universal"
    assert kev["license"]["commercial_use"] == "yes"
    assert kev["license"]["verified_on"] == "2026-10-08"
    assert kev["usage"]["period"] == "month" and kev["usage"]["requests"] == 3
    assert kev["last_run"]["read"] == 1734 and kev["last_run"]["inserted"] == 5
    assert "never-exposed-key" not in response.text


def test_publish_next_run_updates_only_the_next_run(migrated_database_url: str) -> None:
    async def scenario() -> tuple[Any, ...]:
        engine = create_async_engine(migrated_database_url)
        try:
            sessions = create_session_factory(engine)
            later = NOW + timedelta(hours=12)
            await publish_next_run(sessions, "cisa_kev", later)
            async with engine.connect() as connection:
                row = (
                    await connection.execute(
                        text(
                            "SELECT next_run_at, enabled, last_status FROM collector_state "
                            "WHERE collector = 'cisa_kev'"
                        )
                    )
                ).one()
            return tuple(row)
        finally:
            await engine.dispose()

    asyncio.run(seed(migrated_database_url))
    next_run_at, enabled, last_status = asyncio.run(scenario())

    assert abs((next_run_at - (NOW + timedelta(hours=12))).total_seconds()) < 1
    assert enabled is True
    assert last_status == "success"
