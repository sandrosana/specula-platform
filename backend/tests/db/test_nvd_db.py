"""NVD collector end to end: runner, HTTP client, writer and PostgreSQL."""

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

from app.collectors.nvd import API_URL
from app.collectors.runner import CollectorRunner, RunResult
from app.core.config import Settings
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "nvd" / "cves_page.json"


def page() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text("utf-8"))
    return data


def modified_page() -> dict[str, Any]:
    """CVE-2026-88779 modified by NVD: new lastModified, description and no CNA products."""
    data = copy.deepcopy(page())
    cve = data["vulnerabilities"][0]["cve"]
    cve["lastModified"] = "2026-10-09T08:00:00.000"
    cve["descriptions"] = [{"lang": "en", "value": "Updated description."}]
    cve["affected"] = []
    return data


def run_nvd(
    database_url: str, responses: list[dict[str, Any]], runs: list[dict[str, Any]]
) -> list[RunResult]:
    async def main() -> list[RunResult]:
        engine = create_async_engine(database_url)
        settings = Settings(
            environment="test", database_url=SecretStr(database_url), collector_env={}
        )
        results: list[RunResult] = []
        try:
            with respx.mock(assert_all_called=False) as router:
                router.get(API_URL).mock(
                    side_effect=[httpx.Response(200, json=body) for body in responses]
                )
                async with httpx.AsyncClient() as http_client:
                    runner = CollectorRunner(
                        engine=engine, settings=settings, http_client=http_client
                    )
                    for options in runs:
                        results.append(await runner.run("nvd", **options))
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


def test_full_load_stores_vulnerabilities_and_products(migrated_database_url: str) -> None:
    [result] = run_nvd(migrated_database_url, [page()], [{}])

    assert (result.status, result.read, result.inserted, result.updated) == ("success", 3, 3, 0)
    rows = asyncio.run(
        query(
            migrated_database_url,
            "SELECT cve_id, vuln_status, cvss_version, cvss_score::text, classification::text "
            "FROM vulnerabilities ORDER BY cve_id",
        )
    )
    assert rows == [
        ("CVE-1999-0001", "Modified", "2.0", rows[0][3], "public"),
        ("CVE-1999-1598", "Rejected", None, None, "public"),
        ("CVE-2026-88779", "Analyzed", "4.0", "8.7", "public"),
    ]
    products = asyncio.run(
        query(
            migrated_database_url,
            "SELECT source, vendor, product FROM vulnerability_products "
            "WHERE cve_id = 'CVE-2026-88779' ORDER BY source, vendor, product",
        )
    )
    assert ("cna", "netscaler", "adc") in products
    assert any(row[0] == "cpe" and row[1] == "citrix" for row in products)


def test_unchanged_records_are_not_rewritten(migrated_database_url: str) -> None:
    first, second = run_nvd(migrated_database_url, [page(), page()], [{}, {"trigger": "manual"}])

    assert first.inserted == 3
    # Incremental run: same lastModified values, nothing to write.
    assert (second.status, second.read, second.inserted, second.updated) == ("success", 3, 0, 0)


def test_modified_record_is_updated_and_products_replaced(migrated_database_url: str) -> None:
    _first, second = run_nvd(migrated_database_url, [page(), modified_page()], [{}, {}])

    assert (second.inserted, second.updated) == (0, 1)
    [(description,)] = asyncio.run(
        query(
            migrated_database_url,
            "SELECT description FROM vulnerabilities WHERE cve_id = 'CVE-2026-88779'",
        )
    )
    assert description == "Updated description."
    sources = asyncio.run(
        query(
            migrated_database_url,
            "SELECT DISTINCT source FROM vulnerability_products WHERE cve_id = 'CVE-2026-88779'",
        )
    )
    assert sources == [("cpe",)]
    [(cursor,)] = asyncio.run(
        query(
            migrated_database_url,
            "SELECT cursor->>'last_modified' FROM collector_state WHERE collector = 'nvd'",
        )
    )
    assert cursor == "2026-10-09T08:00:00.000Z"
