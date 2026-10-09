"""Priority levels end to end: NVD, KEV and EPSS runs update the derived columns."""

import asyncio
import copy
import gzip
import json
from pathlib import Path
from typing import Any

import httpx
import respx
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.collectors import cisa_kev, epss, nvd
from app.collectors.runner import CollectorRunner, RunResult
from app.core.config import Settings
from app.core.db import create_session_factory
from app.processing.priority import recompute_all_priorities
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def nvd_page() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "nvd" / "cves_page.json").read_text("utf-8"))
    return data


def kev_catalog(ransomware_88779: str = "Unknown") -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / "cisa_kev" / "kev_catalog.json").read_text("utf-8")
    )
    data = copy.deepcopy(data)
    for entry in data["vulnerabilities"]:
        if entry["cveID"] == "CVE-2026-88779":
            entry["knownRansomwareCampaignUse"] = ransomware_88779
    return data


def epss_csv() -> bytes:
    """The fixture with CVE-1999-0001 above the default threshold."""
    content = (FIXTURES / "epss" / "epss_scores.csv").read_text("utf-8")
    content = content.replace("CVE-1999-0001,0.03351,0.88354", "CVE-1999-0001,0.91000,0.99500")
    return gzip.compress(content.encode("utf-8"))


def run(
    database_url: str, collectors: list[str], kev: dict[str, Any] | None = None
) -> list[RunResult]:
    async def main() -> list[RunResult]:
        engine = create_async_engine(database_url)
        settings = Settings(
            environment="test", database_url=SecretStr(database_url), collector_env={}
        )
        results: list[RunResult] = []
        try:
            with respx.mock(assert_all_called=False) as router:
                router.get(nvd.API_URL).mock(return_value=httpx.Response(200, json=nvd_page()))
                router.get(cisa_kev.FEED_URL).mock(
                    return_value=httpx.Response(200, json=kev or kev_catalog())
                )
                router.get(epss.FEED_URL).mock(return_value=httpx.Response(200, content=epss_csv()))
                async with httpx.AsyncClient() as http_client:
                    runner = CollectorRunner(
                        engine=engine, settings=settings, http_client=http_client
                    )
                    for name in collectors:
                        results.append(await runner.run(name, use_cache=False))
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


def levels(database_url: str) -> dict[str, str | None]:
    rows = asyncio.run(
        query(database_url, "SELECT cve_id, priority_level FROM vulnerabilities ORDER BY cve_id")
    )
    return {cve_id: level for cve_id, level in rows}


def test_levels_follow_nvd_kev_and_epss_runs(migrated_database_url: str) -> None:
    [nvd_run] = run(migrated_database_url, ["nvd"])
    assert nvd_run.status == "success"
    assert set(levels(migrated_database_url).values()) == {"P4"}

    [kev_run] = run(migrated_database_url, ["cisa_kev"])
    assert kev_run.status == "success"
    assert levels(migrated_database_url)["CVE-2026-88779"] == "P2"

    [epss_run] = run(migrated_database_url, ["epss"])
    assert epss_run.status == "success"
    assert levels(migrated_database_url) == {
        "CVE-1999-0001": "P3",
        "CVE-1999-1598": "P4",
        "CVE-2026-88779": "P2",
    }
    [(reason,)] = asyncio.run(
        query(
            migrated_database_url,
            "SELECT priority_reason FROM vulnerabilities WHERE cve_id = 'CVE-2026-88779'",
        )
    )
    assert reason == {
        "rule": "kev",
        "kev": {"date_added": "2026-10-04", "ransomware_use": "Unknown"},
        "epss": {"score": 0.00592, "percentile": 0.46624},
        "epss_threshold": 0.5,
        "cvss": {"score": 8.7, "version": "4.0", "severity": "HIGH"},
    }


def test_kev_loaded_before_nvd_is_applied_when_nvd_arrives(migrated_database_url: str) -> None:
    run(migrated_database_url, ["cisa_kev", "nvd"], kev=kev_catalog(ransomware_88779="Known"))

    assert levels(migrated_database_url)["CVE-2026-88779"] == "P1"


def test_recompute_all_applies_a_new_threshold(migrated_database_url: str) -> None:
    run(migrated_database_url, ["nvd", "epss"])

    async def recompute(threshold: float) -> int:
        engine = create_async_engine(migrated_database_url)
        try:
            return await recompute_all_priorities(create_session_factory(engine), threshold)
        finally:
            await engine.dispose()

    # CVE-1999-0001 (0.91) leaves P3 with a threshold above its score.
    assert asyncio.run(recompute(0.95)) == 3
    assert levels(migrated_database_url)["CVE-1999-0001"] == "P4"
    # Same threshold again: nothing changes.
    assert asyncio.run(recompute(0.95)) == 0
