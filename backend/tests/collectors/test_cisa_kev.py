import json
import logging
from collections.abc import AsyncIterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError

from app.collectors.base import CollectorContext, Cursor, RawRecord, definition_errors
from app.collectors.cisa_kev import FEED_URL, CisaKevCollector, KevEntry
from app.collectors.http import SourceHttpClient
from app.core.classification import Classification
from tests.collectors.fakes import FakeClock, MemoryCacheStore, MemoryUsageStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cisa_kev" / "kev_catalog.json"


def catalog() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text("utf-8"))
    return data


def first_record() -> RawRecord:
    return {**catalog()["vulnerabilities"][0], "_catalogVersion": "2026.10.04"}


def test_definition_and_license() -> None:
    assert definition_errors(CisaKevCollector) == []
    assert CisaKevCollector.classification is Classification.PUBLIC
    assert CisaKevCollector.license.kind == "CC0 1.0 Universal"
    assert CisaKevCollector.license.commercial_use == "yes"
    assert CisaKevCollector.license.verified_on == date(2026, 10, 8)
    assert CisaKevCollector.required_settings == ()


def test_normalize_maps_every_field() -> None:
    entities = list(CisaKevCollector().normalize(first_record()))

    assert len(entities) == 1
    entry = entities[0]
    assert isinstance(entry, KevEntry)
    assert entry.cve_id == "CVE-2026-59310"
    assert (entry.vendor_project, entry.product) == ("Broadcom", "VMware vCenter")
    assert entry.date_added == date(2026, 8, 18)
    assert entry.due_date == date(2026, 8, 21)
    assert entry.ransomware_known is True
    assert entry.forensic_triage is True
    assert entry.cwes == ("CWE-22",)
    assert entry.catalog_version == "2026.10.04"
    assert entry.raw["cveID"] == "CVE-2026-59310"
    assert "_catalogVersion" not in entry.raw


def test_normalize_accepts_long_cve_numbers_and_optional_fields() -> None:
    record = {**first_record(), "cveID": "CVE-2026-102489"}
    for optional in ("knownRansomwareCampaignUse", "forensicTriage", "notes", "cwes"):
        record.pop(optional)

    entry = next(iter(CisaKevCollector().normalize(record)))

    assert isinstance(entry, KevEntry)
    assert entry.cve_id == "CVE-2026-102489"
    assert entry.ransomware_known is False
    assert entry.forensic_triage is None and entry.notes is None and entry.cwes == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [("cveID", "CVE-26-1"), ("dateAdded", "not-a-date"), ("vendorProject", None)],
)
def test_normalize_rejects_invalid_records(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        list(CisaKevCollector().normalize({**first_record(), field: value}))


@pytest.fixture
async def http() -> AsyncIterator[SourceHttpClient]:
    clock = FakeClock()
    async with httpx.AsyncClient() as client:
        yield SourceHttpClient(
            source="cisa_kev",
            client=client,
            cache=MemoryCacheStore(),
            usage=MemoryUsageStore(),
            cache_ttl=timedelta(hours=3),
            classification=Classification.PUBLIC,
            now=clock.now,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )


async def collect(
    http: SourceHttpClient, cursor: Cursor | None, *, full: bool = False
) -> tuple[list[RawRecord], Cursor | None]:
    collector = CisaKevCollector()
    ctx = CollectorContext(
        http=http, cursor=cursor, secrets={}, logger=logging.getLogger("test"), full=full
    )
    records = [record async for record in collector.fetch(ctx)]
    return records, collector.next_cursor(ctx)


@pytest.mark.anyio
async def test_fetch_yields_all_entries_and_cursor(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    respx_mock.get(FEED_URL).mock(return_value=httpx.Response(200, json=catalog()))

    records, cursor = await collect(http, None)

    assert [record["cveID"] for record in records] == [
        "CVE-2026-59310",
        "CVE-2026-102489",
        "CVE-2026-88779",
    ]
    assert {record["_catalogVersion"] for record in records} == {"2026.10.04"}
    assert cursor == {
        "catalog_version": "2026.10.04",
        "date_released": "2026-10-04T18:52:56.0635Z",
        "count": 3,
    }


@pytest.mark.anyio
async def test_unchanged_catalog_is_not_reprocessed(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    respx_mock.get(FEED_URL).mock(return_value=httpx.Response(200, json=catalog()))
    previous = {"catalog_version": "2026.10.04"}

    unchanged, _ = await collect(http, previous)
    forced, _ = await collect(http, previous, full=True)

    assert unchanged == []
    assert len(forced) == 3


@pytest.mark.anyio
async def test_unexpected_format_fails(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    respx_mock.get(FEED_URL).mock(return_value=httpx.Response(200, json={"error": "maintenance"}))

    with pytest.raises(ValueError, match="unexpected KEV catalog format"):
        await collect(http, None)
