import copy
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from app.collectors.base import CollectorContext, Cursor, RawRecord, definition_errors
from app.collectors.http import SourceHttpClient
from app.collectors.nvd import (
    API_URL,
    NvdCollector,
    Vulnerability,
    format_nvd_datetime,
    normalize_cve,
    parse_nvd_datetime,
    windows,
)
from app.core.classification import Classification
from tests.collectors.fakes import FakeClock, MemoryCacheStore, MemoryUsageStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "nvd" / "cves_page.json"


def page() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text("utf-8"))
    return data


def cve(cve_id: str) -> dict[str, Any]:
    item: dict[str, Any] = next(
        v["cve"] for v in page()["vulnerabilities"] if v["cve"]["id"] == cve_id
    )
    return item


def test_definition_and_license() -> None:
    assert definition_errors(NvdCollector) == []
    assert NvdCollector.classification is Classification.PUBLIC
    assert NvdCollector.license.commercial_use == "yes"
    assert NvdCollector.license.attribution == (
        "This product uses data from the NVD API but is not endorsed or certified by the NVD."
    )
    assert NvdCollector.optional_settings == ("NVD_API_KEY",)
    assert NvdCollector.required_settings == ()


def test_normalize_prefers_cvss_v4_and_ignores_ssvc() -> None:
    entry = normalize_cve(cve("CVE-2026-88779"))

    assert entry.cve_id == "CVE-2026-88779"
    assert entry.vuln_status == "Analyzed"
    assert entry.published.tzinfo is UTC
    assert entry.cvss is not None
    assert (entry.cvss.version, entry.cvss.score, entry.cvss.severity) == ("4.0", 8.7, "HIGH")
    assert [score.version for score in entry.cvss_metrics] == ["4.0", "3.1"]
    assert entry.cvss_metrics[1].type == "Primary" and entry.cvss_metrics[1].score == 7.5
    assert entry.cwes == ("CWE-119",)
    assert entry.description and entry.description.startswith("Vulnerability in NetScaler")
    assert entry.references and "url" in entry.references[0]


def test_normalize_extracts_cpe_and_cna_products() -> None:
    products = {
        (p.source, p.vendor, p.product, p.part)
        for p in normalize_cve(cve("CVE-2026-88779")).products
    }

    assert ("cpe", "citrix", "netscaler_application_delivery_controller", "a") in products
    assert ("cna", "netscaler", "adc", None) in products


def test_normalize_cvss_v2_only() -> None:
    entry = normalize_cve(cve("CVE-1999-0001"))

    assert entry.cvss is not None
    assert entry.cvss.version == "2.0"
    assert entry.cvss.severity is not None


def test_normalize_rejected_without_metrics() -> None:
    entry = normalize_cve(cve("CVE-1999-1598"))

    assert entry.vuln_status == "Rejected"
    assert entry.cvss is None and entry.cvss_metrics == ()


def test_normalize_skips_non_vulnerable_and_wildcard_cpes() -> None:
    record = copy.deepcopy(cve("CVE-2026-88779"))
    record["affected"] = []
    record["configurations"] = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                        },
                        {"vulnerable": True, "criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"},
                    ]
                }
            ]
        }
    ]

    assert normalize_cve(record).products == ()


def test_datetime_helpers_and_windows() -> None:
    parsed = parse_nvd_datetime("2026-10-04T12:15:47.123")
    assert parsed == datetime(2026, 10, 4, 12, 15, 47, 123000, tzinfo=UTC)
    assert format_nvd_datetime(parsed) == "2026-10-04T12:15:47.000Z"

    start = datetime(2026, 1, 1, tzinfo=UTC)
    ranges = windows(start, start + timedelta(days=250))
    assert [(b - a).days for a, b in ranges] == [120, 120, 10]
    assert ranges[0][1] == ranges[1][0]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def http(clock: FakeClock) -> AsyncIterator[SourceHttpClient]:
    async with httpx.AsyncClient() as client:
        yield SourceHttpClient(
            source="nvd",
            client=client,
            cache=MemoryCacheStore(),
            usage=MemoryUsageStore(),
            cache_ttl=timedelta(hours=1),
            classification=Classification.PUBLIC,
            rate_limit=NvdCollector.rate_limit,
            now=clock.now,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )


async def collect(
    http: SourceHttpClient,
    cursor: Cursor | None,
    secrets: dict[str, str] | None = None,
    *,
    full: bool = False,
) -> tuple[list[RawRecord], Cursor | None]:
    collector = NvdCollector()
    ctx = CollectorContext(
        http=http, cursor=cursor, secrets=secrets or {}, logger=logging.getLogger("t"), full=full
    )
    records = [record async for record in collector.fetch(ctx)]
    return records, collector.next_cursor(ctx)


def split_pages(per_page: int) -> list[dict[str, Any]]:
    full = page()
    items = full["vulnerabilities"]
    return [
        dict(
            full,
            resultsPerPage=len(items[i : i + per_page]),
            startIndex=i,
            vulnerabilities=items[i : i + per_page],
        )
        for i in range(0, len(items), per_page)
    ]


@pytest.mark.anyio
async def test_full_load_pages_through_everything(
    respx_mock: respx.MockRouter, http: SourceHttpClient, clock: FakeClock
) -> None:
    route = respx_mock.get(API_URL).mock(
        side_effect=[httpx.Response(200, json=body) for body in split_pages(2)]
    )

    records, cursor = await collect(http, None, {"NVD_API_KEY": "k-123"})

    assert [record["id"] for record in records] == [
        "CVE-2026-88779",
        "CVE-1999-0001",
        "CVE-1999-1598",
    ]
    starts = [call.request.url.params["startIndex"] for call in route.calls]
    assert starts == ["0", "2"]
    assert all("lastModStartDate" not in call.request.url.params for call in route.calls)
    assert all(call.request.headers["apiKey"] == "k-123" for call in route.calls)
    # One request every 6 s, as NVD recommends.
    assert clock.slept == [6.0]
    latest = max(parse_nvd_datetime(r["lastModified"]) for r in records)
    assert cursor == {"last_modified": format_nvd_datetime(latest)}


@pytest.mark.anyio
async def test_incremental_sync_uses_last_modified_window(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    route = respx_mock.get(API_URL).mock(return_value=httpx.Response(200, json=page()))

    since = format_nvd_datetime(datetime.now(UTC) - timedelta(hours=3))
    await collect(http, {"last_modified": since})

    params = route.calls.last.request.url.params
    assert params["lastModStartDate"] == since
    assert params["lastModEndDate"].endswith(".000Z")
    assert "apiKey" not in route.calls.last.request.headers


@pytest.mark.anyio
async def test_long_gap_is_split_in_120_day_windows(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    empty = dict(page(), resultsPerPage=0, totalResults=0, vulnerabilities=[])
    route = respx_mock.get(API_URL).mock(return_value=httpx.Response(200, json=empty))
    since = format_nvd_datetime(datetime.now(UTC) - timedelta(days=200))

    records, cursor = await collect(http, {"last_modified": since})

    assert records == []
    assert route.call_count == 2
    # Nothing new: the cursor stays where it was.
    assert cursor == {"last_modified": since}


@pytest.mark.anyio
async def test_full_flag_ignores_cursor(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    route = respx_mock.get(API_URL).mock(return_value=httpx.Response(200, json=page()))

    await collect(http, {"last_modified": "2026-10-01T00:00:00.000Z"}, full=True)

    assert "lastModStartDate" not in route.calls.last.request.url.params


@pytest.mark.anyio
async def test_unexpected_format_fails(
    respx_mock: respx.MockRouter, http: SourceHttpClient
) -> None:
    respx_mock.get(API_URL).mock(return_value=httpx.Response(200, json={"message": "maintenance"}))

    with pytest.raises(ValueError, match="unexpected NVD response format"):
        await collect(http, None)


def test_entity_is_a_vulnerability() -> None:
    entities = list(NvdCollector().normalize(cve("CVE-2026-88779")))

    assert len(entities) == 1 and isinstance(entities[0], Vulnerability)
    assert entities[0].raw["id"] == "CVE-2026-88779"
    assert date(2026, 1, 1) < entities[0].published.date()
