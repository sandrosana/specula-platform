"""GET /cves and GET /cves/{cve_id} against PostgreSQL."""

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, date, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import Settings
from app.core.db import create_session_factory
from app.processing.priority import recompute_all_priorities
from tests.db.auth import logged_in
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

# cve_id, published day, status, cvss, classification
CVES = [
    ("CVE-2026-1001", 1, "Analyzed", 9.8, "public"),
    ("CVE-2026-1002", 2, "Analyzed", 7.0, "public"),
    ("CVE-2026-1003", 3, "Analyzed", 8.0, "public"),
    ("CVE-2026-1004", 4, "Analyzed", 8.8, "public"),
    ("CVE-2026-1005", 5, "Awaiting Analysis", None, "public"),
    ("CVE-2026-1006", 6, "Analyzed", 9.8, "public"),
    ("CVE-2026-1007", 7, "Received", None, "public"),
    ("CVE-2026-1008", 8, "Analyzed", 5.0, "public"),
    ("CVE-2026-1009", 9, "Rejected", None, "public"),
    ("CVE-2026-1010", 10, "Analyzed", 9.9, "internal"),
]
# cve_id, date added, ransomware use, classification
KEV = [
    ("CVE-2026-1001", "2026-10-01", "Known", "public"),
    ("CVE-2026-1002", "2026-10-03", "Known", "public"),
    ("CVE-2026-1003", "2026-10-05", "Unknown", "public"),
    ("CVE-2026-1010", "2026-10-06", "Known", "internal"),
]
# cve_id, epss, percentile
EPSS = [
    ("CVE-2026-1001", 0.9, 0.99),
    ("CVE-2026-1002", 0.2, 0.95),
    ("CVE-2026-1003", 0.5, 0.97),
    ("CVE-2026-1004", 0.62, 0.98),
    ("CVE-2026-1005", 0.95, 0.999),
    ("CVE-2026-1006", 0.03, 0.7),
    ("CVE-2026-1008", 0.01, 0.4),
]
PRIORITY_ORDER = [
    "CVE-2026-1002",  # P1, newest KEV entry
    "CVE-2026-1001",  # P1
    "CVE-2026-1003",  # P2
    "CVE-2026-1005",  # P3, highest EPSS
    "CVE-2026-1004",  # P3
    "CVE-2026-1006",  # P4, highest CVSS
    "CVE-2026-1008",  # P4
    "CVE-2026-1007",  # P4 without CVSS goes last
]


async def seed(database_url: str) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            for cve, day, status, cvss, classification in CVES:
                await connection.execute(
                    text(
                        "INSERT INTO vulnerabilities (cve_id, published, last_modified, "
                        "vuln_status, description, cvss_version, cvss_score, cvss_severity, "
                        'cvss_vector, cvss_metrics, cwes, "references", raw, classification) '
                        "VALUES (:cve, :published, :published, :status, 'Description.', "
                        ":version, :cvss, :severity, NULL, CAST(:metrics AS jsonb), "
                        "ARRAY['CWE-79'], CAST(:refs AS jsonb), '{}', "
                        "CAST(:classification AS classification))"
                    ),
                    {
                        "cve": cve,
                        "published": datetime(2026, 10, day, 12, tzinfo=UTC),
                        "status": status,
                        "version": "3.1" if cvss is not None else None,
                        "cvss": cvss,
                        "severity": "CRITICAL" if cvss and cvss >= 9 else None,
                        "metrics": json.dumps(
                            [
                                {
                                    "version": "3.1",
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "score": cvss,
                                    "severity": "CRITICAL",
                                    "vector": "CVSS:3.1/AV:N",
                                }
                            ]
                            if cvss is not None
                            else []
                        ),
                        "refs": json.dumps([{"url": "https://example.org/a", "tags": ["Patch"]}]),
                        "classification": classification,
                    },
                )
            for cve, added, ransomware, classification in KEV:
                await connection.execute(
                    text(
                        "INSERT INTO kev_entries (cve_id, vendor_project, product, "
                        "vulnerability_name, date_added, short_description, required_action, "
                        "due_date, known_ransomware_campaign_use, cwes, catalog_version, raw, "
                        "classification) VALUES (:cve, 'Microsoft', 'Windows', 'name', "
                        "CAST(:added AS date), 'description', 'action', NULL, :ransomware, "
                        "ARRAY['CWE-79'], '2026.10.06', '{}', "
                        "CAST(:classification AS classification))"
                    ),
                    {
                        "cve": cve,
                        "added": date.fromisoformat(added),
                        "ransomware": ransomware,
                        "classification": classification,
                    },
                )
            for cve, score, percentile in EPSS:
                await connection.execute(
                    text(
                        "INSERT INTO epss_scores (cve_id, epss, percentile, model_version, "
                        "score_date, history_epss, classification) VALUES (:cve, :epss, :pct, "
                        "'v2026.06.15', CAST('2026-10-08' AS date), :epss, 'public')"
                    ),
                    {"cve": cve, "epss": score, "pct": percentile},
                )
            await connection.execute(
                text(
                    "INSERT INTO epss_history (cve_id, score_date, epss, percentile, "
                    "model_version, reason, classification) VALUES "
                    "('CVE-2026-1001', CAST('2026-10-07' AS date), 0.4, 0.9, 'v2026.06.15', "
                    "'first', 'public'), "
                    "('CVE-2026-1001', CAST('2026-10-08' AS date), 0.9, 0.99, 'v2026.06.15', "
                    "'threshold', 'public')"
                )
            )
            await connection.execute(
                text(
                    "INSERT INTO vulnerability_products (cve_id, source, vendor, product, part) "
                    "VALUES ('CVE-2026-1001', 'cpe', 'microsoft', 'windows', 'o'), "
                    "('CVE-2026-1001', 'cna', 'microsoft', 'windows_server', NULL), "
                    "('CVE-2026-1004', 'cpe', 'fortinet', 'fortios', 'o')"
                )
            )
        await recompute_all_priorities(create_session_factory(engine), 0.5)
    finally:
        await engine.dispose()


@pytest.fixture
def api(migrated_database_url: str) -> Iterator[TestClient]:
    asyncio.run(seed(migrated_database_url))
    settings = Settings(
        environment="test",
        log_level="WARNING",
        database_url=SecretStr(migrated_database_url),
        collector_env={},
    )
    with logged_in(migrated_database_url, settings=settings) as client:
        yield client


def ids(page: dict[str, Any]) -> list[str]:
    return [item["cve_id"] for item in page["items"]]


def walk(api: TestClient, params: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(20):
        page = api.get("/api/v1/cves", params={**params, **({"cursor": cursor} if cursor else {})})
        assert page.status_code == 200
        seen += ids(page.json())
        cursor = page.json()["next_cursor"]
        if cursor is None:
            return seen
    raise AssertionError("pagination did not end")


def test_default_order_is_priority(api: TestClient) -> None:
    response = api.get("/api/v1/cves")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, max-age=60"
    page = response.json()
    # Rejected CVEs are excluded by default; the internal CVE is neither listed nor counted.
    assert ids(page) == PRIORITY_ORDER
    assert page["total"] == len(PRIORITY_ORDER)
    first = page["items"][0]
    assert first["priority"]["level"] == "P1"
    assert first["priority"]["reason"]["rule"] == "kev_ransomware"
    assert first["kev"]["ransomware_known"] is True
    assert first["epss"]["score"] == 0.2


def test_list_item_carries_products_epss_and_cvss(api: TestClient) -> None:
    page = api.get("/api/v1/cves", params={"level": "P1"}).json()
    item = next(i for i in page["items"] if i["cve_id"] == "CVE-2026-1001")

    assert item["cvss"] == {"score": 9.8, "version": "3.1", "severity": "CRITICAL"}
    assert item["products_total"] == 2
    # NVD CPE data comes before CNA data.
    assert item["products"][0] == {
        "vendor": "microsoft",
        "product": "windows",
        "source": "cpe",
        "part": "o",
    }


@pytest.mark.parametrize("sort", ["priority", "published"])
def test_pagination_walks_every_cve_once(api: TestClient, sort: str) -> None:
    seen = walk(api, {"limit": 3, "sort": sort})

    if sort == "priority":
        assert seen == PRIORITY_ORDER
    else:
        assert seen == sorted(PRIORITY_ORDER, reverse=True)


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (
            {"level": ["P1", "P3"]},
            ["CVE-2026-1002", "CVE-2026-1001", "CVE-2026-1005", "CVE-2026-1004"],
        ),
        ({"level": "P2"}, ["CVE-2026-1003"]),
        ({"in_kev": "true"}, ["CVE-2026-1002", "CVE-2026-1001", "CVE-2026-1003"]),
        ({"in_kev": "false", "level": "P4"}, ["CVE-2026-1006", "CVE-2026-1008", "CVE-2026-1007"]),
        ({"min_epss": 0.6}, ["CVE-2026-1001", "CVE-2026-1005", "CVE-2026-1004"]),
        ({"min_cvss": 9}, ["CVE-2026-1001", "CVE-2026-1006"]),
        ({"vendor": "MICRO"}, ["CVE-2026-1001"]),
        ({"vendor": "%"}, []),
        (
            {"published_from": "2026-10-04", "published_to": "2026-10-05"},
            ["CVE-2026-1005", "CVE-2026-1004"],
        ),
        (
            {"include_rejected": "true", "level": "P4"},
            ["CVE-2026-1006", "CVE-2026-1008", "CVE-2026-1009", "CVE-2026-1007"],
        ),
    ],
)
def test_filters(api: TestClient, params: dict[str, Any], expected: list[str]) -> None:
    page = api.get("/api/v1/cves", params=params).json()

    assert ids(page) == expected
    assert page["total"] == len(expected)


def test_invalid_parameters(api: TestClient) -> None:
    assert api.get("/api/v1/cves", params={"level": "P5"}).status_code == 422
    assert api.get("/api/v1/cves", params={"cursor": "not-a-cursor"}).status_code == 400
    priority_cursor = api.get("/api/v1/cves", params={"limit": 1}).json()["next_cursor"]
    wrong_sort = api.get("/api/v1/cves", params={"sort": "published", "cursor": priority_cursor})
    assert wrong_sort.status_code == 400
    assert wrong_sort.headers["content-type"].startswith("application/problem+json")


def test_detail(api: TestClient) -> None:
    response = api.get("/api/v1/cves/cve-2026-1001")

    assert response.status_code == 200
    detail = response.json()
    assert detail["cve_id"] == "CVE-2026-1001"
    assert detail["priority"]["level"] == "P1"
    assert detail["priority"]["reason"] == {
        "rule": "kev_ransomware",
        "kev": {"date_added": "2026-10-01", "ransomware_use": "Known"},
        "epss": {"score": 0.9, "percentile": 0.99},
        "epss_threshold": 0.5,
        "cvss": {"score": 9.8, "version": "3.1", "severity": "CRITICAL"},
    }
    assert detail["kev"]["required_action"] == "action"
    assert [p["reason"] for p in detail["epss_history"]] == ["first", "threshold"]
    assert len(detail["products"]) == 2
    assert detail["cvss_metrics"][0]["vector"] == "CVSS:3.1/AV:N"
    assert detail["references"] == [{"url": "https://example.org/a", "tags": ["Patch"]}]
    assert detail["cwes"] == ["CWE-79"]


@pytest.mark.parametrize("cve_id", ["CVE-2026-1010", "CVE-2026-9999", "not-a-cve"])
def test_detail_not_found_or_not_visible(api: TestClient, cve_id: str) -> None:
    response = api.get(f"/api/v1/cves/{cve_id}")

    # An internal CVE looks exactly like a missing one to an anonymous caller.
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
