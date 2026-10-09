"""NVD CVE API 2.0 (docs/architettura.md §6.1, §6.2).

Verified on 2026-10-08 against https://nvd.nist.gov/developers/start-here and
https://nvd.nist.gov/developers/vulnerabilities:
- API key in the `apiKey` header; 5 requests per rolling 30 s without key, 50 with;
  NVD asks to sleep 6 s between requests in any case, and not to sync more
  often than every two hours;
- initial load: page through everything with startIndex and the default
  resultsPerPage (2,000); then lastModStartDate = last lastModified received,
  lastModEndDate = now, at most 120 consecutive days per request.
"""

from collections.abc import AsyncIterator, Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, delete, func, insert, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import (
    CollectorContext,
    Cursor,
    Interval,
    PeriodicCollector,
    RateLimit,
    RawRecord,
    Schedule,
    SourceLicense,
)
from app.collectors.registry import register
from app.collectors.writers import WriteStats, register_writer
from app.core.classification import Classification
from app.models import VulnerabilityProductRow, VulnerabilityRow

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW = timedelta(days=120)
REQUEST_TIMEOUT_SECONDS = 120.0
# Preference order of the reference score (docs/specifica §4.2: v4.0, else v3.x).
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
PRODUCTS_PER_STATEMENT = 2000


def parse_nvd_datetime(value: str) -> datetime:
    """NVD timestamps are UTC without an offset (e.g. 2026-10-04T12:15:47.123)."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def format_nvd_datetime(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Split [start, end] into consecutive ranges of at most 120 days."""
    ranges: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        upper = min(cursor + MAX_WINDOW, end)
        ranges.append((cursor, upper))
        cursor = upper
    return ranges or [(start, end)]


class CvssScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    source: str | None
    type: str | None
    score: float
    severity: str | None
    vector: str | None


class AffectedProduct(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str  # "cpe" or "cna"
    vendor: str
    product: str
    part: str | None = None


class Vulnerability(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")
    source_identifier: str | None = None
    published: datetime
    last_modified: datetime
    vuln_status: str
    description: str | None = None
    cvss: CvssScore | None = None
    cvss_metrics: tuple[CvssScore, ...] = ()
    cwes: tuple[str, ...] = ()
    references: tuple[dict[str, Any], ...] = ()
    products: tuple[AffectedProduct, ...] = ()
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @field_validator("published", "last_modified", mode="before")
    @classmethod
    def _utc(cls, value: object) -> object:
        return parse_nvd_datetime(value) if isinstance(value, str) else value


def cvss_metrics(metrics: dict[str, Any]) -> list[CvssScore]:
    """All CVSS metrics in preference order. SSVC and other non-CVSS blocks are ignored."""
    scores: list[CvssScore] = []
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        # NVD's own analysis (Primary) first, then CNA and other scorers (Secondary).
        ordered = sorted(entries, key=lambda entry: 0 if entry.get("type") == "Primary" else 1)
        for entry in ordered:
            data = entry.get("cvssData")
            if not isinstance(data, dict) or data.get("baseScore") is None:
                continue
            scores.append(
                CvssScore(
                    version=str(data.get("version", "")),
                    source=entry.get("source"),
                    type=entry.get("type"),
                    score=float(data["baseScore"]),
                    # In CVSS v2 records the severity sits next to cvssData.
                    severity=data.get("baseSeverity") or entry.get("baseSeverity"),
                    vector=data.get("vectorString"),
                )
            )
    return scores


def affected_products(cve: dict[str, Any]) -> list[AffectedProduct]:
    products: dict[tuple[str, str, str], AffectedProduct] = {}
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = str(match.get("criteria", "")).split(":")
                if not match.get("vulnerable") or len(parts) < 5 or parts[3] in ("*", "-"):
                    continue
                vendor, product = parts[3].lower(), parts[4].lower()
                products.setdefault(
                    ("cpe", vendor, product),
                    AffectedProduct(source="cpe", vendor=vendor, product=product, part=parts[2]),
                )
    for affected in cve.get("affected") or []:
        for data in affected.get("affectedData") or []:
            vendor = str(data.get("vendor") or "").strip().lower()
            product = str(data.get("product") or "").strip().lower()
            if vendor and product and vendor != "n/a" and product != "n/a":
                products.setdefault(
                    ("cna", vendor, product),
                    AffectedProduct(source="cna", vendor=vendor, product=product),
                )
    return list(products.values())


def normalize_cve(cve: dict[str, Any]) -> Vulnerability:
    descriptions = cve.get("descriptions") or []
    english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    scores = cvss_metrics(cve.get("metrics") or {})
    cwes = sorted(
        {
            description["value"]
            for weakness in cve.get("weaknesses") or []
            for description in weakness.get("description") or []
            if str(description.get("value", "")).startswith("CWE-")
        }
    )
    references = tuple(
        {"url": reference["url"], "tags": list(reference.get("tags") or [])}
        for reference in cve.get("references") or []
        if reference.get("url")
    )
    return Vulnerability.model_validate(
        {
            "cve_id": cve.get("id"),
            "source_identifier": cve.get("sourceIdentifier"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus") or "Unknown",
            "description": english or (descriptions[0].get("value") if descriptions else None),
            "cvss": scores[0] if scores else None,
            "cvss_metrics": scores,
            "cwes": cwes,
            "references": references,
            "products": affected_products(cve),
            "raw": cve,
        }
    )


@register
class NvdCollector(PeriodicCollector):
    name = "nvd"
    display_name = "NVD - National Vulnerability Database"
    classification = Classification.PUBLIC
    license = SourceLicense(
        kind="Public domain (17 U.S.C. §105)",
        commercial_use="yes",
        terms_url="https://nvd.nist.gov/developers/start-here",
        quota="5 requests / 30 s without API key, 50 / 30 s with NVD_API_KEY",
        attribution=(
            "This product uses data from the NVD API but is not endorsed or certified by the NVD."
        ),
        notes="The NVD name may identify the source of the data, never imply endorsement.",
        verified_on=date(2026, 10, 8),
    )
    schedule: ClassVar[Schedule] = Interval(timedelta(hours=2))
    cache_ttl = timedelta(hours=1)
    # NVD recommends 6 s between requests even with a key; this also respects 5 per 30 s.
    rate_limit = RateLimit(requests=1, per=timedelta(seconds=6))
    optional_settings: ClassVar[tuple[str, ...]] = ("NVD_API_KEY",)

    def __init__(self) -> None:
        self._latest_modified: datetime | None = None

    async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        secret_headers = (
            {"apiKey": ctx.secrets["NVD_API_KEY"]} if "NVD_API_KEY" in ctx.secrets else {}
        )
        since = ctx.cursor.get("last_modified") if ctx.cursor and not ctx.full else None
        ranges: list[tuple[datetime, datetime] | None]
        if since:
            ranges = list(windows(parse_nvd_datetime(str(since)), datetime.now(UTC)))
            ctx.logger.info("NVD incremental sync since %s (%d window(s))", since, len(ranges))
        else:
            ranges = [None]
            ctx.logger.info("NVD full load")
        for window in ranges:
            async for cve in self._pages(ctx, window, secret_headers):
                yield cve

    async def _pages(
        self,
        ctx: CollectorContext,
        window: tuple[datetime, datetime] | None,
        secret_headers: dict[str, str],
    ) -> AsyncIterator[RawRecord]:
        start_index = 0
        while True:
            params = {"startIndex": str(start_index)}
            if window is not None:
                params["lastModStartDate"] = format_nvd_datetime(window[0])
                params["lastModEndDate"] = format_nvd_datetime(window[1])
            response = await ctx.http.get(
                API_URL,
                params=params,
                secret_headers=secret_headers,
                store=False,
                read_timeout=REQUEST_TIMEOUT_SECONDS,
            )
            page = response.json()
            if not isinstance(page, dict) or not isinstance(page.get("vulnerabilities"), list):
                raise ValueError("unexpected NVD response format")
            for item in page["vulnerabilities"]:
                cve = item.get("cve") if isinstance(item, dict) else None
                if not isinstance(cve, dict):
                    continue
                modified = cve.get("lastModified")
                if isinstance(modified, str):
                    at = parse_nvd_datetime(modified)
                    if self._latest_modified is None or at > self._latest_modified:
                        self._latest_modified = at
                yield cve
            per_page = int(page.get("resultsPerPage") or 0)
            total = int(page.get("totalResults") or 0)
            start_index += per_page
            if per_page == 0 or start_index >= total:
                return

    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        return [normalize_cve(dict(raw))]

    def next_cursor(self, ctx: CollectorContext) -> Cursor | None:
        if self._latest_modified is None:
            return ctx.cursor
        return {"last_modified": format_nvd_datetime(self._latest_modified)}


def _row(entity: Vulnerability, classification: Classification) -> dict[str, Any]:
    cvss = entity.cvss
    return {
        "cve_id": entity.cve_id,
        "source_identifier": entity.source_identifier,
        "published": entity.published,
        "last_modified": entity.last_modified,
        "vuln_status": entity.vuln_status,
        "description": entity.description,
        "cvss_version": cvss.version if cvss else None,
        "cvss_score": cvss.score if cvss else None,
        "cvss_severity": cvss.severity if cvss else None,
        "cvss_vector": cvss.vector if cvss else None,
        "cvss_source": cvss.source if cvss else None,
        "cvss_metrics": [score.model_dump() for score in entity.cvss_metrics],
        "cwes": list(entity.cwes),
        "references": list(entity.references),
        "raw": entity.raw,
        "classification": classification,
    }


@register_writer(Vulnerability)
async def write_vulnerabilities(
    session: AsyncSession, entities: Sequence[BaseModel], classification: Classification
) -> WriteStats:
    """Upsert on cve_id when lastModified changed; replace the products of changed CVEs."""
    by_cve: dict[str, Vulnerability] = {}
    for entity in entities:
        if not isinstance(entity, Vulnerability):
            raise TypeError(f"expected Vulnerability, got {type(entity).__name__}")
        by_cve[entity.cve_id] = entity
    if not by_cve:
        return WriteStats()

    rows = [_row(entity, classification) for entity in by_cve.values()]
    statement = pg_insert(VulnerabilityRow).values(rows)
    upsert = statement.on_conflict_do_update(
        index_elements=[VulnerabilityRow.cve_id],
        set_={
            **{name: statement.excluded[name] for name in rows[0] if name != "cve_id"},
            "updated_at": func.now(),
        },
        where=VulnerabilityRow.last_modified.is_distinct_from(statement.excluded.last_modified),
    ).returning(VulnerabilityRow.cve_id, literal_column("(xmax = 0)", Boolean).label("inserted"))
    written = (await session.execute(upsert)).all()
    changed = [row.cve_id for row in written]
    if changed:
        await session.execute(
            delete(VulnerabilityProductRow).where(VulnerabilityProductRow.cve_id.in_(changed))
        )
        products = [
            {
                "cve_id": cve_id,
                "source": product.source,
                "vendor": product.vendor,
                "product": product.product,
                "part": product.part,
            }
            for cve_id in changed
            for product in by_cve[cve_id].products
        ]
        for start in range(0, len(products), PRODUCTS_PER_STATEMENT):
            await session.execute(
                insert(VulnerabilityProductRow), products[start : start + PRODUCTS_PER_STATEMENT]
            )
    inserted = sum(1 for row in written if row.inserted)
    return WriteStats(inserted=inserted, updated=len(written) - inserted)
