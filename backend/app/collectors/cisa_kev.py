"""CISA Known Exploited Vulnerabilities catalog (docs/architettura.md §6.1, §6.2).

The catalog is a single JSON file (about 1.7 MB, ~1,700 entries) published by
CISA under CC0 1.0. Every run downloads it (subject to the HTTP cache) and
upserts all entries; when the catalog version has not changed since the last
successful run, no records are processed.

Verified on 2026-10-08 against the official page, JSON schema and license:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from collections.abc import AsyncIterator, Iterable, Sequence
from datetime import date, timedelta
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, func, literal_column, or_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import (
    CollectorContext,
    Cursor,
    Interval,
    PeriodicCollector,
    RawRecord,
    Schedule,
    SourceLicense,
)
from app.collectors.registry import register
from app.collectors.writers import WriteStats, register_writer
from app.core.classification import Classification
from app.models import KevEntryRow

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_VERSION_FIELD = "_catalogVersion"


class KevEntry(BaseModel):
    """One catalog entry, normalized. Field aliases are the CISA JSON names."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    cve_id: str = Field(alias="cveID", pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")
    vendor_project: str = Field(alias="vendorProject")
    product: str
    vulnerability_name: str = Field(alias="vulnerabilityName")
    date_added: date = Field(alias="dateAdded")
    short_description: str = Field(alias="shortDescription")
    required_action: str = Field(alias="requiredAction")
    due_date: date | None = Field(default=None, alias="dueDate")
    known_ransomware_campaign_use: str | None = Field(
        default=None, alias="knownRansomwareCampaignUse"
    )
    forensic_triage: bool | None = Field(default=None, alias="forensicTriage")
    notes: str | None = None
    cwes: tuple[str, ...] = ()
    catalog_version: str = Field(alias=CATALOG_VERSION_FIELD)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @field_validator("forensic_triage", mode="before")
    @classmethod
    def _yes_no(cls, value: object) -> object:
        if isinstance(value, str):
            return {"yes": True, "no": False}.get(value.strip().lower())
        return value

    @field_validator("notes", "known_ransomware_campaign_use", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @property
    def ransomware_known(self) -> bool:
        return self.known_ransomware_campaign_use == "Known"


@register
class CisaKevCollector(PeriodicCollector):
    name = "cisa_kev"
    display_name = "CISA Known Exploited Vulnerabilities"
    classification = Classification.PUBLIC
    license = SourceLicense(
        kind="CC0 1.0 Universal",
        commercial_use="yes",
        terms_url="https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
        quota=None,
        attribution=None,
        notes=(
            "Public domain dedication. The CISA logo and DHS seal may not be used, "
            "and use of the data does not imply endorsement by CISA or DHS."
        ),
        verified_on=date(2026, 10, 8),
    )
    schedule: ClassVar[Schedule] = Interval(timedelta(hours=6))
    cache_ttl = timedelta(hours=3)

    def __init__(self) -> None:
        self._catalog: dict[str, Any] | None = None

    async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        response = await ctx.http.get(FEED_URL)
        catalog = response.json()
        if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
            raise ValueError("unexpected KEV catalog format")
        self._catalog = catalog
        version = str(catalog.get("catalogVersion", ""))
        if not ctx.full and ctx.cursor and ctx.cursor.get("catalog_version") == version:
            ctx.logger.info("KEV catalog %s already processed", version)
            return
        for item in catalog["vulnerabilities"]:
            if isinstance(item, dict):
                yield {**item, CATALOG_VERSION_FIELD: version}

    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        source = {key: value for key, value in raw.items() if key != CATALOG_VERSION_FIELD}
        return [KevEntry.model_validate({**raw, "raw": source})]

    def next_cursor(self, ctx: CollectorContext) -> Cursor | None:
        if self._catalog is None:
            return ctx.cursor
        return {
            "catalog_version": str(self._catalog.get("catalogVersion", "")),
            "date_released": self._catalog.get("dateReleased"),
            "count": self._catalog.get("count"),
        }


@register_writer(KevEntry)
async def write_kev_entries(
    session: AsyncSession, entities: Sequence[BaseModel], classification: Classification
) -> WriteStats:
    """Upsert on cve_id. Rows whose content did not change are left untouched."""
    # One row per CVE: PostgreSQL rejects an upsert touching the same key twice.
    by_cve: dict[str, dict[str, Any]] = {}
    for entity in entities:
        if not isinstance(entity, KevEntry):
            raise TypeError(f"expected KevEntry, got {type(entity).__name__}")
        by_cve[entity.cve_id] = {
            "cve_id": entity.cve_id,
            "vendor_project": entity.vendor_project,
            "product": entity.product,
            "vulnerability_name": entity.vulnerability_name,
            "date_added": entity.date_added,
            "short_description": entity.short_description,
            "required_action": entity.required_action,
            "due_date": entity.due_date,
            "known_ransomware_campaign_use": entity.known_ransomware_campaign_use,
            "forensic_triage": entity.forensic_triage,
            "notes": entity.notes,
            "cwes": list(entity.cwes),
            "catalog_version": entity.catalog_version,
            "raw": entity.raw,
            "classification": classification,
        }
    rows = list(by_cve.values())
    if not rows:
        return WriteStats()

    statement = insert(KevEntryRow).values(rows)
    content_columns = [name for name in rows[0] if name not in ("cve_id", "catalog_version", "raw")]
    changed = or_(
        *(
            getattr(KevEntryRow, name).is_distinct_from(statement.excluded[name])
            for name in content_columns
        )
    )
    upsert = statement.on_conflict_do_update(
        index_elements=[KevEntryRow.cve_id],
        set_={
            **{name: statement.excluded[name] for name in rows[0] if name != "cve_id"},
            "updated_at": func.now(),
        },
        where=changed,
    ).returning(literal_column("(xmax = 0)", Boolean).label("inserted"))
    # Unchanged rows are filtered by `where` and not returned: only real changes count.
    result = await session.execute(upsert)
    flags = [bool(row.inserted) for row in result]
    inserted = sum(flags)
    return WriteStats(inserted=inserted, updated=len(flags) - inserted)
