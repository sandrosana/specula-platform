"""A scripted collector and its entity writer, shared by registry, scheduler and runner tests."""

from collections.abc import AsyncIterator, Iterable, Sequence
from datetime import timedelta
from typing import ClassVar

from pydantic import BaseModel
from sqlalchemy import text
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
from app.collectors.writers import WriteStats, register_writer
from app.core.classification import Classification

PROBE_TABLE_DDL = (
    "CREATE TABLE probe_items (id integer PRIMARY KEY, value text NOT NULL, "
    "classification classification NOT NULL DEFAULT 'sensitive')"
)


class ProbeItem(BaseModel):
    id: int
    value: str


@register_writer(ProbeItem)
async def write_probe_items(
    session: AsyncSession, entities: Sequence[BaseModel], classification: Classification
) -> WriteStats:
    stats = WriteStats()
    for entity in entities:
        if not isinstance(entity, ProbeItem):
            raise TypeError(type(entity).__name__)
        inserted = await session.scalar(
            text(
                "INSERT INTO probe_items (id, value, classification) "
                "VALUES (:id, :value, CAST(:classification AS classification)) "
                "ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, "
                "classification = EXCLUDED.classification RETURNING (xmax = 0)"
            ),
            {"id": entity.id, "value": entity.value, "classification": classification.value},
        )
        stats += WriteStats(inserted=1) if inserted else WriteStats(updated=1)
    return stats


class ScriptedCollector(PeriodicCollector):
    """Yields `records`, then raises `fail_with` if set. Records with "bad" fail to normalize."""

    name = "test_scripted"
    display_name = "Scripted test collector"
    license = SourceLicense(kind="Test", commercial_use="yes", terms_url="https://example.test")
    classification = Classification.PUBLIC
    schedule: ClassVar[Schedule] = Interval(timedelta(hours=1))
    cache_ttl = timedelta(minutes=30)

    records: ClassVar[list[RawRecord]] = []
    fail_with: ClassVar[Exception | None] = None
    seen_cursor: ClassVar[Cursor | None] = None

    async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        type(self).seen_cursor = ctx.cursor
        for record in self.records:
            yield record
        if self.fail_with is not None:
            raise self.fail_with

    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        if raw.get("bad"):
            raise ValueError("malformed record")
        return [ProbeItem(id=raw["id"], value=raw["value"])]

    def next_cursor(self, ctx: CollectorContext) -> Cursor | None:
        ids = [record["id"] for record in self.records if not record.get("bad")]
        return {"last_id": max(ids)} if ids else ctx.cursor


class KeyedCollector(ScriptedCollector):
    """Same, but requires an API key: disabled without it."""

    name = "test_keyed"
    display_name = "Keyed test collector"
    required_settings: ClassVar[tuple[str, ...]] = ("OTX_API_KEY",)
