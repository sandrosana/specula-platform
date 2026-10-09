"""Inline post-processor: CVE priority level and reason (docs/architettura.md §5.6).

Runs after NVD, KEV and EPSS writes, in the same transaction, for the CVEs of
the batch. Only CVEs present in `vulnerabilities` get a level: a KEV or EPSS
record of a CVE that NVD has not delivered yet is picked up when NVD writes it.
All inputs are public data in the MVP.
"""

from collections.abc import Iterable, Sequence
from typing import Any, ClassVar

from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.collectors.cisa_kev import KevEntry
from app.collectors.epss import EpssScore
from app.collectors.nvd import Vulnerability
from app.core.config import get_settings
from app.models import EpssScoreRow, KevEntryRow, VulnerabilityRow
from app.processing.base import PostProcessor, register_processor
from app.services.priority import PriorityFacts, evaluate

RECOMPUTE_BATCH = 2000


async def recompute_priorities(
    session: AsyncSession, cve_ids: Iterable[str], epss_threshold: float | None = None
) -> int:
    """Update level and reason of the given CVEs where they changed; returns the count."""
    ids = sorted(set(cve_ids))
    if not ids:
        return 0
    threshold = get_settings().epss_threshold if epss_threshold is None else epss_threshold
    rows = await session.execute(
        select(
            VulnerabilityRow.cve_id,
            VulnerabilityRow.cvss_score,
            VulnerabilityRow.cvss_version,
            VulnerabilityRow.cvss_severity,
            VulnerabilityRow.priority_level,
            VulnerabilityRow.priority_reason,
            KevEntryRow.date_added,
            KevEntryRow.known_ransomware_campaign_use,
            EpssScoreRow.epss,
            EpssScoreRow.percentile,
        )
        .outerjoin(KevEntryRow, KevEntryRow.cve_id == VulnerabilityRow.cve_id)
        .outerjoin(EpssScoreRow, EpssScoreRow.cve_id == VulnerabilityRow.cve_id)
        .where(VulnerabilityRow.cve_id.in_(ids))
    )
    changes: list[dict[str, Any]] = []
    for row in rows:
        level, reason = evaluate(
            PriorityFacts(
                kev_date_added=row.date_added,
                kev_ransomware_use=row.known_ransomware_campaign_use,
                epss=row.epss,
                epss_percentile=row.percentile,
                cvss_score=row.cvss_score,
                cvss_version=row.cvss_version,
                cvss_severity=row.cvss_severity,
            ),
            threshold,
        )
        if level != row.priority_level or reason != row.priority_reason:
            changes.append(
                {"cve_id": row.cve_id, "priority_level": level, "priority_reason": reason}
            )
    if changes:
        # ORM bulk UPDATE by primary key: one executemany statement.
        await session.execute(update(VulnerabilityRow), changes)
    return len(changes)


async def recompute_all_priorities(
    sessions: async_sessionmaker[AsyncSession], epss_threshold: float | None = None
) -> int:
    """Every CVE, in keyset batches: initial backfill or after changing EPSS_THRESHOLD.

    One transaction per batch, so running collectors are never blocked for long.
    """
    changed = 0
    last = ""
    while True:
        async with sessions.begin() as session:
            ids = list(
                await session.scalars(
                    select(VulnerabilityRow.cve_id)
                    .where(VulnerabilityRow.cve_id > last)
                    .order_by(VulnerabilityRow.cve_id)
                    .limit(RECOMPUTE_BATCH)
                )
            )
            if not ids:
                return changed
            changed += await recompute_priorities(session, ids, epss_threshold)
        last = ids[-1]


class PriorityProcessor(PostProcessor):
    name = "priority_level"
    version = "1"
    applies_to: ClassVar[frozenset[type[BaseModel]]] = frozenset(
        {Vulnerability, KevEntry, EpssScore}
    )

    async def process(self, session: AsyncSession, entities: Sequence[BaseModel]) -> None:
        ids = [
            entity.cve_id
            for entity in entities
            if isinstance(entity, Vulnerability | KevEntry | EpssScore)
        ]
        await recompute_priorities(session, ids)


register_processor(PriorityProcessor())
