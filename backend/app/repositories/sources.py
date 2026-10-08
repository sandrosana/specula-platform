from datetime import date

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CollectorRun, CollectorState, SourceUsage


async def collector_states(session: AsyncSession) -> dict[str, CollectorState]:
    rows = (await session.scalars(select(CollectorState))).all()
    return {row.collector: row for row in rows}


async def last_runs(session: AsyncSession) -> dict[str, CollectorRun]:
    """Most recent run of each collector."""
    rows = (
        await session.scalars(
            select(CollectorRun)
            .distinct(CollectorRun.collector)
            .order_by(CollectorRun.collector, CollectorRun.id.desc())
        )
    ).all()
    return {row.collector: row for row in rows}


async def usage_since(session: AsyncSession, source: str, since: date) -> int:
    total = await session.scalar(
        select(func.coalesce(func.sum(SourceUsage.requests), 0)).where(
            SourceUsage.source == source, SourceUsage.day >= since
        )
    )
    return int(total or 0)
