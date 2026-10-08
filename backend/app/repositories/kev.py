from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import ColumnElement, and_, func, literal, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.classification import Classification
from app.models import CollectorState, KevEntryRow


@dataclass(frozen=True)
class KevFilters:
    vendor: str | None = None
    product: str | None = None
    ransomware: bool | None = None
    added_from: date | None = None
    added_to: date | None = None


def _contains(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _conditions(
    filters: KevFilters, visible: frozenset[Classification]
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [KevEntryRow.classification.in_(visible)]
    if filters.vendor:
        conditions.append(KevEntryRow.vendor_project.ilike(_contains(filters.vendor), escape="\\"))
    if filters.product:
        conditions.append(KevEntryRow.product.ilike(_contains(filters.product), escape="\\"))
    if filters.ransomware is True:
        conditions.append(KevEntryRow.known_ransomware_campaign_use == "Known")
    elif filters.ransomware is False:
        conditions.append(
            or_(
                KevEntryRow.known_ransomware_campaign_use.is_(None),
                KevEntryRow.known_ransomware_campaign_use != "Known",
            )
        )
    if filters.added_from:
        conditions.append(KevEntryRow.date_added >= filters.added_from)
    if filters.added_to:
        conditions.append(KevEntryRow.date_added <= filters.added_to)
    return conditions


async def list_kev(
    session: AsyncSession,
    *,
    filters: KevFilters,
    visible: frozenset[Classification],
    limit: int,
    after: tuple[date, str] | None,
) -> tuple[list[KevEntryRow], bool]:
    """Newest first (date_added, cve_id). Returns the page and whether more rows follow."""
    conditions = _conditions(filters, visible)
    if after is not None:
        conditions.append(
            tuple_(KevEntryRow.date_added, KevEntryRow.cve_id)
            < tuple_(literal(after[0]), literal(after[1]))
        )
    rows = (
        await session.scalars(
            select(KevEntryRow)
            .where(and_(*conditions))
            .order_by(KevEntryRow.date_added.desc(), KevEntryRow.cve_id.desc())
            .limit(limit + 1)
        )
    ).all()
    return list(rows[:limit]), len(rows) > limit


async def count_kev(
    session: AsyncSession, *, filters: KevFilters, visible: frozenset[Classification]
) -> int:
    total = await session.scalar(
        select(func.count()).select_from(KevEntryRow).where(and_(*_conditions(filters, visible)))
    )
    return int(total or 0)


async def kev_data_as_of(session: AsyncSession) -> datetime | None:
    state = await session.get(CollectorState, "cisa_kev")
    return state.last_success_at if state is not None else None
