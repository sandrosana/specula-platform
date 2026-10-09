"""CVE queries for GET /cves and GET /cves/{cve_id} (docs/architettura.md §9).

Priority order (docs/specifica §6), expressed as one descending sort key so that
keyset pagination stays a single row comparison:
- level: P1 first (rank 4) ... P4 last (rank 1); CVEs not yet ranked count as P4;
- P1 and P2: KEV date added, then EPSS, then CVSS;
- P3: EPSS, then CVSS;
- P4: CVSS, then EPSS; missing values go last.
"""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Literal

from sqlalchemy import (
    ColumnElement,
    Date,
    Float,
    Integer,
    Select,
    and_,
    case,
    cast,
    exists,
    func,
    literal,
    select,
    tuple_,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.classification import Classification
from app.models import (
    CollectorState,
    EpssHistoryRow,
    EpssScoreRow,
    KevEntryRow,
    VulnerabilityProductRow,
    VulnerabilityRow,
)

CveSort = Literal["priority", "published"]
PRODUCTS_IN_LIST = 5
MISSING = -1.0
NO_DATE = date(1, 1, 1)


@dataclass(frozen=True)
class CveFilters:
    levels: frozenset[str] = frozenset()
    vendor: str | None = None
    in_kev: bool | None = None
    min_cvss: float | None = None
    min_epss: float | None = None
    published_from: date | None = None
    published_to: date | None = None
    include_rejected: bool = False


@dataclass(frozen=True)
class CveRow:
    vulnerability: VulnerabilityRow
    kev: KevEntryRow | None
    epss: EpssScoreRow | None
    sort_key: tuple[Any, ...]


def _contains(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _level() -> ColumnElement[str]:
    return func.coalesce(VulnerabilityRow.priority_level, "P4")


def _priority_key() -> list[ColumnElement[Any]]:
    level = _level()
    kev_level = level.in_(["P1", "P2"])
    epss = func.coalesce(EpssScoreRow.epss, MISSING)
    cvss = func.coalesce(cast(VulnerabilityRow.cvss_score, Float), MISSING)
    return [
        case({"P1": 4, "P2": 3, "P3": 2}, value=level, else_=1).cast(Integer),
        case((kev_level, func.coalesce(KevEntryRow.date_added, NO_DATE)), else_=NO_DATE).cast(Date),
        case((level == "P4", cvss), else_=epss).cast(Float),
        case((level == "P4", epss), else_=cvss).cast(Float),
        VulnerabilityRow.cve_id.expression,
    ]


def _published_key() -> list[ColumnElement[Any]]:
    return [VulnerabilityRow.published.expression, VulnerabilityRow.cve_id.expression]


def sort_key(sort: CveSort) -> list[ColumnElement[Any]]:
    return _priority_key() if sort == "priority" else _published_key()


def _base(visible: frozenset[Classification]) -> Select[Any]:
    # Joined sources follow the caller's visibility too: a hidden KEV or EPSS row
    # is treated as absent.
    return (
        select(VulnerabilityRow, KevEntryRow, EpssScoreRow)
        .outerjoin(
            KevEntryRow,
            and_(
                KevEntryRow.cve_id == VulnerabilityRow.cve_id,
                KevEntryRow.classification.in_(visible),
            ),
        )
        .outerjoin(
            EpssScoreRow,
            and_(
                EpssScoreRow.cve_id == VulnerabilityRow.cve_id,
                EpssScoreRow.classification.in_(visible),
            ),
        )
    )


def _conditions(
    filters: CveFilters, visible: frozenset[Classification]
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [VulnerabilityRow.classification.in_(visible)]
    if not filters.include_rejected:
        conditions.append(VulnerabilityRow.vuln_status != "Rejected")
    if filters.levels:
        conditions.append(_level().in_(sorted(filters.levels)))
    if filters.vendor:
        conditions.append(
            exists().where(
                VulnerabilityProductRow.cve_id == VulnerabilityRow.cve_id,
                VulnerabilityProductRow.vendor.ilike(_contains(filters.vendor), escape="\\"),
            )
        )
    if filters.in_kev is True:
        conditions.append(KevEntryRow.cve_id.is_not(None))
    elif filters.in_kev is False:
        conditions.append(KevEntryRow.cve_id.is_(None))
    if filters.min_cvss is not None:
        conditions.append(VulnerabilityRow.cvss_score >= filters.min_cvss)
    if filters.min_epss is not None:
        conditions.append(EpssScoreRow.epss >= filters.min_epss)
    if filters.published_from:
        conditions.append(func.date(VulnerabilityRow.published) >= filters.published_from)
    if filters.published_to:
        conditions.append(func.date(VulnerabilityRow.published) <= filters.published_to)
    return conditions


async def list_cves(
    session: AsyncSession,
    *,
    filters: CveFilters,
    visible: frozenset[Classification],
    sort: CveSort,
    limit: int,
    after: tuple[Any, ...] | None,
) -> tuple[list[CveRow], bool]:
    """One page in descending `sort` order and whether more rows follow."""
    key = sort_key(sort)
    conditions = _conditions(filters, visible)
    if after is not None:
        conditions.append(tuple_(*key) < tuple_(*(literal(value) for value in after)))
    statement = (
        _base(visible)
        .add_columns(*(column.label(f"k{i}") for i, column in enumerate(key)))
        .where(and_(*conditions))
        .order_by(*(column.desc() for column in key))
        .limit(limit + 1)
    )
    result = (await session.execute(statement)).all()
    rows = [
        CveRow(
            vulnerability=row[0],
            kev=row[1],
            epss=row[2],
            sort_key=tuple(row[3 + i] for i in range(len(key))),
        )
        for row in result[:limit]
    ]
    return rows, len(result) > limit


async def count_cves(
    session: AsyncSession, *, filters: CveFilters, visible: frozenset[Classification]
) -> int:
    statement = (
        select(func.count())
        .select_from(VulnerabilityRow)
        .outerjoin(
            KevEntryRow,
            and_(
                KevEntryRow.cve_id == VulnerabilityRow.cve_id,
                KevEntryRow.classification.in_(visible),
            ),
        )
        .outerjoin(
            EpssScoreRow,
            and_(
                EpssScoreRow.cve_id == VulnerabilityRow.cve_id,
                EpssScoreRow.classification.in_(visible),
            ),
        )
        .where(and_(*_conditions(filters, visible)))
    )
    return int(await session.scalar(statement) or 0)


async def products_of(
    session: AsyncSession, cve_ids: list[str]
) -> dict[str, list[VulnerabilityProductRow]]:
    """Affected products per CVE: NVD CPE data first, then CNA data."""
    if not cve_ids:
        return {}
    rows = await session.scalars(
        select(VulnerabilityProductRow)
        .where(VulnerabilityProductRow.cve_id.in_(cve_ids))
        .order_by(
            VulnerabilityProductRow.cve_id,
            case((VulnerabilityProductRow.source == "cpe", 0), else_=1),
            VulnerabilityProductRow.vendor,
            VulnerabilityProductRow.product,
        )
    )
    products: dict[str, list[VulnerabilityProductRow]] = {}
    for row in rows:
        products.setdefault(row.cve_id, []).append(row)
    return products


async def get_cve(
    session: AsyncSession, cve_id: str, visible: frozenset[Classification]
) -> CveRow | None:
    row = (
        await session.execute(
            _base(visible).where(
                VulnerabilityRow.cve_id == cve_id, VulnerabilityRow.classification.in_(visible)
            )
        )
    ).first()
    if row is None:
        return None
    return CveRow(vulnerability=row[0], kev=row[1], epss=row[2], sort_key=())


async def epss_history(
    session: AsyncSession, cve_id: str, visible: frozenset[Classification]
) -> list[EpssHistoryRow]:
    rows = await session.scalars(
        select(EpssHistoryRow)
        .where(EpssHistoryRow.cve_id == cve_id, EpssHistoryRow.classification.in_(visible))
        .order_by(EpssHistoryRow.score_date)
    )
    return list(rows)


async def nvd_data_as_of(session: AsyncSession) -> datetime | None:
    state = await session.get(CollectorState, "nvd")
    return state.last_success_at if state is not None else None
