"""GET /cves and GET /cves/{cve_id} (docs/architettura.md §9, docs/specifica §6)."""

import re
from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, Response

from app.api.deps import SessionDep, VisibleClassesDep
from app.api.pagination import decode_cursor, encode_cursor
from app.models import EpssScoreRow, KevEntryRow, VulnerabilityProductRow, VulnerabilityRow
from app.repositories.cves import (
    PRODUCTS_IN_LIST,
    CveFilters,
    CveSort,
    count_cves,
    epss_history,
    get_cve,
    list_cves,
    nvd_data_as_of,
    products_of,
)
from app.schemas.cves import (
    AffectedProduct,
    CveDetail,
    CveItem,
    CvePage,
    CvssMetric,
    CvssSummary,
    EpssHistoryPoint,
    EpssSummary,
    KevDetail,
    KevSummary,
    Priority,
    PriorityLevel,
    Reference,
)

router = APIRouter(tags=["vulnerabilities"])

CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")


def _cursor_value(value: Any) -> Any:
    return value.isoformat() if isinstance(value, date | datetime) else value


def _decode_after(cursor: str, sort: CveSort) -> tuple[Any, ...]:
    position = decode_cursor(cursor)
    try:
        if position["s"] != sort:
            raise ValueError("cursor of another sort order")
        key = list(position["k"])
        if sort == "priority":
            return (
                int(key[0]),
                date.fromisoformat(str(key[1])),
                float(key[2]),
                float(key[3]),
                str(key[4]),
            )
        return (datetime.fromisoformat(str(key[0])), str(key[1]))
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc


def _cvss(row: VulnerabilityRow) -> CvssSummary | None:
    if row.cvss_score is None:
        return None
    return CvssSummary(score=row.cvss_score, version=row.cvss_version, severity=row.cvss_severity)


def _epss(row: EpssScoreRow | None) -> EpssSummary | None:
    if row is None:
        return None
    return EpssSummary(
        score=row.epss,
        percentile=row.percentile,
        score_date=row.score_date,
        model_version=row.model_version,
    )


def _kev(row: KevEntryRow | None) -> KevSummary | None:
    if row is None:
        return None
    return KevSummary(
        date_added=row.date_added,
        due_date=row.due_date,
        known_ransomware_campaign_use=row.known_ransomware_campaign_use,
        ransomware_known=row.ransomware_known,
    )


LEVELS: dict[str, PriorityLevel] = {"P1": "P1", "P2": "P2", "P3": "P3", "P4": "P4"}


def _priority(row: VulnerabilityRow) -> Priority:
    # None until the priority post-processor has ranked the CVE.
    return Priority(level=LEVELS.get(row.priority_level or ""), reason=row.priority_reason)


def _product(row: VulnerabilityProductRow) -> AffectedProduct:
    return AffectedProduct(vendor=row.vendor, product=row.product, source=row.source, part=row.part)


@router.get("/cves", summary="List CVEs, by priority level (default) or newest first")
async def get_cves(
    response: Response,
    session: SessionDep,
    visible: VisibleClassesDep,
    level: Annotated[
        list[PriorityLevel] | None, Query(description="Priority levels (repeatable)")
    ] = None,
    vendor: Annotated[
        str | None, Query(max_length=200, description="Affected vendor contains")
    ] = None,
    in_kev: Annotated[bool | None, Query(description="In the CISA KEV catalog")] = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    min_epss: Annotated[float | None, Query(ge=0, le=1)] = None,
    published_from: Annotated[date | None, Query(description="Published on or after")] = None,
    published_to: Annotated[date | None, Query(description="Published on or before")] = None,
    include_rejected: Annotated[
        bool, Query(description="Include CVEs rejected by their CNA")
    ] = False,
    sort: Annotated[CveSort, Query(description="priority (docs/specifica §6) or published")] = (
        "priority"
    ),
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    cursor: Annotated[str | None, Query(max_length=500)] = None,
) -> CvePage:
    after = _decode_after(cursor, sort) if cursor else None
    filters = CveFilters(
        levels=frozenset(level or ()),
        vendor=vendor,
        in_kev=in_kev,
        min_cvss=min_cvss,
        min_epss=min_epss,
        published_from=published_from,
        published_to=published_to,
        include_rejected=include_rejected,
    )
    rows, more = await list_cves(
        session, filters=filters, visible=visible, sort=sort, limit=limit, after=after
    )
    products = await products_of(session, [row.vulnerability.cve_id for row in rows])
    items = []
    for row in rows:
        vulnerability = row.vulnerability
        affected = products.get(vulnerability.cve_id, [])
        items.append(
            CveItem(
                cve_id=vulnerability.cve_id,
                published=vulnerability.published,
                last_modified=vulnerability.last_modified,
                vuln_status=vulnerability.vuln_status,
                description=vulnerability.description,
                cvss=_cvss(vulnerability),
                epss=_epss(row.epss),
                kev=_kev(row.kev),
                priority=_priority(vulnerability),
                products=[_product(p) for p in affected[:PRODUCTS_IN_LIST]],
                products_total=len(affected),
                classification=vulnerability.classification,
            )
        )
    next_cursor = (
        encode_cursor({"s": sort, "k": [_cursor_value(v) for v in rows[-1].sort_key]})
        if more and rows
        else None
    )
    response.headers["Cache-Control"] = "private, max-age=60"
    return CvePage(
        items=items,
        total=await count_cves(session, filters=filters, visible=visible),
        next_cursor=next_cursor,
        data_as_of=await nvd_data_as_of(session),
    )


@router.get("/cves/{cve_id}", summary="CVE detail with priority level and reason")
async def get_cve_detail(
    response: Response,
    session: SessionDep,
    visible: VisibleClassesDep,
    cve_id: Annotated[str, Path(max_length=32, description="e.g. CVE-2021-44228")],
) -> CveDetail:
    normalized = cve_id.strip().upper()
    found = await get_cve(session, normalized, visible) if CVE_ID.match(normalized) else None
    if found is None:
        raise HTTPException(status_code=404, detail="CVE not found.")
    vulnerability, kev = found.vulnerability, found.kev
    products = (await products_of(session, [vulnerability.cve_id])).get(vulnerability.cve_id, [])
    history = await epss_history(session, vulnerability.cve_id, visible)
    response.headers["Cache-Control"] = "private, max-age=60"
    return CveDetail(
        cve_id=vulnerability.cve_id,
        source_identifier=vulnerability.source_identifier,
        published=vulnerability.published,
        last_modified=vulnerability.last_modified,
        vuln_status=vulnerability.vuln_status,
        description=vulnerability.description,
        cvss=_cvss(vulnerability),
        cvss_vector=vulnerability.cvss_vector,
        cvss_metrics=[CvssMetric.model_validate(m) for m in vulnerability.cvss_metrics],
        cwes=list(vulnerability.cwes),
        references=[Reference.model_validate(r) for r in vulnerability.references],
        products=[_product(p) for p in products],
        epss=_epss(found.epss),
        epss_history=[
            EpssHistoryPoint(
                score_date=point.score_date,
                score=point.epss,
                percentile=point.percentile,
                model_version=point.model_version,
                reason=point.reason,
            )
            for point in history
        ],
        kev=(
            KevDetail(
                date_added=kev.date_added,
                due_date=kev.due_date,
                known_ransomware_campaign_use=kev.known_ransomware_campaign_use,
                ransomware_known=kev.ransomware_known,
                vendor_project=kev.vendor_project,
                product=kev.product,
                vulnerability_name=kev.vulnerability_name,
                short_description=kev.short_description,
                required_action=kev.required_action,
                notes=kev.notes,
            )
            if kev is not None
            else None
        ),
        priority=_priority(vulnerability),
        classification=vulnerability.classification,
        data_as_of=await nvd_data_as_of(session),
    )
