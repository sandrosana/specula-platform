"""GET /kev: CISA Known Exploited Vulnerabilities (docs/architettura.md §9)."""

from datetime import date
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response

from app.api.deps import SessionDep, VisibleClassesDep
from app.api.pagination import decode_cursor, encode_cursor
from app.repositories.kev import KevFilters, count_kev, kev_data_as_of, list_kev
from app.schemas.kev import KevItem, KevPage

router = APIRouter(tags=["vulnerabilities"])


@router.get("/kev", summary="List KEV catalog entries, newest first")
async def get_kev(
    response: Response,
    session: SessionDep,
    visible: VisibleClassesDep,
    vendor: Annotated[str | None, Query(max_length=200, description="Vendor contains")] = None,
    product: Annotated[str | None, Query(max_length=200, description="Product contains")] = None,
    ransomware: Annotated[
        bool | None, Query(description="Known use in ransomware campaigns")
    ] = None,
    added_from: Annotated[date | None, Query(description="Added on or after")] = None,
    added_to: Annotated[date | None, Query(description="Added on or before")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    cursor: Annotated[str | None, Query(max_length=500)] = None,
) -> KevPage:
    after: tuple[date, str] | None = None
    if cursor:
        position = decode_cursor(cursor)
        try:
            after = (date.fromisoformat(str(position["d"])), str(position["c"]))
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor.") from exc

    filters = KevFilters(
        vendor=vendor,
        product=product,
        ransomware=ransomware,
        added_from=added_from,
        added_to=added_to,
    )
    rows, more = await list_kev(session, filters=filters, visible=visible, limit=limit, after=after)
    next_cursor = (
        encode_cursor({"d": rows[-1].date_added.isoformat(), "c": rows[-1].cve_id})
        if more and rows
        else None
    )
    response.headers["Cache-Control"] = "private, max-age=60"
    return KevPage(
        items=[KevItem.model_validate(row) for row in rows],
        total=await count_kev(session, filters=filters, visible=visible),
        next_cursor=next_cursor,
        data_as_of=await kev_data_as_of(session),
    )
