"""GET /sources: status, licensing and usage of every source (docs/architettura.md §9)."""

from contextlib import suppress
from datetime import timedelta

from fastapi import APIRouter, Response

from app.api.deps import SessionDep
from app.collectors.base import CollectorBase, PeriodicCollector, QuotaPeriod
from app.collectors.http import period_start, utcnow
from app.collectors.registry import discover, parse_schedule
from app.collectors.status import expected_period, source_status
from app.models import CollectorRun, CollectorState
from app.repositories.sources import collector_states, last_runs, usage_since
from app.schemas.sources import (
    LastRunOut,
    SourceLicenseOut,
    SourceOut,
    SourcesOut,
    SourceUsageOut,
)

router = APIRouter(tags=["sources"])


def _period(cls: type[CollectorBase], state: CollectorState | None) -> timedelta | None:
    """Run period from the schedule published by the scheduler, else the declared one."""
    published = state.schedule if state is not None else None
    if published:
        text = published.removeprefix("every ").removeprefix("cron ")
        with suppress(ValueError):
            return expected_period(parse_schedule(text))
    return expected_period(cls.schedule) if issubclass(cls, PeriodicCollector) else None


def _last_run(run: CollectorRun | None) -> LastRunOut | None:
    if run is None:
        return None
    return LastRunOut(
        id=run.id,
        trigger=run.trigger,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        read=run.records_read,
        inserted=run.records_inserted,
        updated=run.records_updated,
        errors=run.errors,
    )


@router.get("/sources", summary="Status, licensing and usage of every source")
async def get_sources(response: Response, session: SessionDep) -> SourcesOut:
    now = utcnow()
    states = await collector_states(session)
    runs = await last_runs(session)
    items: list[SourceOut] = []
    for cls in discover():
        state = states.get(cls.name)
        period: QuotaPeriod = cls.quota.period if cls.quota else "month"
        since = period_start(now.date(), period)
        items.append(
            SourceOut(
                name=cls.name,
                display_name=cls.display_name,
                kind=cls.kind,
                classification=cls.classification,
                status=source_status(
                    enabled=state.enabled if state else None,
                    last_status=state.last_status if state else None,
                    last_success_at=state.last_success_at if state else None,
                    period=_period(cls, state),
                    now=now,
                ),
                enabled=state.enabled if state else None,
                disabled_reason=state.disabled_reason if state else None,
                configured=state.configured if state else None,
                schedule=state.schedule if state else None,
                last_run_at=state.last_run_at if state else None,
                last_success_at=state.last_success_at if state else None,
                next_run_at=state.next_run_at if state else None,
                last_run=_last_run(runs.get(cls.name)),
                license=SourceLicenseOut(
                    kind=cls.license.kind,
                    commercial_use=cls.license.commercial_use,
                    terms_url=cls.license.terms_url,
                    quota=cls.license.quota,
                    attribution=cls.license.attribution,
                    notes=cls.license.notes,
                    verified_on=cls.license.verified_on,
                ),
                usage=SourceUsageOut(
                    period=period,
                    since=since,
                    requests=await usage_since(session, cls.name, since),
                    limit=cls.quota.limit if cls.quota else None,
                ),
            )
        )
    response.headers["Cache-Control"] = "private, max-age=60"
    return SourcesOut(items=items, generated_at=now)
