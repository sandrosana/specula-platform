"""Scheduler entrypoint (docs/architettura.md §5.2, §5.4). Run with: python -m app.scheduler"""

import asyncio
import logging
import signal
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.collectors.base import Cron, PeriodicCollector, Schedule
from app.collectors.http import create_http_client, utcnow
from app.collectors.registry import CollectorConfig, discover, resolve
from app.collectors.runner import CollectorRunner
from app.collectors.status import publish_configs, publish_next_run
from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_session_factory
from app.core.logging import configure_logging
from app.models import CollectorState

logger = logging.getLogger(__name__)

# Daily cleanup of expired HTTP cache entries (docs/architettura.md §7.1).
CACHE_PURGE_HOUR, CACHE_PURGE_MINUTE = 3, 15


@dataclass(frozen=True)
class JobSpec:
    collector: str
    schedule: Schedule


def make_trigger(schedule: Schedule, timezone: str) -> Any:
    if isinstance(schedule, Cron):
        return CronTrigger.from_crontab(schedule.expression, timezone=timezone)
    return IntervalTrigger(seconds=int(schedule.every.total_seconds()), timezone=timezone)


def first_run_time(
    schedule: Schedule, last_success_at: datetime | None, now: datetime
) -> datetime | None:
    """When an interval job first runs after a (re)start.

    Interval timers would otherwise restart from zero at every deploy, and a
    collector restarted often enough would never run. The first run is due one
    interval after the last success, or immediately if that time has passed or
    the collector never succeeded. Cron schedules keep their fixed times (None).
    """
    if isinstance(schedule, Cron):
        return None
    if last_success_at is None:
        return now
    return max(last_success_at + schedule.every, now)


async def _last_successes(sessions: async_sessionmaker[AsyncSession]) -> dict[str, datetime]:
    async with sessions() as session:
        rows = (
            await session.execute(select(CollectorState.collector, CollectorState.last_success_at))
        ).all()
    return {name: at for name, at in rows if at is not None}


def resolve_periodic(settings: Settings) -> list[CollectorConfig]:
    return [resolve(cls, settings) for cls in discover() if issubclass(cls, PeriodicCollector)]


def plan_jobs(settings: Settings) -> list[JobSpec]:
    """One job per enabled periodic collector; disabled ones are logged and skipped."""
    jobs: list[JobSpec] = []
    for config in resolve_periodic(settings):
        name = config.collector.name
        if not config.enabled or config.schedule is None:
            logger.info("collector %s not scheduled: %s", name, config.disabled_reason)
            continue
        jobs.append(JobSpec(name, config.schedule))
    return jobs


async def run(stop: asyncio.Event, settings: Settings | None = None) -> None:
    """Run the collector schedules until `stop` is set."""
    config = settings or get_settings()
    configs = resolve_periodic(config)
    jobs = plan_jobs(config)
    engine = create_engine(config)
    sessions = create_session_factory(engine)
    http_client = create_http_client(config)
    runner = CollectorRunner(engine=engine, settings=config, http_client=http_client)
    scheduler = AsyncIOScheduler(timezone=config.scheduler_timezone)

    async def run_collector(name: str) -> None:
        await runner.run(name)
        job = scheduler.get_job(name)
        try:
            await publish_next_run(sessions, name, job.next_run_time if job else None)
        except Exception:
            logger.warning("could not publish the next run of %s", name, exc_info=True)

    try:
        last_successes = await _last_successes(sessions)
    except Exception:
        # Without the database the timers simply start from now.
        logger.warning("could not read the last successful runs", exc_info=True)
        last_successes = {}
    started_at = utcnow()
    for job in jobs:
        options: dict[str, Any] = {}
        first = first_run_time(job.schedule, last_successes.get(job.collector), started_at)
        if first is not None:
            options["next_run_time"] = first
        scheduler.add_job(
            run_collector,
            make_trigger(job.schedule, config.scheduler_timezone),
            args=[job.collector],
            id=job.collector,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=3600,
            **options,
        )
    scheduler.add_job(
        runner.purge_http_cache,
        CronTrigger(
            hour=CACHE_PURGE_HOUR, minute=CACHE_PURGE_MINUTE, timezone=config.scheduler_timezone
        ),
        id="purge_http_cache",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    if jobs:
        names = ", ".join(job.collector for job in jobs)
        logger.info("scheduler started: %d collector(s) scheduled (%s)", len(jobs), names)
    else:
        logger.info("scheduler started: no collectors registered yet")

    next_runs: dict[str, datetime | None] = {}
    for job in jobs:
        scheduled = scheduler.get_job(job.collector)
        next_runs[job.collector] = scheduled.next_run_time if scheduled else None
    try:
        await publish_configs(sessions, configs, next_runs, utcnow())
    except Exception:
        # The schedules keep running; GET /sources shows the configuration as unknown.
        logger.warning("could not publish the collector configuration", exc_info=True)

    try:
        await stop.wait()
    finally:
        scheduler.shutdown(wait=False)
        await http_client.aclose()
        await engine.dispose()
        logger.info("scheduler stopped")


async def _serve() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await run(stop)


def main() -> None:
    configure_logging(get_settings().log_level)
    asyncio.run(_serve())
