"""Scheduler entrypoint (docs/architettura.md §5.2, §5.4). Run with: python -m app.scheduler"""

import asyncio
import logging
import signal
from dataclasses import dataclass
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.collectors.base import Cron, PeriodicCollector, Schedule
from app.collectors.http import create_http_client
from app.collectors.registry import discover, resolve
from app.collectors.runner import CollectorRunner
from app.core.config import Settings, get_settings
from app.core.db import create_engine
from app.core.logging import configure_logging

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


def plan_jobs(settings: Settings) -> list[JobSpec]:
    """One job per enabled periodic collector; disabled ones are logged and skipped."""
    jobs: list[JobSpec] = []
    for cls in discover():
        if not issubclass(cls, PeriodicCollector):
            continue
        config = resolve(cls, settings)
        if not config.enabled or config.schedule is None:
            logger.info("collector %s not scheduled: %s", cls.name, config.disabled_reason)
            continue
        jobs.append(JobSpec(cls.name, config.schedule))
    return jobs


async def run(stop: asyncio.Event, settings: Settings | None = None) -> None:
    """Run the collector schedules until `stop` is set."""
    config = settings or get_settings()
    jobs = plan_jobs(config)
    engine = create_engine(config)
    http_client = create_http_client(config)
    runner = CollectorRunner(engine=engine, settings=config, http_client=http_client)
    scheduler = AsyncIOScheduler(timezone=config.scheduler_timezone)
    for job in jobs:
        scheduler.add_job(
            runner.run,
            make_trigger(job.schedule, config.scheduler_timezone),
            args=[job.collector],
            id=job.collector,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=3600,
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
