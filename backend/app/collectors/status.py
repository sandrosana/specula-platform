"""Effective collector configuration, published by the scheduler for the API.

Only the scheduler receives the source API keys, so only it can tell whether a
collector is configured. It writes the outcome to collector_state at startup
and the next run time after every run; GET /sources reads it from there.
"""

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.collectors.base import Cron, Interval, Schedule, missing_settings
from app.collectors.registry import CollectorConfig
from app.models import CollectorState

SourceStatus = Literal["ok", "late", "error", "disabled", "pending", "unknown"]


def describe_schedule(schedule: Schedule | None) -> str | None:
    """'every 6h', 'every 30m', 'cron 15 6 * * *'."""
    if schedule is None:
        return None
    if isinstance(schedule, Cron):
        return f"cron {schedule.expression}"
    return f"every {describe_duration(schedule.every)}"


def describe_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def expected_period(schedule: Schedule | None) -> timedelta | None:
    """Time between two runs; cron schedules are assumed to run at least daily."""
    if isinstance(schedule, Interval):
        return schedule.every
    if isinstance(schedule, Cron):
        return timedelta(days=1)
    return None


def source_status(
    *,
    enabled: bool | None,
    last_status: str | None,
    last_success_at: datetime | None,
    period: timedelta | None,
    now: datetime,
) -> SourceStatus:
    """Status shown in GET /sources and the Sources view (docs/specifica §4.6).

    unknown: the scheduler never published the configuration; pending: enabled
    but never run successfully; late: no success for more than two periods.
    """
    if enabled is None:
        return "unknown"
    if not enabled:
        return "disabled"
    if last_status in ("failed", "quota_exceeded"):
        return "error"
    if last_success_at is None:
        return "pending"
    if period is not None and now - last_success_at > 2 * period:
        return "late"
    return "ok"


async def publish_configs(
    sessions: async_sessionmaker[AsyncSession],
    configs: Iterable[CollectorConfig],
    next_runs: dict[str, datetime | None],
    now: datetime,
) -> None:
    async with sessions.begin() as session:
        for config in configs:
            cls = config.collector
            values = {
                "collector": cls.name,
                "enabled": config.enabled,
                "disabled_reason": config.disabled_reason,
                "configured": not missing_settings(cls, config.secrets),
                "schedule": describe_schedule(config.schedule),
                "next_run_at": next_runs.get(cls.name),
                "config_published_at": now,
            }
            statement = insert(CollectorState).values(**values)
            await session.execute(
                statement.on_conflict_do_update(
                    index_elements=[CollectorState.collector],
                    set_={key: statement.excluded[key] for key in values if key != "collector"},
                )
            )


async def publish_next_run(
    sessions: async_sessionmaker[AsyncSession], name: str, next_run_at: datetime | None
) -> None:
    statement = insert(CollectorState).values(collector=name, next_run_at=next_run_at)
    async with sessions.begin() as session:
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[CollectorState.collector],
                set_={"next_run_at": statement.excluded.next_run_at},
            )
        )
