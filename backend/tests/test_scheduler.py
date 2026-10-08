import asyncio
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from pydantic import SecretStr

from app.collectors import registry
from app.collectors.base import Cron, Interval
from app.core.config import Settings
from app.scheduler.main import JobSpec, first_run_time, make_trigger, plan_jobs, run
from tests.collectors.scripted import KeyedCollector, ScriptedCollector


@pytest.fixture
def registered() -> Iterator[None]:
    registry.register(ScriptedCollector)
    registry.register(KeyedCollector)
    yield
    registry.unregister(ScriptedCollector.name)
    registry.unregister(KeyedCollector.name)


def make_settings(collector_env: dict[str, str] | None = None) -> Settings:
    return Settings(
        environment="test",
        database_url=SecretStr("postgresql+asyncpg://u:p@127.0.0.1:1/d"),
        collector_env=collector_env or {},
    )


def scheduled_test_jobs(settings: Settings) -> list[JobSpec]:
    """Jobs of the test collectors only (real collectors are registered too)."""
    return [job for job in plan_jobs(settings) if job.collector.startswith("test_")]


@pytest.mark.usefixtures("registered")
def test_only_enabled_collectors_are_scheduled() -> None:
    # KeyedCollector has no OTX_API_KEY: disabled, not scheduled.
    assert scheduled_test_jobs(make_settings()) == [
        JobSpec("test_scripted", Interval(timedelta(hours=1)))
    ]


@pytest.mark.usefixtures("registered")
def test_schedule_override_is_applied() -> None:
    settings = make_settings({"COLLECTOR_TEST_SCRIPTED_SCHEDULE": "15 6 * * *"})

    assert scheduled_test_jobs(settings) == [JobSpec("test_scripted", Cron("15 6 * * *"))]


def test_real_collectors_can_be_disabled() -> None:
    jobs = plan_jobs(make_settings({"COLLECTOR_CISA_KEV_ENABLED": "false"}))

    assert "cisa_kev" not in [job.collector for job in jobs]
    assert "cisa_kev" in [job.collector for job in plan_jobs(make_settings())]


NOW = datetime(2026, 10, 8, 16, 0, tzinfo=UTC)
SIX_HOURS = Interval(timedelta(hours=6))


def test_first_run_resumes_from_last_success() -> None:
    last = NOW - timedelta(hours=2)

    assert first_run_time(SIX_HOURS, last, NOW) == last + timedelta(hours=6)


def test_first_run_is_immediate_when_overdue_or_never_run() -> None:
    assert first_run_time(SIX_HOURS, NOW - timedelta(hours=9), NOW) == NOW
    assert first_run_time(SIX_HOURS, None, NOW) == NOW


def test_cron_schedules_keep_their_fixed_times() -> None:
    assert first_run_time(Cron("15 6 * * *"), NOW - timedelta(days=3), NOW) is None


def test_make_trigger() -> None:
    assert isinstance(make_trigger(Cron("15 6 * * *"), "Europe/Rome"), CronTrigger)
    interval = make_trigger(Interval(timedelta(hours=2)), "Europe/Rome")
    assert isinstance(interval, IntervalTrigger)
    assert interval.interval == timedelta(hours=2)


def test_run_returns_when_stopped(caplog: pytest.LogCaptureFixture) -> None:
    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(run(stop, make_settings()))
        await asyncio.sleep(0)
        assert not task.done()
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    with caplog.at_level(logging.INFO, logger="app.scheduler.main"):
        asyncio.run(scenario())

    messages = [record.getMessage() for record in caplog.records]
    assert any(message.startswith("scheduler started") for message in messages)
    assert "scheduler stopped" in messages
