from datetime import UTC, datetime, timedelta

import pytest

from app.collectors.base import Cron, Interval
from app.collectors.status import (
    describe_duration,
    describe_schedule,
    expected_period,
    source_status,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def test_describe_schedule() -> None:
    assert describe_schedule(Interval(timedelta(hours=6))) == "every 6h"
    assert describe_schedule(Interval(timedelta(minutes=90))) == "every 90m"
    assert describe_schedule(Interval(timedelta(days=1))) == "every 1d"
    assert describe_schedule(Cron("15 6 * * *")) == "cron 15 6 * * *"
    assert describe_schedule(None) is None
    assert describe_duration(timedelta(seconds=45)) == "45s"


def test_expected_period() -> None:
    assert expected_period(Interval(timedelta(hours=6))) == timedelta(hours=6)
    assert expected_period(Cron("15 6 * * *")) == timedelta(days=1)
    assert expected_period(None) is None


@pytest.mark.parametrize(
    ("enabled", "last_status", "last_success_hours_ago", "expected"),
    [
        (None, None, None, "unknown"),
        (False, "success", 1, "disabled"),
        (True, "failed", 1, "error"),
        (True, "quota_exceeded", 1, "error"),
        (True, None, None, "pending"),
        (True, "success", 1, "ok"),
        (True, "success", 11, "ok"),
        (True, "success", 13, "late"),
        (True, "skipped_locked", 1, "ok"),
    ],
)
def test_source_status(
    enabled: bool | None,
    last_status: str | None,
    last_success_hours_ago: int | None,
    expected: str,
) -> None:
    last_success = (
        NOW - timedelta(hours=last_success_hours_ago)
        if last_success_hours_ago is not None
        else None
    )

    status = source_status(
        enabled=enabled,
        last_status=last_status,
        last_success_at=last_success,
        period=timedelta(hours=6),
        now=NOW,
    )

    assert status == expected
