import asyncio
import logging

import pytest

from app.scheduler.main import run


def test_run_returns_when_stopped(caplog: pytest.LogCaptureFixture) -> None:
    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(run(stop))
        await asyncio.sleep(0)
        assert not task.done()
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    with caplog.at_level(logging.INFO, logger="app.scheduler.main"):
        asyncio.run(scenario())

    messages = [record.getMessage() for record in caplog.records]
    assert "scheduler started: no collectors registered yet" in messages
    assert "scheduler stopped" in messages
