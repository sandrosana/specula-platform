"""Scheduler entrypoint. Run with: python -m app.scheduler"""

import asyncio
import logging
import signal

from app.core.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


async def run(stop: asyncio.Event) -> None:
    """Run until `stop` is set. Collectors are registered here from M2 on."""
    logger.info("scheduler started: no collectors registered yet")
    await stop.wait()
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
