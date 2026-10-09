"""Post-processing CLI.

python -m app.processing priorities   # recompute every CVE priority level
"""

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_session_factory
from app.core.logging import configure_logging
from app.processing.priority import recompute_all_priorities


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.processing")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "priorities",
        help="recompute every CVE priority level (backfill, or after changing EPSS_THRESHOLD)",
    )
    return parser


async def recompute(settings: Settings) -> int:
    engine = create_engine(settings)
    try:
        return await recompute_all_priorities(
            create_session_factory(engine), settings.epss_threshold
        )
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    changed = asyncio.run(recompute(settings))
    print(json.dumps({"changed": changed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
