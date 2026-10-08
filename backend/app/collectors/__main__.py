"""Collector CLI (docs/architettura.md §5.5).

python -m app.collectors list
python -m app.collectors run <name> [--full] [--no-cache]
"""

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from app.collectors.base import PeriodicCollector
from app.collectors.http import create_http_client
from app.collectors.registry import discover, get_collector, resolve
from app.collectors.runner import CollectorRunner
from app.core.config import Settings, get_settings
from app.core.db import create_engine
from app.core.logging import configure_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.collectors")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list collectors and their configuration")
    run = commands.add_parser("run", help="run one collector now")
    run.add_argument("name")
    run.add_argument("--full", action="store_true", help="ignore the saved cursor (backfill)")
    run.add_argument("--no-cache", action="store_true", help="ignore the HTTP cache")
    return parser


def describe(settings: Settings) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for cls in discover():
        config = resolve(cls, settings)
        rows.append(
            {
                "name": cls.name,
                "kind": cls.kind,
                "enabled": config.enabled,
                "disabled_reason": config.disabled_reason,
                "schedule": repr(config.schedule) if config.schedule else None,
                "cache_ttl": str(config.cache_ttl) if config.cache_ttl else None,
                "classification": cls.classification.value,
                "commercial_use": cls.license.commercial_use,
            }
        )
    return rows


async def run_once(settings: Settings, name: str, *, full: bool, use_cache: bool) -> int:
    discover()
    cls = get_collector(name)
    if not issubclass(cls, PeriodicCollector):
        print(f"{name} is a listener and cannot be run from the CLI", file=sys.stderr)
        return 2
    engine = create_engine(settings)
    http_client = create_http_client(settings)
    try:
        runner = CollectorRunner(engine=engine, settings=settings, http_client=http_client)
        result = await runner.run(name, trigger="cli", full=full, use_cache=use_cache)
    finally:
        await http_client.aclose()
        await engine.dispose()
    print(json.dumps(result.__dict__, indent=2))
    return 0 if result.status in ("success", "disabled") else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    if args.command == "list":
        print(json.dumps(describe(settings), indent=2))
        return 0
    return asyncio.run(run_once(settings, args.name, full=args.full, use_cache=not args.no_cache))


if __name__ == "__main__":
    sys.exit(main())
