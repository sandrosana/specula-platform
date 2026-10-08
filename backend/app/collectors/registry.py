"""Collector registry and per-collector configuration (docs/architettura.md §5.4, §5.5).

Collectors register with `@register`. `discover()` imports every module of the
`app.collectors` package so that their decorators run.
"""

import importlib
import pkgutil
import re
from dataclasses import dataclass
from datetime import timedelta

from app.collectors.base import (
    CollectorBase,
    Cron,
    Interval,
    PeriodicCollector,
    Schedule,
    missing_settings,
    validate_definition,
)
from app.core.config import Settings

# Framework modules: not collectors.
_FRAMEWORK_MODULES = frozenset(
    {"__main__", "base", "http", "registry", "runner", "status", "storage", "writers"}
)
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}

_registry: dict[str, type[CollectorBase]] = {}


def register[C: type[CollectorBase]](cls: C) -> C:
    """Class decorator: validate the definition and add it to the registry."""
    validate_definition(cls)
    existing = _registry.get(cls.name)
    if existing is not None and existing is not cls:
        raise ValueError(f"collector name {cls.name!r} is already registered")
    _registry[cls.name] = cls
    return cls


def unregister(name: str) -> None:
    """For tests."""
    _registry.pop(name, None)


def collectors() -> list[type[CollectorBase]]:
    return [_registry[name] for name in sorted(_registry)]


def get_collector(name: str) -> type[CollectorBase]:
    try:
        return _registry[name]
    except KeyError:
        raise KeyError(f"unknown collector {name!r}") from None


def discover() -> list[type[CollectorBase]]:
    """Import all collector modules (and subpackages) of app.collectors."""
    package = importlib.import_module("app.collectors")
    for module in pkgutil.walk_packages(package.__path__, prefix="app.collectors."):
        if module.name.removeprefix("app.collectors.") in _FRAMEWORK_MODULES:
            continue
        importlib.import_module(module.name)
    return collectors()


def parse_duration(value: str) -> timedelta:
    """'30s', '15m', '2h', '1d' -> timedelta."""
    match = _DURATION.match(value.strip().lower())
    if not match:
        raise ValueError(f"invalid duration {value!r} (use e.g. 30m, 2h, 1d)")
    amount, unit = int(match.group(1)), match.group(2)
    if amount <= 0:
        raise ValueError(f"invalid duration {value!r}: must be positive")
    return timedelta(**{_UNITS[unit]: amount})


def parse_schedule(value: str) -> Schedule:
    """A 5-field cron expression, or a duration for an interval."""
    text = value.strip()
    return Cron(text) if len(text.split()) == 5 else Interval(parse_duration(text))


@dataclass(frozen=True)
class CollectorConfig:
    """Effective configuration of one collector, after environment overrides."""

    collector: type[CollectorBase]
    enabled: bool
    disabled_reason: str | None
    schedule: Schedule | None
    cache_ttl: timedelta | None
    secrets: dict[str, str]


def resolve(cls: type[CollectorBase], settings: Settings) -> CollectorConfig:
    names = (*cls.required_settings, *cls.optional_settings)
    secrets = settings.source_secrets(names)
    reason: str | None = None

    enabled_option = settings.collector_option(cls.name, "ENABLED")
    if enabled_option is not None and enabled_option.lower() in {"false", "0", "no", "off"}:
        reason = "disabled by configuration"
    else:
        missing = missing_settings(cls, secrets)
        if missing:
            reason = f"missing required settings: {', '.join(missing)}"

    schedule: Schedule | None = None
    cache_ttl: timedelta | None = None
    if issubclass(cls, PeriodicCollector):
        schedule_option = settings.collector_option(cls.name, "SCHEDULE")
        schedule = parse_schedule(schedule_option) if schedule_option else cls.schedule
        ttl_option = settings.collector_option(cls.name, "CACHE_TTL")
        cache_ttl = parse_duration(ttl_option) if ttl_option else cls.cache_ttl

    return CollectorConfig(
        collector=cls,
        enabled=reason is None,
        disabled_reason=reason,
        schedule=schedule,
        cache_ttl=cache_ttl,
        secrets=secrets,
    )
