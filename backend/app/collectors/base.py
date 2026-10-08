"""Collector interfaces and declarative metadata (docs/architettura.md §5.1-§5.3)."""

import logging
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from pydantic import BaseModel

from app.core.classification import Classification

if TYPE_CHECKING:
    from app.collectors.http import SourceHttpClient

CollectorKind = Literal["periodic", "listener"]
CommercialUse = Literal["yes", "no", "to_verify"]
QuotaPeriod = Literal["day", "month"]

# A record as returned by the source, before normalization.
RawRecord = Mapping[str, Any]
# Incremental state saved after a successful run (must be JSON-serializable).
Cursor = dict[str, Any]

COLLECTOR_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$")
SETTING_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class CollectorDefinitionError(Exception):
    """A collector class does not declare the metadata the framework needs."""


@dataclass(frozen=True)
class Interval:
    every: timedelta

    def __post_init__(self) -> None:
        if self.every <= timedelta(0):
            raise ValueError("Interval must be positive")


@dataclass(frozen=True)
class Cron:
    """Standard 5-field cron expression, evaluated in the scheduler's time zone."""

    expression: str

    def __post_init__(self) -> None:
        if len(self.expression.split()) != 5:
            raise ValueError("Cron expression must have 5 fields")


Schedule = Interval | Cron


@dataclass(frozen=True)
class RateLimit:
    """At most `requests` requests in any window of length `per`."""

    requests: int
    per: timedelta

    def __post_init__(self) -> None:
        if self.requests <= 0 or self.per <= timedelta(0):
            raise ValueError("RateLimit needs positive requests and window")


@dataclass(frozen=True)
class Quota:
    """Declared usage quota, enforced by the HTTP client before each request."""

    limit: int
    period: QuotaPeriod

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValueError("Quota limit must be positive")


@dataclass(frozen=True)
class SourceLicense:
    """Licensing metadata, exposed in GET /sources (docs/architettura.md §6.2)."""

    kind: str
    commercial_use: CommercialUse
    terms_url: str
    quota: str | None = None
    attribution: str | None = None
    notes: str | None = None
    verified_on: date | None = None


@dataclass
class CollectorContext:
    """What a collector receives for one run."""

    http: "SourceHttpClient"
    cursor: Cursor | None
    secrets: Mapping[str, str]
    logger: logging.Logger
    full: bool = False


class CollectorBase(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    kind: ClassVar[CollectorKind]
    # A collector that does not declare its class produces sensitive data.
    classification: ClassVar[Classification] = Classification.SENSITIVE
    license: ClassVar[SourceLicense]
    rate_limit: ClassVar[RateLimit | None] = None
    quota: ClassVar[Quota | None] = None
    # Missing required settings disable the collector; they never crash the app.
    required_settings: ClassVar[tuple[str, ...]] = ()
    optional_settings: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        """Pure: raw record -> entities of the common model. No I/O."""


class PeriodicCollector(CollectorBase):
    kind: ClassVar[CollectorKind] = "periodic"
    schedule: ClassVar[Schedule]
    cache_ttl: ClassVar[timedelta]

    @abstractmethod
    def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        """Download records using only ctx.http."""

    def next_cursor(self, ctx: CollectorContext) -> Cursor | None:
        """State for the next run. Default: keep the current cursor."""
        return ctx.cursor


class ListenerCollector(CollectorBase):
    kind: ClassVar[CollectorKind] = "listener"
    flush_every: ClassVar[timedelta] = timedelta(seconds=30)
    flush_max_records: ClassVar[int] = 500

    @abstractmethod
    def listen(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        """Endless stream of records, resuming from ctx.cursor."""

    @abstractmethod
    def checkpoint(self, record: RawRecord) -> Cursor:
        """Position to resume from after `record` has been stored."""


def definition_errors(cls: type[CollectorBase]) -> list[str]:
    """Problems in a collector class definition; empty when it is valid."""
    errors: list[str] = []
    for attribute in ("name", "display_name", "license"):
        if not hasattr(cls, attribute):
            errors.append(f"missing {attribute}")
    name = getattr(cls, "name", "")
    if name and not COLLECTOR_NAME.match(name):
        errors.append(f"invalid name {name!r}")
    if not isinstance(getattr(cls, "license", None), SourceLicense) and hasattr(cls, "license"):
        errors.append("license must be a SourceLicense")
    if not isinstance(cls.classification, Classification):
        errors.append("classification must be a Classification")
    for setting in (*cls.required_settings, *cls.optional_settings):
        if not SETTING_NAME.match(setting):
            errors.append(f"invalid setting name {setting!r}")
    if issubclass(cls, PeriodicCollector):
        if not isinstance(getattr(cls, "schedule", None), Interval | Cron):
            errors.append("missing schedule")
        cache_ttl = getattr(cls, "cache_ttl", None)
        if not isinstance(cache_ttl, timedelta) or cache_ttl <= timedelta(0):
            errors.append("cache_ttl must be a positive timedelta")
    return errors


def validate_definition(cls: type[CollectorBase]) -> None:
    errors = definition_errors(cls)
    if errors:
        raise CollectorDefinitionError(f"{cls.__qualname__}: {'; '.join(errors)}")


def missing_settings(cls: type[CollectorBase], values: Mapping[str, str | None]) -> list[str]:
    """Required settings that are absent or empty in `values`."""
    return [name for name in cls.required_settings if not values.get(name)]
