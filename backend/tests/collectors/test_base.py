from collections.abc import AsyncIterator, Iterable
from datetime import timedelta
from typing import ClassVar

import pytest
from pydantic import BaseModel

from app.collectors.base import (
    CollectorBase,
    CollectorContext,
    CollectorDefinitionError,
    Cron,
    Cursor,
    Interval,
    ListenerCollector,
    PeriodicCollector,
    Quota,
    RateLimit,
    RawRecord,
    Schedule,
    SourceLicense,
    definition_errors,
    missing_settings,
    validate_definition,
)
from app.core.classification import Classification

LICENSE = SourceLicense(kind="Test terms", commercial_use="yes", terms_url="https://example.test")


class _Feed(PeriodicCollector):
    name = "example_feed"
    display_name = "Example feed"
    license = LICENSE
    classification = Classification.PUBLIC
    schedule: ClassVar[Schedule] = Interval(timedelta(hours=1))
    cache_ttl = timedelta(minutes=30)
    required_settings: ClassVar[tuple[str, ...]] = ("EXAMPLE_API_KEY",)
    optional_settings: ClassVar[tuple[str, ...]] = ("EXAMPLE_REGION",)

    async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        yield {"id": 1}

    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        return []


class _Stream(ListenerCollector):
    name = "example.stream"
    display_name = "Example stream"
    license = LICENSE

    async def listen(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        yield {"id": 1}

    def checkpoint(self, record: RawRecord) -> Cursor:
        return {"last_id": record["id"]}

    def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
        return []


def test_valid_periodic_collector() -> None:
    assert definition_errors(_Feed) == []
    validate_definition(_Feed)
    assert _Feed.kind == "periodic"


def test_valid_listener_collector() -> None:
    assert definition_errors(_Stream) == []
    assert _Stream.kind == "listener"


def test_undeclared_classification_is_sensitive() -> None:
    assert _Stream.classification is Classification.SENSITIVE


def test_missing_metadata_is_reported() -> None:
    class Incomplete(PeriodicCollector):
        async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
            yield {}

        def normalize(self, raw: RawRecord) -> Iterable[BaseModel]:
            return []

    errors = definition_errors(Incomplete)

    assert "missing name" in errors
    assert "missing license" in errors
    assert "missing schedule" in errors
    with pytest.raises(CollectorDefinitionError, match="Incomplete"):
        validate_definition(Incomplete)


def _variant(*, name: str = "example_feed", required: tuple[str, ...] = ()) -> type[CollectorBase]:
    class Variant(_Feed):
        pass

    Variant.name = name
    Variant.required_settings = required
    return Variant


@pytest.mark.parametrize("name", ["NVD", "abuse-ch", "a.b.c", "1source"])
def test_invalid_names(name: str) -> None:
    assert f"invalid name {name!r}" in definition_errors(_variant(name=name))


def test_invalid_setting_name() -> None:
    errors = definition_errors(_variant(required=("api_key",)))

    assert "invalid setting name 'api_key'" in errors


def test_missing_settings() -> None:
    assert missing_settings(_Feed, {}) == ["EXAMPLE_API_KEY"]
    assert missing_settings(_Feed, {"EXAMPLE_API_KEY": ""}) == ["EXAMPLE_API_KEY"]
    assert missing_settings(_Feed, {"EXAMPLE_API_KEY": "x"}) == []


def test_value_objects_reject_invalid_values() -> None:
    with pytest.raises(ValueError):
        Interval(timedelta(0))
    with pytest.raises(ValueError):
        Cron("0 6 * *")
    with pytest.raises(ValueError):
        RateLimit(requests=0, per=timedelta(seconds=30))
    with pytest.raises(ValueError):
        Quota(limit=0, period="day")
    assert Cron("15 6 * * *").expression == "15 6 * * *"
