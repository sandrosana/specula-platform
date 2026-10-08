from collections.abc import Iterator
from datetime import timedelta

import pytest
from pydantic import SecretStr

from app.collectors import registry
from app.collectors.base import Cron, Interval
from app.core.config import Settings
from tests.collectors.scripted import KeyedCollector, ScriptedCollector


@pytest.fixture
def registered() -> Iterator[None]:
    registry.register(ScriptedCollector)
    registry.register(KeyedCollector)
    yield
    registry.unregister(ScriptedCollector.name)
    registry.unregister(KeyedCollector.name)


def make_settings(
    collector_env: dict[str, str] | None = None, otx_api_key: SecretStr | None = None
) -> Settings:
    return Settings(
        environment="test",
        database_url=SecretStr("postgresql+asyncpg://u:p@h/d"),
        collector_env=collector_env or {},
        otx_api_key=otx_api_key,
    )


@pytest.mark.usefixtures("registered")
def test_register_and_lookup() -> None:
    assert registry.get_collector("test_scripted") is ScriptedCollector
    names = [cls.name for cls in registry.collectors()]
    assert {"test_keyed", "test_scripted"} <= set(names)
    assert names == sorted(names)
    registry.register(ScriptedCollector)  # registering the same class again is harmless


@pytest.mark.usefixtures("registered")
def test_duplicate_name_is_rejected() -> None:
    class Impostor(ScriptedCollector):
        pass

    with pytest.raises(ValueError, match="already registered"):
        registry.register(Impostor)


def test_unknown_collector() -> None:
    with pytest.raises(KeyError, match="unknown collector"):
        registry.get_collector("does_not_exist")


def test_discover_finds_real_collectors() -> None:
    names = {cls.name for cls in registry.discover()}

    assert "cisa_kev" in names


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("15m", timedelta(minutes=15)),
        ("2h", timedelta(hours=2)),
        ("1d", timedelta(days=1)),
        (" 6H ", timedelta(hours=6)),
    ],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert registry.parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "2", "h", "-1h", "0m", "1w", "1.5h"])
def test_parse_duration_rejects_invalid(text: str) -> None:
    with pytest.raises(ValueError):
        registry.parse_duration(text)


def test_parse_schedule() -> None:
    assert registry.parse_schedule("15 6 * * *") == Cron("15 6 * * *")
    assert registry.parse_schedule("2h") == Interval(timedelta(hours=2))


def test_resolve_defaults() -> None:
    config = registry.resolve(ScriptedCollector, make_settings())

    assert config.enabled is True
    assert config.schedule == Interval(timedelta(hours=1))
    assert config.cache_ttl == timedelta(minutes=30)
    assert config.secrets == {}


def test_resolve_environment_overrides() -> None:
    settings = make_settings(
        collector_env={
            "COLLECTOR_TEST_SCRIPTED_SCHEDULE": "0 */6 * * *",
            "COLLECTOR_TEST_SCRIPTED_CACHE_TTL": "10m",
        }
    )

    config = registry.resolve(ScriptedCollector, settings)

    assert config.schedule == Cron("0 */6 * * *")
    assert config.cache_ttl == timedelta(minutes=10)


@pytest.mark.parametrize("value", ["false", "0", "no", "OFF"])
def test_disabled_by_configuration(value: str) -> None:
    settings = make_settings(collector_env={"COLLECTOR_TEST_SCRIPTED_ENABLED": value})

    config = registry.resolve(ScriptedCollector, settings)

    assert config.enabled is False
    assert config.disabled_reason == "disabled by configuration"


def test_missing_required_key_disables_without_crashing() -> None:
    config = registry.resolve(KeyedCollector, make_settings())

    assert config.enabled is False
    assert config.disabled_reason == "missing required settings: OTX_API_KEY"


def test_required_key_present() -> None:
    config = registry.resolve(KeyedCollector, make_settings(otx_api_key=SecretStr("k")))

    assert config.enabled is True
    assert config.secrets == {"OTX_API_KEY": "k"}
