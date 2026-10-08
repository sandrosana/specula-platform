from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from app.collectors import registry
from app.collectors.__main__ import build_parser, describe
from app.core.config import Settings
from tests.collectors.scripted import KeyedCollector, ScriptedCollector


@pytest.fixture
def registered() -> Iterator[None]:
    registry.register(ScriptedCollector)
    registry.register(KeyedCollector)
    yield
    registry.unregister(ScriptedCollector.name)
    registry.unregister(KeyedCollector.name)


def test_parser() -> None:
    parser = build_parser()

    run = parser.parse_args(["run", "cisa_kev", "--full", "--no-cache"])
    assert (run.command, run.name, run.full, run.no_cache) == ("run", "cisa_kev", True, True)
    assert parser.parse_args(["list"]).command == "list"
    with pytest.raises(SystemExit):
        parser.parse_args([])


@pytest.mark.usefixtures("registered")
def test_describe_shows_configuration_without_secrets() -> None:
    settings = Settings(
        environment="test",
        database_url=SecretStr("postgresql+asyncpg://u:p@h/d"),
        otx_api_key=SecretStr("super-secret-key"),
        collector_env={},
    )

    rows = {row["name"]: row for row in describe(settings)}

    assert rows["test_scripted"]["enabled"] is True
    assert rows["test_scripted"]["classification"] == "public"
    assert rows["test_keyed"]["enabled"] is True
    assert "super-secret-key" not in repr(rows)
