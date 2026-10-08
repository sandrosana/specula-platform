from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import create_app

# A syntactically valid URL that is never reachable in unit tests: sockets are disabled.
UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://specula:unit-test@127.0.0.1:1/specula"


@pytest.fixture(autouse=True)
def _test_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test reads a known environment and a fresh settings cache."""
    monkeypatch.setenv("DATABASE_URL", UNREACHABLE_DATABASE_URL)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def anyio_backend() -> str:
    """Async tests (@pytest.mark.anyio) run on asyncio."""
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", log_level="WARNING")


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
