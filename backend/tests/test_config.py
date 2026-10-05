import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

# Test value, not a real credential.
SECRET_PASSWORD = "do-not-leak-me"
SECRET_ASYNCPG_URL = f"postgresql+asyncpg://specula:{SECRET_PASSWORD}@db/specula"


def test_defaults() -> None:
    settings = Settings()

    assert settings.app_name == "Specula Threat"
    assert settings.api_prefix == "/api/v1"


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LOG_LEVEL", "debug")

    settings = get_settings()

    assert settings.environment == "production"
    assert settings.log_level == "DEBUG"


def test_invalid_value_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")

    with pytest.raises(ValidationError):
        Settings()


def test_unknown_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_UNRELATED_VARIABLE", "x")

    Settings()


def test_settings_are_immutable() -> None:
    settings = Settings()

    with pytest.raises(ValidationError):
        settings.environment = "production"  # type: ignore[misc]


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL")

    with pytest.raises(ValidationError, match="database_url"):
        Settings()


def test_database_url_must_use_asyncpg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"postgresql://specula:{SECRET_PASSWORD}@db/specula")

    with pytest.raises(ValidationError) as error:
        Settings()

    assert "postgresql+asyncpg://" in str(error.value)
    assert SECRET_PASSWORD not in str(error.value)


def test_database_url_is_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SECRET_ASYNCPG_URL)

    settings = Settings()

    assert SECRET_PASSWORD not in repr(settings)
    assert SECRET_PASSWORD not in str(settings.model_dump())
