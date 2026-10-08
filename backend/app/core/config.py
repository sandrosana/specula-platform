"""Application settings.

All configuration comes from environment variables (see `.env.example`).
This is the only module allowed to read the environment.
"""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

DATABASE_URL_SCHEME = "postgresql+asyncpg://"


class Settings(BaseSettings):
    """Validated settings. Invalid values stop the application at startup."""

    # hide_input_in_errors: validation errors must never echo secrets (e.g. the DB password).
    model_config = SettingsConfigDict(extra="ignore", frozen=True, hide_input_in_errors=True)

    app_name: str = "Specula Threat"
    environment: Environment = "development"
    log_level: LogLevel = "INFO"
    api_prefix: str = "/api/v1"

    database_url: SecretStr

    # Outbound proxy for collectors; empty in the current LAB (no proxy).
    https_proxy: str | None = None

    @field_validator("log_level", mode="before")
    @classmethod
    def _uppercase_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg_scheme(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(DATABASE_URL_SCHEME):
            raise ValueError(f"DATABASE_URL must start with {DATABASE_URL_SCHEME}")
        return value


@lru_cache
def get_settings() -> Settings:
    """Settings loaded once from the environment."""
    return Settings()
