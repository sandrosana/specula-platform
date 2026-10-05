"""Application settings.

All configuration comes from environment variables (see `.env.example`).
This is the only module allowed to read the environment.
"""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Validated settings. Invalid values stop the application at startup."""

    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    app_name: str = "Specula Threat"
    environment: Environment = "development"
    log_level: LogLevel = "INFO"
    api_prefix: str = "/api/v1"

    @field_validator("log_level", mode="before")
    @classmethod
    def _uppercase_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


@lru_cache
def get_settings() -> Settings:
    """Settings loaded once from the environment."""
    return Settings()
