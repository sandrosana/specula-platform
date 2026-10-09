"""Application settings.

All configuration comes from environment variables (see `.env.example`).
This is the only module allowed to read the environment.
"""

import os
from collections.abc import Iterable
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

DATABASE_URL_SCHEME = "postgresql+asyncpg://"
COLLECTOR_ENV_PREFIX = "COLLECTOR_"


def _collector_environment() -> dict[str, str]:
    """COLLECTOR_<NAME>_<OPTION> overrides (docs/architettura.md §5.4, §5.5)."""
    return {key: value for key, value in os.environ.items() if key.startswith(COLLECTOR_ENV_PREFIX)}


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

    # Time zone of the collector schedules.
    scheduler_timezone: str = "Europe/Rome"

    # EPSS score from which a CVE is "likely to be exploited" (priority level P3,
    # docs/specifica §6) and whose crossing is kept in the EPSS history.
    epss_threshold: float = Field(default=0.5, gt=0, lt=1)

    # Source API keys: only the scheduler container receives them.
    nvd_api_key: SecretStr | None = None
    ransomware_live_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    maxmind_license_key: SecretStr | None = None

    collector_env: dict[str, str] = Field(default_factory=_collector_environment)

    @field_validator(
        "https_proxy",
        "nvd_api_key",
        "ransomware_live_api_key",
        "abusech_auth_key",
        "otx_api_key",
        "maxmind_license_key",
        mode="before",
    )
    @classmethod
    def _empty_means_unset(cls, value: object) -> object:
        # `.env.example` lists optional variables with empty values (e.g. HTTPS_PROXY=).
        return None if isinstance(value, str) and not value.strip() else value

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

    def source_secrets(self, names: Iterable[str]) -> dict[str, str]:
        """Non-empty values of the requested source settings (e.g. "OTX_API_KEY")."""
        secrets: dict[str, str] = {}
        for name in names:
            value = getattr(self, name.lower(), None)
            if isinstance(value, SecretStr) and value.get_secret_value():
                secrets[name] = value.get_secret_value()
            elif isinstance(value, str) and value:
                secrets[name] = value
        return secrets

    def collector_option(self, collector: str, option: str) -> str | None:
        """Value of COLLECTOR_<NAME>_<OPTION>; "abusech.threatfox" -> ABUSECH_THREATFOX."""
        key = f"{COLLECTOR_ENV_PREFIX}{collector.replace('.', '_').upper()}_{option.upper()}"
        value = self.collector_env.get(key, "").strip()
        return value or None


@lru_cache
def get_settings() -> Settings:
    """Settings loaded once from the environment."""
    return Settings()
