"""Helpers for tests that run against a real PostgreSQL (TEST_DATABASE_URL)."""

from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

BACKEND_DIR = Path(__file__).resolve().parents[2]

# Database tests open real connections, but only to the local test database.
DB_TEST_MARKS = [pytest.mark.enable_socket, pytest.mark.allow_hosts(["127.0.0.1"])]


def alembic_config(database_url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


async def classification_enum_labels(database_url: str) -> list[str]:
    """Labels of the PostgreSQL `classification` enum, in declaration order."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT e.enumlabel FROM pg_enum e "
                    "JOIN pg_type t ON t.oid = e.enumtypid "
                    "WHERE t.typname = 'classification' ORDER BY e.enumsortorder"
                )
            )
            return [row[0] for row in result]
    finally:
        await engine.dispose()
