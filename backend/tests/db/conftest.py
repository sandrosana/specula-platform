import os

import pytest
from alembic import command

from tests.db.helpers import alembic_config


@pytest.fixture(scope="session")
def database_url() -> str:
    """URL of a disposable test database. In CI the database tests must run."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        if os.environ.get("CI") == "true":
            pytest.fail("TEST_DATABASE_URL must be set in CI: database tests cannot be skipped")
        pytest.skip("TEST_DATABASE_URL is not set")
    return url


@pytest.fixture
def migrated_database_url(database_url: str) -> str:
    """The test database rebuilt from scratch at the latest migration."""
    config = alembic_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    return database_url
