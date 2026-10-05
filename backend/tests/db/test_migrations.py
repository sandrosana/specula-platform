import asyncio

import pytest
from alembic import command

from app.core.classification import Classification
from tests.db.helpers import DB_TEST_MARKS, alembic_config, classification_enum_labels

pytestmark = DB_TEST_MARKS


def test_upgrade_and_downgrade_roundtrip(database_url: str) -> None:
    config = alembic_config(database_url)

    command.downgrade(config, "base")
    command.upgrade(config, "head")
    labels = asyncio.run(classification_enum_labels(database_url))
    assert labels == [member.value for member in Classification]

    command.downgrade(config, "base")
    assert asyncio.run(classification_enum_labels(database_url)) == []

    command.upgrade(config, "head")


@pytest.mark.usefixtures("migrated_database_url")
def test_upgrade_is_idempotent(database_url: str) -> None:
    command.upgrade(alembic_config(database_url), "head")

    labels = asyncio.run(classification_enum_labels(database_url))
    assert labels == [member.value for member in Classification]
