"""The `classification` column: database default and allowed values."""

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.classification import Classification
from app.models import ClassifiedMixin
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS


class _ProbeBase(DeclarativeBase):
    """Separate metadata, so the probe table never appears in app migrations."""


class _Probe(ClassifiedMixin, _ProbeBase):
    __tablename__ = "classification_probe"

    id: Mapped[int] = mapped_column(primary_key=True)


async def _store_and_read(database_url: str, classification: Classification | None) -> object:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_ProbeBase.metadata.create_all)
        async with AsyncSession(engine) as session:
            probe = _Probe(id=1)
            if classification is not None:
                probe.classification = classification
            session.add(probe)
            await session.commit()
            return await session.scalar(select(_Probe.classification).where(_Probe.id == 1))
    finally:
        async with engine.begin() as connection:
            await connection.run_sync(_ProbeBase.metadata.drop_all)
        await engine.dispose()


async def _insert_raw_value(database_url: str, value: str) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_ProbeBase.metadata.create_all)
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO classification_probe (id, classification) VALUES (1, :value)"),
                {"value": value},
            )
    finally:
        async with engine.begin() as connection:
            await connection.run_sync(_ProbeBase.metadata.drop_all)
        await engine.dispose()


def test_row_without_classification_is_sensitive(migrated_database_url: str) -> None:
    stored = asyncio.run(_store_and_read(migrated_database_url, None))

    assert stored is Classification.SENSITIVE


def test_explicit_classification_is_kept(migrated_database_url: str) -> None:
    stored = asyncio.run(_store_and_read(migrated_database_url, Classification.PUBLIC))

    assert stored is Classification.PUBLIC


def test_unknown_classification_is_rejected(migrated_database_url: str) -> None:
    with pytest.raises(DBAPIError):
        asyncio.run(_insert_raw_value(migrated_database_url, "secret"))
