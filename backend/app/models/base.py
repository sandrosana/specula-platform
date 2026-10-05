"""Declarative base and shared column definitions."""

from sqlalchemy import MetaData
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.classification import DEFAULT_CLASSIFICATION, Classification

# Deterministic constraint names, so migrations can reference them.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# The PostgreSQL type is created by migration 0001; models never create it.
classification_type = postgresql.ENUM(
    Classification,
    name="classification",
    create_type=False,
    values_callable=lambda enum_class: [member.value for member in enum_class],
)


class ClassifiedMixin:
    """Adds the mandatory `classification` column (docs/architettura.md §8.1, §10.2).

    There is no Python-side default: a row inserted without an explicit
    classification gets the database default, `sensitive`.
    """

    classification: Mapped[Classification] = mapped_column(
        classification_type,
        nullable=False,
        server_default=DEFAULT_CLASSIFICATION.value,
    )
