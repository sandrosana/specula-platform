"""Baseline: data classification type.

Creates the PostgreSQL enum used by the `classification` column of every
entity, sighting and event table (docs/architettura.md §8.1, §10.2).
Tables arrive in later migrations, starting with M2.

Revision ID: 0001
Revises:
Create Date: 2026-10-05
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Values must match app.core.classification.Classification (checked by tests).
    op.execute("CREATE TYPE classification AS ENUM ('public', 'internal', 'sensitive')")


def downgrade() -> None:
    op.execute("DROP TYPE classification")
