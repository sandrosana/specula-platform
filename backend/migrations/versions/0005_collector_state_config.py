"""Collector state: effective configuration published by the scheduler.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _columns() -> list[sa.Column[object]]:
    return [
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column("configured", sa.Boolean(), nullable=True),
        sa.Column("schedule", sa.String(64), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_published_at", sa.DateTime(timezone=True), nullable=True),
    ]


def upgrade() -> None:
    for column in _columns():
        op.add_column("collector_state", column)


def downgrade() -> None:
    for column in reversed(_columns()):
        op.drop_column("collector_state", column.name)
