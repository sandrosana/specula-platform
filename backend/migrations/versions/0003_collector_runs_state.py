"""Collector framework: run history and per-collector state.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "collector_runs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("collector", sa.String(64), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("full", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_read", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_inserted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_collector_runs"),
    )
    op.create_index("ix_collector_runs_collector", "collector_runs", ["collector"])

    op.create_table(
        "collector_state",
        sa.Column("collector", sa.String(64), nullable=False),
        sa.Column("cursor", postgresql.JSONB(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("collector", name="pk_collector_state"),
    )


def downgrade() -> None:
    op.drop_table("collector_state")
    op.drop_index("ix_collector_runs_collector", table_name="collector_runs")
    op.drop_table("collector_runs")
