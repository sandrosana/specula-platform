"""Collector framework: HTTP cache and per-source usage.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

classification = postgresql.ENUM(name="classification", create_type=False)


def upgrade() -> None:
    op.create_table(
        "http_cache",
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column("last_modified", sa.Text(), nullable=True),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("classification", classification, nullable=False, server_default="sensitive"),
        sa.PrimaryKeyConstraint("key", name="pk_http_cache"),
    )
    op.create_index("ix_http_cache_source", "http_cache", ["source"])
    op.create_index("ix_http_cache_expires_at", "http_cache", ["expires_at"])

    op.create_table(
        "source_usage",
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("source", "day", name="pk_source_usage"),
    )


def downgrade() -> None:
    op.drop_table("source_usage")
    op.drop_index("ix_http_cache_expires_at", table_name="http_cache")
    op.drop_index("ix_http_cache_source", table_name="http_cache")
    op.drop_table("http_cache")
