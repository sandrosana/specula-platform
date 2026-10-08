"""CISA KEV catalog entries.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

classification = postgresql.ENUM(name="classification", create_type=False)


def upgrade() -> None:
    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("vendor_project", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("vulnerability_name", sa.Text(), nullable=False),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("short_description", sa.Text(), nullable=False),
        sa.Column("required_action", sa.Text(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware_campaign_use", sa.String(16), nullable=True),
        sa.Column("forensic_triage", sa.Boolean(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("cwes", postgresql.ARRAY(sa.String(32)), nullable=False, server_default="{}"),
        sa.Column("catalog_version", sa.String(32), nullable=False),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("classification", classification, nullable=False, server_default="sensitive"),
        sa.PrimaryKeyConstraint("cve_id", name="pk_kev_entries"),
    )
    op.create_index("ix_kev_entries_date_added", "kev_entries", ["date_added"])


def downgrade() -> None:
    op.drop_index("ix_kev_entries_date_added", table_name="kev_entries")
    op.drop_table("kev_entries")
