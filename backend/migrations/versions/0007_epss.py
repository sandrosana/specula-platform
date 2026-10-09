"""EPSS: current score per CVE and history of relevant changes.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

classification = postgresql.ENUM(name="classification", create_type=False)


def upgrade() -> None:
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("epss", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(32), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("history_epss", sa.Float(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("classification", classification, nullable=False, server_default="sensitive"),
        sa.PrimaryKeyConstraint("cve_id", name="pk_epss_scores"),
    )
    op.create_index("ix_epss_scores_epss", "epss_scores", ["epss"])

    op.create_table(
        "epss_history",
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("epss", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(16), nullable=False),
        sa.Column("classification", classification, nullable=False, server_default="sensitive"),
        sa.PrimaryKeyConstraint("cve_id", "score_date", name="pk_epss_history"),
    )
    op.create_index("ix_epss_history_score_date", "epss_history", ["score_date"])


def downgrade() -> None:
    op.drop_index("ix_epss_history_score_date", table_name="epss_history")
    op.drop_table("epss_history")
    op.drop_index("ix_epss_scores_epss", table_name="epss_scores")
    op.drop_table("epss_scores")
