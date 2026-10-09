"""CVE priority level and reason (derived columns).

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("priority_level", sa.String(2), nullable=True))
    op.add_column(
        "vulnerabilities", sa.Column("priority_reason", postgresql.JSONB(), nullable=True)
    )
    op.create_index("ix_vulnerabilities_priority_level", "vulnerabilities", ["priority_level"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_priority_level", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "priority_reason")
    op.drop_column("vulnerabilities", "priority_level")
