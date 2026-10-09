"""Stored sort key of the CVE priority list, with its index.

Existing rows get the defaults (an unknown P4) until
`python -m app.processing priorities` recomputes them.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Constant defaults: PostgreSQL adds these columns without rewriting the table.
    op.add_column(
        "vulnerabilities",
        sa.Column("priority_rank", sa.SmallInteger(), nullable=False, server_default="1"),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("priority_kev_date", sa.Date(), nullable=False, server_default="0001-01-01"),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("priority_sort_first", sa.Float(), nullable=False, server_default="-1"),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("priority_sort_second", sa.Float(), nullable=False, server_default="-1"),
    )
    op.create_index(
        "ix_vulnerabilities_priority_sort",
        "vulnerabilities",
        [
            "priority_rank",
            "priority_kev_date",
            "priority_sort_first",
            "priority_sort_second",
            "cve_id",
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_priority_sort", table_name="vulnerabilities")
    for column in (
        "priority_sort_second",
        "priority_sort_first",
        "priority_kev_date",
        "priority_rank",
    ):
        op.drop_column("vulnerabilities", column)
