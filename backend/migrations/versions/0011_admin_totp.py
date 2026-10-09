"""TOTP second factor for Admins (docs/architettura.md §10.4).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_pending_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "sessions",
        sa.Column("mfa_pending", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "user_recovery_codes",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_user_recovery_codes"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_recovery_codes_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_user_recovery_codes_user_id"),
    )
    op.create_index("ix_user_recovery_codes_user_id", "user_recovery_codes", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_user_recovery_codes_user_id", table_name="user_recovery_codes")
    op.drop_table("user_recovery_codes")
    op.drop_column("sessions", "mfa_pending")
    for column in ("totp_last_step", "totp_pending_secret", "totp_secret", "totp_enabled"):
        op.drop_column("users", column)
