"""NVD CVE records and affected products.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

classification = postgresql.ENUM(name="classification", create_type=False)


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("source_identifier", sa.Text(), nullable=True),
        sa.Column("published", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_modified", sa.DateTime(timezone=True), nullable=False),
        sa.Column("vuln_status", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_version", sa.String(8), nullable=True),
        sa.Column("cvss_score", sa.Numeric(3, 1, asdecimal=False), nullable=True),
        sa.Column("cvss_severity", sa.String(16), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("cvss_source", sa.Text(), nullable=True),
        sa.Column("cvss_metrics", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("cwes", postgresql.ARRAY(sa.String(32)), nullable=False, server_default="{}"),
        sa.Column("references", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("classification", classification, nullable=False, server_default="sensitive"),
        sa.PrimaryKeyConstraint("cve_id", name="pk_vulnerabilities"),
    )
    op.create_index("ix_vulnerabilities_published", "vulnerabilities", ["published"])
    op.create_index("ix_vulnerabilities_last_modified", "vulnerabilities", ["last_modified"])
    op.create_index("ix_vulnerabilities_cvss_score", "vulnerabilities", ["cvss_score"])

    op.create_table(
        "vulnerability_products",
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("part", sa.String(1), nullable=True),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["vulnerabilities.cve_id"],
            name="fk_vulnerability_products_cve_id_vulnerabilities",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "cve_id", "source", "vendor", "product", name="pk_vulnerability_products"
        ),
    )
    op.create_index("ix_vulnerability_products_vendor", "vulnerability_products", ["vendor"])


def downgrade() -> None:
    op.drop_index("ix_vulnerability_products_vendor", table_name="vulnerability_products")
    op.drop_table("vulnerability_products")
    op.drop_index("ix_vulnerabilities_cvss_score", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_last_modified", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_published", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
