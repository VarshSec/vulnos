"""Align scope_rules with canonical DATABASE_DESIGN.md and identity model.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-02 04:00:00.000000+00:00

Reconciles the scope_rules table from draft baseline columns
to the canonical schema:
- Drops draft columns (asset_type, pattern, conditions, description)
- Drops draft check constraint ck_scope_rules_asset_type
- Adds canonical columns (match_type, value, ports, protocols, note)
- Adds check constraint ck_scope_rules_match_type
- Adds index ix_scope_rules_version_effect on (scope_version_id, effect)
- Preserves PostgreSQL Row-Level Security (RLS) policies and existing foreign keys.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # 1. Drop old draft check constraint
    op.drop_constraint("ck_scope_rules_asset_type", "scope_rules", type_="check")

    # 2. Drop old draft columns
    op.drop_column("scope_rules", "asset_type")
    op.drop_column("scope_rules", "pattern")
    op.drop_column("scope_rules", "conditions")
    op.drop_column("scope_rules", "description")

    # 3. Add canonical columns
    op.add_column(
        "scope_rules",
        sa.Column("match_type", sa.Text(), nullable=False, server_default="exact_host"),
    )
    op.add_column(
        "scope_rules",
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scope_rules",
        sa.Column("ports", postgresql.INT4RANGE(), nullable=True),
    )
    op.add_column(
        "scope_rules",
        sa.Column("protocols", postgresql.ARRAY(sa.Text()), nullable=True),
    )
    op.add_column(
        "scope_rules",
        sa.Column("note", sa.Text(), nullable=True),
    )

    # 4. Add canonical check constraint
    op.create_check_constraint(
        "ck_scope_rules_match_type",
        "scope_rules",
        "match_type IN ('exact_url', 'url_prefix', 'exact_host', 'domain_suffix', 'wildcard_domain', 'ip', 'cidr')",
    )

    # 5. Create index on (scope_version_id, effect)
    op.create_index(
        "ix_scope_rules_version_effect",
        "scope_rules",
        ["scope_version_id", "effect"],
    )


def downgrade() -> None:
    # 1. Drop index and canonical constraint
    op.drop_index("ix_scope_rules_version_effect", table_name="scope_rules")
    op.drop_constraint("ck_scope_rules_match_type", "scope_rules", type_="check")

    # 2. Drop canonical columns
    op.drop_column("scope_rules", "note")
    op.drop_column("scope_rules", "protocols")
    op.drop_column("scope_rules", "ports")
    op.drop_column("scope_rules", "value")
    op.drop_column("scope_rules", "match_type")

    # 3. Re-add old draft columns
    op.add_column("scope_rules", sa.Column("description", sa.Text(), nullable=True))
    op.add_column(
        "scope_rules",
        sa.Column("conditions", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "scope_rules",
        sa.Column("pattern", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scope_rules",
        sa.Column("asset_type", sa.String(50), nullable=False, server_default="host"),
    )

    # 4. Re-add old check constraint
    op.create_check_constraint(
        "ck_scope_rules_asset_type",
        "scope_rules",
        "asset_type IN ('domain','host','ip_range','url_path','port','technology','wildcard')",
    )
