"""Align authorization_records with canonical DATABASE_DESIGN.md and identity model.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-02 03:15:00.000000+00:00

Reconciles the authorization_records table from draft baseline columns
to the canonical schema:
- Replaces draft columns (authorization_type, granted_by, status, scope_summary, restrictions, reviewed_by, reviewed_at, updated_at)
- Adds canonical columns (reference, authorized_by_name, authorized_by_contact, allowed_actions, destructive_allowed, allow_private_ranges, max_requests_per_scan, notes, revoked_at)
- Renames valid_until to valid_to
- Replaces check constraint ck_authorization_records_validity_range with ck_authorization_records_validity_window
- Adds ix_authorization_records_project_id
- Preserves PostgreSQL Row-Level Security (RLS) policies and existing foreign keys.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # 1. Drop old check constraints
    op.drop_constraint(
        "ck_authorization_records_authorization_type", "authorization_records", type_="check"
    )
    op.drop_constraint("ck_authorization_records_status", "authorization_records", type_="check")
    op.drop_constraint(
        "ck_authorization_records_validity_range", "authorization_records", type_="check"
    )

    # 2. Drop old draft columns
    op.drop_column("authorization_records", "authorization_type")
    op.drop_column("authorization_records", "granted_by")
    op.drop_column("authorization_records", "status")
    op.drop_column("authorization_records", "scope_summary")
    op.drop_column("authorization_records", "restrictions")
    op.drop_column("authorization_records", "reviewed_by")
    op.drop_column("authorization_records", "reviewed_at")
    op.drop_column("authorization_records", "updated_at")

    # 3. Rename valid_until to valid_to
    op.alter_column("authorization_records", "valid_until", new_column_name="valid_to")

    # 4. Add canonical columns
    op.add_column(
        "authorization_records",
        sa.Column("reference", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "authorization_records",
        sa.Column("authorized_by_name", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "authorization_records",
        sa.Column("authorized_by_contact", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "authorization_records",
        sa.Column(
            "allowed_actions", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"
        ),
    )
    op.add_column(
        "authorization_records",
        sa.Column(
            "destructive_allowed", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "authorization_records",
        sa.Column(
            "allow_private_ranges", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "authorization_records", sa.Column("max_requests_per_scan", sa.BigInteger(), nullable=True)
    )
    op.add_column("authorization_records", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column(
        "authorization_records", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True)
    )

    # 5. Add canonical check constraint
    op.create_check_constraint(
        "ck_authorization_records_validity_window",
        "authorization_records",
        "valid_to > valid_from",
    )

    # 6. Index on project_id
    op.create_index("ix_authorization_records_project_id", "authorization_records", ["project_id"])


def downgrade() -> None:
    # 1. Drop index & canonical constraint
    op.drop_index("ix_authorization_records_project_id", table_name="authorization_records")
    op.drop_constraint(
        "ck_authorization_records_validity_window", "authorization_records", type_="check"
    )

    # 2. Drop canonical columns
    op.drop_column("authorization_records", "revoked_at")
    op.drop_column("authorization_records", "notes")
    op.drop_column("authorization_records", "max_requests_per_scan")
    op.drop_column("authorization_records", "allow_private_ranges")
    op.drop_column("authorization_records", "destructive_allowed")
    op.drop_column("authorization_records", "allowed_actions")
    op.drop_column("authorization_records", "authorized_by_contact")
    op.drop_column("authorization_records", "authorized_by_name")
    op.drop_column("authorization_records", "reference")

    # 3. Rename valid_to back to valid_until
    op.alter_column("authorization_records", "valid_to", new_column_name="valid_until")

    # 4. Re-add old draft columns
    op.add_column(
        "authorization_records",
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.add_column(
        "authorization_records", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "authorization_records",
        sa.Column(
            "reviewed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "authorization_records",
        sa.Column("restrictions", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "authorization_records",
        sa.Column("scope_summary", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "authorization_records",
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
    )
    op.add_column(
        "authorization_records",
        sa.Column("granted_by", sa.String(200), nullable=False, server_default=""),
    )
    op.add_column(
        "authorization_records",
        sa.Column(
            "authorization_type", sa.String(50), nullable=False, server_default="pentest_contract"
        ),
    )

    # 5. Re-add old check constraints
    op.create_check_constraint(
        "ck_authorization_records_authorization_type",
        "authorization_records",
        "authorization_type IN ('bug_bounty','pentest_contract','self_owned','ctf','training','research')",
    )
    op.create_check_constraint(
        "ck_authorization_records_status",
        "authorization_records",
        "status IN ('pending','active','expired','revoked')",
    )
    op.create_check_constraint(
        "ck_authorization_records_validity_range",
        "authorization_records",
        "valid_until > valid_from",
    )
