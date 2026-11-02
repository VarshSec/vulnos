"""Phase 2 baseline schema — all 50 tables.

Revision ID: 0001
Revises: None
Create Date: 2026-11-02 00:00:00.000000+00:00

This migration creates every table documented in DATABASE_DESIGN.md for Phase 2:
  Identity/Auth: users, api_keys, projects, project_members, authorization_records,
                 scope_versions, scope_rules, scope_decisions, targets
  Assets:        assets, domains, hosts, host_addresses, services, endpoints,
                 parameters, technologies, asset_technologies, api_schemas,
                 asset_discoveries
  Execution:     tools, tool_versions, tool_capabilities, scans, scan_stage_runs,
                 tool_executions, tool_selection_decisions, agent_runs, test_cases,
                 operation_approvals
  Security:      auth_contexts, secret_refs
  Evidence:      evidence_objects, http_exchanges (partitioned)
  Findings:      finding_clusters, findings, finding_evidence, cluster_relations
  Validation:    validations, validation_checks, finding_state_transitions, reports
  AI:            ai_providers, ai_models, prompt_templates, ai_routing_policies,
                 ai_invocations
  Audit:         audit_logs (partitioned), outbox_events, cost_entries
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ─── Identity & Authorization ───────────────────────────────────────

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("mfa_secret_enc", sa.Text(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "owner_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("default_retention_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("char_length(name) BETWEEN 1 AND 200", name="ck_projects_name_length"),
        sa.CheckConstraint("slug ~ '^[a-z0-9-]{3,80}$'", name="ck_projects_slug_format"),
        sa.CheckConstraint("status IN ('active','archived')", name="ck_projects_status"),
        sa.CheckConstraint(
            "default_retention_days BETWEEN 1 AND 3650", name="ck_projects_retention_days_range"
        ),
        sa.UniqueConstraint("slug", name="uq_projects_slug"),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])

    op.create_table(
        "project_members",
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column(
            "invited_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("project_id", "user_id", name="pk_project_members"),
        sa.CheckConstraint(
            "role IN ('owner','admin','member','viewer')", name="ck_project_members_role"
        ),
    )
    op.create_index("ix_project_members_user_id", "project_members", ["user_id"])

    op.create_table(
        "authorization_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("authorization_type", sa.String(50), nullable=False),
        sa.Column("granted_by", sa.String(200), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("document_evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_summary", sa.Text(), nullable=False),
        sa.Column("restrictions", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "reviewed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "authorization_type IN ('bug_bounty','pentest_contract','self_owned','ctf','training','research')",
            name="ck_authorization_records_authorization_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending','active','expired','revoked')",
            name="ck_authorization_records_status",
        ),
        sa.CheckConstraint(
            "valid_until > valid_from", name="ck_authorization_records_validity_range"
        ),
    )

    op.create_table(
        "scope_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "authorization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("authorization_records.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("content_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("version > 0", name="ck_scope_versions_version_positive"),
        sa.CheckConstraint(
            "status IN ('draft','active','superseded')", name="ck_scope_versions_status"
        ),
        sa.UniqueConstraint("project_id", "version", name="uq_scope_versions_project_version"),
    )
    op.create_index(
        "uq_scope_versions_active",
        "scope_versions",
        ["project_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "scope_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scope_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scope_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("conditions", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("effect IN ('allow','deny')", name="ck_scope_rules_effect"),
        sa.CheckConstraint(
            "asset_type IN ('domain','host','ip_range','url_path','port','technology','wildcard')",
            name="ck_scope_rules_asset_type",
        ),
        sa.UniqueConstraint("scope_version_id", "priority", name="uq_scope_rules_version_priority"),
    )
    op.create_index("ix_scope_rules_version_effect", "scope_rules", ["scope_version_id", "effect"])

    # scope_decisions — partitioned by RANGE on decided_at
    op.execute("""
        CREATE TABLE scope_decisions (
            id bigint GENERATED ALWAYS AS IDENTITY,
            decided_at timestamptz NOT NULL,
            project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            scan_id uuid,
            asset_type text NOT NULL,
            asset_identifier text NOT NULL,
            matched_rule_id uuid,
            allowed boolean NOT NULL,
            reason_code text NOT NULL,
            reason_detail text,
            scope_version_id uuid NOT NULL,
            PRIMARY KEY (id, decided_at)
        ) PARTITION BY RANGE (decided_at)
    """)
    op.execute("""
        CREATE TABLE scope_decisions_default PARTITION OF scope_decisions DEFAULT
    """)
    op.create_index(
        "ix_scope_decisions_project_decided",
        "scope_decisions",
        ["project_id", sa.text("decided_at DESC")],
    )
    op.create_index("ix_scope_decisions_scan_id", "scope_decisions", ["scan_id"])

    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seed_type", sa.String(30), nullable=False),
        sa.Column("seed_value", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "authorization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("authorization_records.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "added_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "seed_type IN ('domain','host','ip','cidr','url','api_spec')",
            name="ck_targets_seed_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending','validated','rejected','expired')", name="ck_targets_status"
        ),
        sa.UniqueConstraint(
            "project_id", "seed_type", "seed_value", name="uq_targets_project_seed"
        ),
    )
    op.create_index("ix_targets_project_status", "targets", ["project_id", "status"])

    # ─── Assets & Attack Surface ────────────────────────────────────────

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "kind IN ('domain','host','service','endpoint','parameter','technology','api_schema')",
            name="ck_assets_kind",
        ),
        sa.UniqueConstraint(
            "project_id", "kind", "canonical_key", name="uq_assets_project_kind_canonical"
        ),
    )
    op.create_index(
        "ix_assets_project_last_seen", "assets", ["project_id", sa.text("last_seen_at DESC")]
    )

    op.create_table(
        "domains",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("registrable_domain", sa.Text(), nullable=True),
        sa.Column("parent_domain", sa.Text(), nullable=True),
        sa.UniqueConstraint("project_id", "name", name="uq_domains_project_name"),
    )

    op.create_table(
        "hosts",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("canonical_name", sa.Text(), nullable=False),
        sa.Column("host_kind", sa.String(20), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("host_kind IN ('hostname','ip')", name="ck_hosts_host_kind"),
        sa.UniqueConstraint("project_id", "canonical_name", name="uq_hosts_project_canonical_name"),
    )

    op.create_table(
        "host_addresses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("last_tool_execution_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.UniqueConstraint("host_id", "ip", name="uq_host_addresses_host_ip"),
    )

    op.create_table(
        "services",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("transport", sa.String(10), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="open"),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("tls", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_services_port_range"),
        sa.CheckConstraint("transport IN ('tcp','udp')", name="ck_services_transport"),
        sa.CheckConstraint(
            "state IN ('open','filtered','closed','unknown')", name="ck_services_state"
        ),
        sa.UniqueConstraint("host_id", "port", "transport", name="uq_services_host_port_transport"),
    )

    op.create_table(
        "endpoints",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.asset_id"),
            nullable=False,
        ),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.asset_id"),
            nullable=True,
        ),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("scheme", sa.String(10), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("query_template", sa.Text(), nullable=True),
        sa.Column("path_template", sa.Text(), nullable=True),
        sa.Column("normalized_url", sa.Text(), nullable=False),
        sa.Column("url_hash", sa.LargeBinary(), nullable=False),
        sa.Column("auth_required", sa.Boolean(), nullable=True),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT')",
            name="ck_endpoints_method",
        ),
        sa.CheckConstraint("scheme IN ('http','https')", name="ck_endpoints_scheme"),
        sa.UniqueConstraint(
            "project_id", "method", "url_hash", name="uq_endpoints_project_method_url_hash"
        ),
    )
    op.create_index("ix_endpoints_project_host", "endpoints", ["project_id", "host_id"])

    op.create_table(
        "parameters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("location", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("data_type", sa.String(50), nullable=True),
        sa.Column("sample_redacted", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "location IN ('query','path','header','cookie','body_json','body_form','graphql_arg')",
            name="ck_parameters_location",
        ),
        sa.UniqueConstraint(
            "endpoint_id", "location", "name", name="uq_parameters_endpoint_location_name"
        ),
    )

    op.create_table(
        "technologies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("vendor", sa.String(200), nullable=True),
        sa.Column("cpe", sa.String(500), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("name", "category", name="uq_technologies_name_category"),
    )

    op.create_table(
        "asset_technologies",
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "technology_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("technologies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.String(50), nullable=True),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False, server_default="1.000"),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("asset_id", "technology_id", name="pk_asset_technologies"),
    )

    op.create_table(
        "api_schemas",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("schema_type", sa.String(20), nullable=False),
        sa.Column("version_label", sa.String(50), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("spec_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("spec_hash", sa.LargeBinary(), nullable=False),
        sa.Column("operation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "schema_type IN ('openapi','graphql','postman','har')",
            name="ck_api_schemas_schema_type",
        ),
        sa.UniqueConstraint(
            "project_id",
            "asset_id",
            "schema_type",
            "spec_hash",
            name="uq_api_schemas_project_asset_type_hash",
        ),
    )

    # ─── Security Contexts ──────────────────────────────────────────────

    op.create_table(
        "secret_refs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("backend", sa.String(50), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "backend IN ('env','file','vault','aws_secrets_manager','gcp_secret_manager')",
            name="ck_secret_refs_backend",
        ),
        sa.UniqueConstraint("project_id", "name", name="uq_secret_refs_project_name"),
    )

    op.create_table(
        "auth_contexts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("identity_type", sa.String(50), nullable=False),
        sa.Column(
            "secret_ref_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("secret_refs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "identity_type IN ('anonymous','user','admin','service')",
            name="ck_auth_contexts_identity_type",
        ),
        sa.UniqueConstraint("project_id", "label", name="uq_auth_contexts_project_label"),
    )

    # ─── Tools, Scans & Execution ───────────────────────────────────────

    op.create_table(
        "tools",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("vendor", sa.String(200), nullable=True),
        sa.Column("upstream_url", sa.Text(), nullable=True),
        sa.Column("license", sa.String(100), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("maintenance_status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("default_image", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "maintenance_status IN ('active','maintenance','stale','unknown','abandoned')",
            name="ck_tools_maintenance_status",
        ),
        sa.UniqueConstraint("name", name="uq_tools_name"),
    )

    op.create_table(
        "tool_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.String(100), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_status", sa.String(30), nullable=False, server_default="declared"),
        sa.Column("capabilities_hash", sa.LargeBinary(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "verification_status IN ('declared','smoke_tested','contract_tested','production_verified','quarantined')",
            name="ck_tool_versions_verification_status",
        ),
        sa.UniqueConstraint(
            "tool_id", "version", "image_digest", name="uq_tool_versions_tool_version_digest"
        ),
    )

    op.create_table(
        "tool_capabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_versions.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "vulnerability_classes",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "target_types", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column(
            "required_inputs", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column(
            "install_requirements",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("input_schema", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "output_formats", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column("auth_support", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("passive", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("state_changing", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("destructive", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("cost_tier", sa.String(10), nullable=False),
        sa.Column("expected_duration_seconds", sa.Integer(), nullable=True),
        sa.Column("overlap_group", sa.String(100), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint("passive OR active", name="ck_tool_capabilities_passive_or_active"),
        sa.CheckConstraint(
            "NOT destructive OR requires_approval", name="ck_tool_capabilities_destructive_approval"
        ),
        sa.CheckConstraint(
            "cost_tier IN ('low','medium','high')", name="ck_tool_capabilities_cost_tier"
        ),
    )
    op.create_index(
        "ix_tool_capabilities_vuln_classes",
        "tool_capabilities",
        ["vulnerability_classes"],
        postgresql_using="gin",
    )
    op.create_index("ix_tool_capabilities_overlap_group", "tool_capabilities", ["overlap_group"])

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("scan_type", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column(
            "scope_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scope_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "authorization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("authorization_records.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("profile", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("budget", postgresql.JSONB(), nullable=False),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("stats", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "scan_type IN ('recon','discovery','web','api','agent','full','validation')",
            name="ck_scans_scan_type",
        ),
        sa.CheckConstraint(
            "status IN ('draft','queued','running','paused','completed','failed','cancelled')",
            name="ck_scans_status",
        ),
    )

    op.create_table(
        "scan_stage_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("stage", sa.String(30), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metrics", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("error_code", sa.String(100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("attempt > 0", name="ck_scan_stage_runs_attempt_positive"),
        sa.CheckConstraint(
            "stage IN ('scope','recon','discovery','selection','scanning','agent','correlation','investigation','validation','reporting')",
            name="ck_scan_stage_runs_stage",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','succeeded','partial','failed','skipped','cancelled')",
            name="ck_scan_stage_runs_status",
        ),
        sa.UniqueConstraint(
            "scan_id", "stage", "attempt", name="uq_scan_stage_runs_scan_stage_attempt"
        ),
    )

    op.create_table(
        "tool_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("stage", sa.String(30), nullable=False),
        sa.Column(
            "tool_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column(
            "target_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "auth_context_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("auth_contexts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("input", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("command_redacted", sa.Text(), nullable=True),
        sa.Column("worker_id", sa.String(100), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "parent_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("coverage_summary", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("stats", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed','timeout','cancelled','skipped','scope_violation')",
            name="ck_tool_executions_status",
        ),
    )
    op.create_index("ix_tool_executions_scan_status", "tool_executions", ["scan_id", "status"])
    op.create_index(
        "ix_tool_executions_project_created",
        "tool_executions",
        ["project_id", sa.text("created_at DESC")],
    )
    op.create_index("ix_tool_executions_tool_version", "tool_executions", ["tool_version_id"])

    op.create_table(
        "tool_selection_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tool_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason_code", sa.String(50), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("score", sa.Numeric(12, 6), nullable=True),
        sa.Column("coverage_gap", postgresql.JSONB(), nullable=True),
        sa.Column("budget_snapshot", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "decision IN ('selected','skipped')", name="ck_tool_selection_decisions_decision"
        ),
    )
    op.create_index(
        "ix_tool_selection_decisions_scan_decision",
        "tool_selection_decisions",
        ["scan_id", "decision"],
    )

    op.create_table(
        "agent_runs",
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("agent_name", sa.String(100), nullable=False),
        sa.Column("agent_version", sa.String(50), nullable=False),
        sa.Column("model_provider", sa.String(100), nullable=True),
        sa.Column("model_id", sa.String(100), nullable=True),
        sa.Column("config_hash", sa.LargeBinary(), nullable=False),
        sa.Column("sandbox_id", sa.String(100), nullable=True),
        sa.Column("budget", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("transcript_evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed','timeout','cancelled','scope_violation')",
            name="ck_agent_runs_status",
        ),
    )
    op.create_index(
        "uq_agent_active_per_target",
        "agent_runs",
        ["project_id", "target_asset_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued','running')"),
    )

    op.create_table(
        "test_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.asset_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("vulnerability_class", sa.String(100), nullable=False),
        sa.Column(
            "auth_context_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("auth_contexts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("coverage_key", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column(
            "tool_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('planned','running','tested','not_applicable','error','skipped')",
            name="ck_test_cases_status",
        ),
        sa.UniqueConstraint("scan_id", "coverage_key", name="uq_test_cases_scan_coverage_key"),
    )
    op.create_index(
        "ix_test_cases_project_endpoint_vuln",
        "test_cases",
        ["project_id", "endpoint_id", "vulnerability_class"],
    )

    op.create_table(
        "operation_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action_hash", sa.LargeBinary(), nullable=False),
        sa.Column("action_description", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column(
            "requested_by_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "approved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope_snapshot", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint(
            "risk_level IN ('state_changing','destructive')",
            name="ck_operation_approvals_risk_level",
        ),
        sa.CheckConstraint("expires_at > approved_at", name="ck_operation_approvals_expiry"),
        sa.UniqueConstraint("scan_id", "action_hash", name="uq_operation_approvals_scan_action"),
    )

    # ─── Evidence ───────────────────────────────────────────────────────

    op.create_table(
        "evidence_objects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("storage_backend", sa.String(20), nullable=False, server_default="s3"),
        sa.Column("bucket", sa.String(255), nullable=False),
        sa.Column("object_key", sa.String(1024), nullable=False),
        sa.Column("sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.String(255), nullable=False),
        sa.Column("encryption_mode", sa.String(50), nullable=False, server_default="sse-kms"),
        sa.Column("encryption_key_ref", sa.String(512), nullable=True),
        sa.Column("redaction_status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_by_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('http_request','http_response','screenshot','tool_output',"
            "'agent_transcript','report','authorization_document','api_spec','other')",
            name="ck_evidence_objects_kind",
        ),
        sa.CheckConstraint(
            "encryption_mode IN ('sse-s3','sse-kms','client_envelope')",
            name="ck_evidence_objects_encryption_mode",
        ),
        sa.CheckConstraint(
            "redaction_status IN ('pending','redacted','not_required','failed')",
            name="ck_evidence_objects_redaction_status",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_evidence_objects_size_non_negative"),
        sa.UniqueConstraint(
            "project_id", "sha256", "kind", name="uq_evidence_objects_project_sha_kind"
        ),
    )
    op.create_index(
        "ix_evidence_objects_retention_active",
        "evidence_objects",
        ["retention_until"],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # Now add FK from asset_technologies.evidence_id and api_schemas.spec_evidence_id
    op.create_foreign_key(
        "fk_asset_technologies_evidence_id",
        "asset_technologies",
        "evidence_objects",
        ["evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_api_schemas_spec_evidence_id",
        "api_schemas",
        "evidence_objects",
        ["spec_evidence_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    # FK from authorization_records.document_evidence_id
    op.create_foreign_key(
        "fk_authorization_records_document_evidence_id",
        "authorization_records",
        "evidence_objects",
        ["document_evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # FK from host_addresses.last_tool_execution_id
    op.create_foreign_key(
        "fk_host_addresses_last_tool_execution_id",
        "host_addresses",
        "tool_executions",
        ["last_tool_execution_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # FK from scope_decisions
    op.create_foreign_key(
        "fk_scope_decisions_scan_id",
        "scope_decisions",
        "scans",
        ["scan_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_scope_decisions_matched_rule_id",
        "scope_decisions",
        "scope_rules",
        ["matched_rule_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_scope_decisions_scope_version_id",
        "scope_decisions",
        "scope_versions",
        ["scope_version_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    # FK from agent_runs.transcript_evidence_id
    op.create_foreign_key(
        "fk_agent_runs_transcript_evidence_id",
        "agent_runs",
        "evidence_objects",
        ["transcript_evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # http_exchanges — partitioned by RANGE on occurred_at
    op.execute("""
        CREATE TABLE http_exchanges (
            id bigint GENERATED ALWAYS AS IDENTITY,
            occurred_at timestamptz NOT NULL,
            project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            tool_execution_id uuid REFERENCES tool_executions(id) ON DELETE SET NULL,
            endpoint_id uuid REFERENCES endpoints(asset_id) ON DELETE SET NULL,
            method text NOT NULL,
            url_redacted text NOT NULL,
            request_evidence_id uuid REFERENCES evidence_objects(id) ON DELETE SET NULL,
            response_evidence_id uuid REFERENCES evidence_objects(id) ON DELETE SET NULL,
            status_code integer,
            request_bytes integer,
            response_bytes integer,
            duration_ms integer,
            redirect_chain jsonb NOT NULL DEFAULT '[]',
            tls jsonb NOT NULL DEFAULT '{}',
            error_code text,
            PRIMARY KEY (id, occurred_at)
        ) PARTITION BY RANGE (occurred_at)
    """)
    op.execute("CREATE TABLE http_exchanges_default PARTITION OF http_exchanges DEFAULT")
    op.create_index(
        "ix_http_exchanges_project_occurred",
        "http_exchanges",
        ["project_id", sa.text("occurred_at DESC")],
    )
    op.create_index("ix_http_exchanges_scan_id", "http_exchanges", ["scan_id"])

    # ─── Findings ───────────────────────────────────────────────────────

    op.create_table(
        "finding_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("canonical_key", sa.LargeBinary(32), nullable=False),
        sa.Column("vulnerability_class", sa.String(100), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="detected"),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "parameter_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parameters.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "auth_context_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("auth_contexts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report_ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence_score", sa.Numeric(5, 2), nullable=True),
        sa.Column("confidence_factors", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("impact_summary", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_finding_clusters_severity",
        ),
        sa.CheckConstraint(
            "status IN ('detected','needs_validation','validated','rejected','report_ready')",
            name="ck_finding_clusters_status",
        ),
        sa.CheckConstraint(
            "confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 100)",
            name="ck_finding_clusters_confidence_range",
        ),
        sa.UniqueConstraint(
            "project_id", "canonical_key", name="uq_finding_clusters_project_canonical_key"
        ),
    )
    op.create_index(
        "ix_finding_clusters_project_status_sev",
        "finding_clusters",
        ["project_id", "status", "severity"],
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column(
            "source_tool_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "agent_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agent_runs.execution_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "parameter_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parameters.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("vulnerability_class", sa.String(100), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity_claimed", sa.String(20), nullable=True),
        sa.Column("confidence_claimed", sa.Numeric(4, 3), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("root_cause_key", sa.String(255), nullable=True),
        sa.Column(
            "raw_output_evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_objects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="new"),
        sa.Column("fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "source_type IN ('scanner','agent','static','import','manual','ai')",
            name="ck_findings_source_type",
        ),
        sa.CheckConstraint(
            "status IN ('new','correlated','duplicate','suppressed')", name="ck_findings_status"
        ),
    )
    op.create_index("ix_findings_project_cluster", "findings", ["project_id", "cluster_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index(
        "ix_findings_project_detected", "findings", ["project_id", sa.text("detected_at DESC")]
    )

    op.create_table(
        "finding_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_objects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "cluster_id IS NOT NULL OR finding_id IS NOT NULL",
            name="ck_finding_evidence_target_present",
        ),
        sa.CheckConstraint(
            "role IN ('request','response','poc','screenshot','log','transcript','control','document','other')",
            name="ck_finding_evidence_role",
        ),
    )
    op.create_index(
        "uq_finding_evidence_finding_role",
        "finding_evidence",
        ["finding_id", "evidence_id", "role"],
        unique=True,
        postgresql_where=sa.text("finding_id IS NOT NULL"),
    )
    op.create_index(
        "uq_finding_evidence_cluster_role",
        "finding_evidence",
        ["cluster_id", "evidence_id", "role"],
        unique=True,
        postgresql_where=sa.text("cluster_id IS NOT NULL"),
    )

    op.create_table(
        "cluster_relations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "from_cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "to_cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relation_type", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "reviewed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "from_cluster_id <> to_cluster_id", name="ck_cluster_relations_no_self_ref"
        ),
        sa.CheckConstraint(
            "relation_type IN ('duplicate_candidate','related','shares_endpoint','conflict')",
            name="ck_cluster_relations_relation_type",
        ),
        sa.UniqueConstraint(
            "from_cluster_id",
            "to_cluster_id",
            "relation_type",
            name="uq_cluster_relations_from_to_type",
        ),
    )

    # ─── AI ─────────────────────────────────────────────────────────────

    op.create_table(
        "ai_providers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=True),
        sa.Column(
            "secret_ref_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("secret_refs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "kind IN ('openai_compatible','anthropic','google','local')",
            name="ck_ai_providers_kind",
        ),
        sa.UniqueConstraint("name", name="uq_ai_providers_name"),
    )

    op.create_table(
        "ai_models",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "provider_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("context_window", sa.Integer(), nullable=True),
        sa.Column("max_output_tokens", sa.Integer(), nullable=True),
        sa.Column("input_price_per_mtok", sa.Numeric(12, 6), nullable=True),
        sa.Column("output_price_per_mtok", sa.Numeric(12, 6), nullable=True),
        sa.Column(
            "capabilities", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('active','degraded','disabled')", name="ck_ai_models_status"
        ),
        sa.UniqueConstraint("provider_id", "model_id", name="uq_ai_models_provider_model_id"),
    )

    op.create_table(
        "prompt_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("task_class", sa.String(100), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("output_schema", postgresql.JSONB(), nullable=False),
        sa.Column("hash", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("version > 0", name="ck_prompt_templates_version_positive"),
        sa.UniqueConstraint("name", "version", name="uq_prompt_templates_name_version"),
    )

    op.create_table(
        "ai_routing_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("task_class", sa.String(100), nullable=False),
        sa.Column("min_tier", sa.String(20), nullable=False),
        sa.Column(
            "preferred_model_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_models.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "fallback_model_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("max_input_tokens", sa.Integer(), nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False),
        sa.Column("max_cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("temperature", sa.Numeric(3, 2), nullable=False, server_default="0.00"),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "min_tier IN ('small','medium','strong')", name="ck_ai_routing_policies_min_tier"
        ),
        sa.CheckConstraint(
            "temperature >= 0 AND temperature <= 2", name="ck_ai_routing_policies_temperature_range"
        ),
        sa.UniqueConstraint("task_class", name="uq_ai_routing_policies_task_class"),
    )

    op.create_table(
        "ai_invocations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("task_class", sa.String(100), nullable=False),
        sa.Column(
            "model_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_models.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("cached_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column(
            "response_evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_objects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("cache_hit", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "fallback_from_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_invocations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("error_code", sa.String(100), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('succeeded','failed','timeout','schema_error','budget_exceeded')",
            name="ck_ai_invocations_status",
        ),
    )
    op.create_index(
        "ix_ai_invocations_project_created",
        "ai_invocations",
        ["project_id", sa.text("created_at DESC")],
    )
    op.create_index("ix_ai_invocations_scan_id", "ai_invocations", ["scan_id"])
    op.create_index("ix_ai_invocations_task_status", "ai_invocations", ["task_class", "status"])

    # ─── Validation & Lifecycle ─────────────────────────────────────────

    op.create_table(
        "validations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("stage", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("plan", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "performed_by_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewer_type", sa.String(20), nullable=True),
        sa.Column(
            "reviewer_model_invocation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_invocations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "reviewer_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("verdict", sa.String(30), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Numeric(5, 2), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "stage IN ('evidence_review','plan','controlled_validation','independent_review','complete')",
            name="ck_validations_stage",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','passed','failed','inconclusive','cancelled')",
            name="ck_validations_status",
        ),
        sa.CheckConstraint(
            "reviewer_type IS NULL OR reviewer_type IN ('human','model')",
            name="ck_validations_reviewer_type",
        ),
        sa.CheckConstraint(
            "verdict IS NULL OR verdict IN ('validated','rejected','needs_more_evidence')",
            name="ck_validations_verdict",
        ),
    )
    op.create_index(
        "ix_validations_cluster_created", "validations", ["cluster_id", sa.text("created_at DESC")]
    )
    op.create_index("ix_validations_status", "validations", ["status"])

    op.create_table(
        "validation_checks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "validation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("validations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("check_type", sa.String(50), nullable=False),
        sa.Column("result", sa.String(30), nullable=False),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_objects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "check_type IN ('scope','reproducibility','evidence_completeness','control_comparison',"
            "'impact','alternative_explanation','duplicate','independent_review','authorization_context')",
            name="ck_validation_checks_check_type",
        ),
        sa.CheckConstraint(
            "result IN ('pass','fail','inconclusive','not_applicable')",
            name="ck_validation_checks_result",
        ),
    )
    op.create_index(
        "ix_validation_checks_validation_type", "validation_checks", ["validation_id", "check_type"]
    )

    op.create_table(
        "finding_state_transitions",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cluster_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding_clusters.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(30), nullable=True),
        sa.Column("to_status", sa.String(30), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column(
            "validation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("validations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "actor_type IN ('user','system','model')",
            name="ck_finding_state_transitions_actor_type",
        ),
    )
    op.create_index(
        "ix_finding_state_transitions_cluster_created",
        "finding_state_transitions",
        ["cluster_id", "created_at"],
    )

    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("finding_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("filters", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "artifact_evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_objects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=True),
        sa.Column(
            "generated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("format IN ('markdown','json','pdf')", name="ck_reports_format"),
        sa.CheckConstraint(
            "status IN ('queued','running','ready','failed')", name="ck_reports_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_reports_version_positive"),
        sa.UniqueConstraint("scan_id", "version", "format", name="uq_reports_scan_version_format"),
    )

    # ─── Audit, Outbox & Cost ───────────────────────────────────────────

    # audit_logs — partitioned by RANGE on created_at
    op.execute("""
        CREATE TABLE audit_logs (
            id bigint GENERATED ALWAYS AS IDENTITY,
            created_at timestamptz NOT NULL DEFAULT now(),
            project_id uuid REFERENCES projects(id) ON DELETE SET NULL,
            actor_type text NOT NULL CHECK (actor_type IN ('user','api_key','system','worker','model')),
            actor_id text,
            action text NOT NULL,
            entity_type text NOT NULL,
            entity_id text,
            before_hash bytea,
            after_hash bytea,
            ip inet,
            user_agent text,
            request_id text,
            metadata jsonb NOT NULL DEFAULT '{}',
            PRIMARY KEY (id, created_at)
        ) PARTITION BY RANGE (created_at)
    """)
    op.execute("CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT")
    op.create_index(
        "ix_audit_logs_project_created", "audit_logs", ["project_id", sa.text("created_at DESC")]
    )
    op.create_index("ix_audit_logs_actor", "audit_logs", ["actor_type", "actor_id"])

    op.create_table(
        "outbox_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("aggregate_type", sa.String(100), nullable=False),
        sa.Column("aggregate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_outbox_events_unpublished",
        "outbox_events",
        ["created_at"],
        postgresql_where=sa.text("published_at IS NULL"),
    )

    op.create_table(
        "cost_entries",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("quantity", sa.Numeric(18, 6), nullable=True),
        sa.Column("unit", sa.String(50), nullable=True),
        sa.Column("reference_type", sa.String(50), nullable=True),
        sa.Column("reference_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "category IN ('tool_compute','ai_tokens','storage','network','other')",
            name="ck_cost_entries_category",
        ),
    )
    op.create_index("ix_cost_entries_project_created", "cost_entries", ["project_id", "created_at"])
    op.create_index("ix_cost_entries_scan_category", "cost_entries", ["scan_id", "category"])

    # ─── Asset discoveries (depends on scans and tool_executions) ──────

    op.create_table(
        "asset_discoveries",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "tool_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_executions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False, server_default="1.000"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_index(
        "ix_asset_discoveries_asset_discovered",
        "asset_discoveries",
        ["asset_id", sa.text("discovered_at DESC")],
    )
    op.create_index("ix_asset_discoveries_scan_id", "asset_discoveries", ["scan_id"])


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_table("asset_discoveries")
    op.drop_table("cost_entries")
    op.drop_table("outbox_events")
    op.execute("DROP TABLE IF EXISTS audit_logs CASCADE")
    op.drop_table("reports")
    op.drop_table("finding_state_transitions")
    op.drop_table("validation_checks")
    op.drop_table("validations")
    op.drop_table("cluster_relations")
    op.drop_table("finding_evidence")
    op.drop_table("findings")
    op.drop_table("finding_clusters")
    op.drop_table("ai_invocations")
    op.drop_table("ai_routing_policies")
    op.drop_table("prompt_templates")
    op.drop_table("ai_models")
    op.drop_table("ai_providers")
    op.execute("DROP TABLE IF EXISTS http_exchanges CASCADE")
    op.drop_table("evidence_objects")
    op.drop_table("operation_approvals")
    op.drop_table("test_cases")
    op.drop_table("agent_runs")
    op.drop_table("tool_selection_decisions")
    op.drop_table("tool_executions")
    op.drop_table("scan_stage_runs")
    op.drop_table("scans")
    op.drop_table("tool_capabilities")
    op.drop_table("tool_versions")
    op.drop_table("tools")
    op.drop_table("auth_contexts")
    op.drop_table("secret_refs")
    op.drop_table("api_schemas")
    op.drop_table("asset_technologies")
    op.drop_table("technologies")
    op.drop_table("parameters")
    op.drop_table("endpoints")
    op.drop_table("services")
    op.drop_table("host_addresses")
    op.drop_table("hosts")
    op.drop_table("domains")
    op.drop_table("assets")
    op.drop_table("targets")
    op.execute("DROP TABLE IF EXISTS scope_decisions CASCADE")
    op.drop_table("scope_rules")
    op.drop_table("scope_versions")
    op.drop_table("authorization_records")
    op.drop_table("project_members")
    op.drop_table("api_keys")
    op.drop_table("projects")
    op.drop_table("users")
