"""Phase 2 Row-Level Security (RLS) and tenant isolation migration.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-02 01:30:00.000000+00:00

This migration:
1. Creates session helper functions `current_project_id()` and `current_user_id()`.
2. Enables and forces RLS on all project-owned tables and partitions.
3. Defines restrictive/permissive policies for SELECT, INSERT, UPDATE, DELETE.
4. Enforces subquery isolation on indirect tables (scope_rules, validation_checks).
5. Enforces append-only immutability on audit_logs (denying UPDATE and DELETE).
6. Provides a complete, symmetric, reversible downgrade() routine.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# All tables containing direct project_id column
DIRECT_PROJECT_TABLES: list[str] = [
    "project_members",
    "authorization_records",
    "scope_versions",
    "scope_decisions",
    "targets",
    "assets",
    "domains",
    "hosts",
    "host_addresses",
    "services",
    "endpoints",
    "parameters",
    "asset_technologies",
    "api_schemas",
    "asset_discoveries",
    "scans",
    "scan_stage_runs",
    "tool_executions",
    "tool_selection_decisions",
    "agent_runs",
    "test_cases",
    "operation_approvals",
    "auth_contexts",
    "secret_refs",
    "evidence_objects",
    "http_exchanges",
    "finding_clusters",
    "findings",
    "finding_evidence",
    "cluster_relations",
    "validations",
    "finding_state_transitions",
    "reports",
    "ai_invocations",
    "cost_entries",
]

PARTITION_TABLES: list[str] = [
    "scope_decisions_default",
    "http_exchanges_default",
    "audit_logs_default",
]


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # Non-PostgreSQL dialects (e.g. SQLite test runners) do not support PostgreSQL RLS DDL
        return

    # 1. Create SQL helper functions for safe context resolution
    op.execute(
        """
        CREATE OR REPLACE FUNCTION current_project_id() RETURNS uuid STABLE AS $$
        BEGIN
            RETURN NULLIF(current_setting('app.current_project_id', true), '')::uuid;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION current_user_id() RETURNS uuid STABLE AS $$
        BEGIN
            RETURN NULLIF(current_setting('app.current_user_id', true), '')::uuid;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    # 2. RLS on projects table (tenant root)
    op.execute("ALTER TABLE projects ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE projects FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        CREATE POLICY projects_tenant_select ON projects
        FOR SELECT
        USING (id = current_project_id());
        """
    )
    op.execute(
        """
        CREATE POLICY projects_tenant_insert ON projects
        FOR INSERT
        WITH CHECK (true);
        """
    )
    op.execute(
        """
        CREATE POLICY projects_tenant_update ON projects
        FOR UPDATE
        USING (id = current_project_id())
        WITH CHECK (id = current_project_id());
        """
    )
    op.execute(
        """
        CREATE POLICY projects_tenant_delete ON projects
        FOR DELETE
        USING (id = current_project_id());
        """
    )

    # 3. RLS on Direct Project-Owned Tables
    for table in DIRECT_PROJECT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

        op.execute(
            f"""
            CREATE POLICY {table}_tenant_select ON {table}
            FOR SELECT
            USING (project_id = current_project_id());
            """
        )
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_insert ON {table}
            FOR INSERT
            WITH CHECK (project_id = current_project_id());
            """
        )
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_update ON {table}
            FOR UPDATE
            USING (project_id = current_project_id())
            WITH CHECK (project_id = current_project_id());
            """
        )
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_delete ON {table}
            FOR DELETE
            USING (project_id = current_project_id());
            """
        )

    # 4. Indirectly Project-Owned: scope_rules (via scope_versions)
    op.execute("ALTER TABLE scope_rules ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scope_rules FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        CREATE POLICY scope_rules_tenant_select ON scope_rules
        FOR SELECT
        USING (
            scope_version_id IN (
                SELECT id FROM scope_versions WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY scope_rules_tenant_insert ON scope_rules
        FOR INSERT
        WITH CHECK (
            scope_version_id IN (
                SELECT id FROM scope_versions WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY scope_rules_tenant_update ON scope_rules
        FOR UPDATE
        USING (
            scope_version_id IN (
                SELECT id FROM scope_versions WHERE project_id = current_project_id()
            )
        )
        WITH CHECK (
            scope_version_id IN (
                SELECT id FROM scope_versions WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY scope_rules_tenant_delete ON scope_rules
        FOR DELETE
        USING (
            scope_version_id IN (
                SELECT id FROM scope_versions WHERE project_id = current_project_id()
            )
        );
        """
    )

    # 5. Indirectly Project-Owned: validation_checks (via validations)
    op.execute("ALTER TABLE validation_checks ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE validation_checks FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        CREATE POLICY validation_checks_tenant_select ON validation_checks
        FOR SELECT
        USING (
            validation_id IN (
                SELECT id FROM validations WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY validation_checks_tenant_insert ON validation_checks
        FOR INSERT
        WITH CHECK (
            validation_id IN (
                SELECT id FROM validations WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY validation_checks_tenant_update ON validation_checks
        FOR UPDATE
        USING (
            validation_id IN (
                SELECT id FROM validations WHERE project_id = current_project_id()
            )
        )
        WITH CHECK (
            validation_id IN (
                SELECT id FROM validations WHERE project_id = current_project_id()
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY validation_checks_tenant_delete ON validation_checks
        FOR DELETE
        USING (
            validation_id IN (
                SELECT id FROM validations WHERE project_id = current_project_id()
            )
        );
        """
    )

    # 6. Audit Logs: Append-only, tenant-isolated read
    op.execute("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        CREATE POLICY audit_logs_tenant_select ON audit_logs
        FOR SELECT
        USING (project_id = current_project_id());
        """
    )
    op.execute(
        """
        CREATE POLICY audit_logs_tenant_insert ON audit_logs
        FOR INSERT
        WITH CHECK (project_id = current_project_id() OR project_id IS NULL);
        """
    )
    # Notice: NO UPDATE or DELETE policy on audit_logs (Strict append-only immutability)

    # 7. Partition Tables: Enable and force RLS
    for partition in PARTITION_TABLES:
        op.execute(f"ALTER TABLE {partition} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {partition} FORCE ROW LEVEL SECURITY;")

    # 8. Cross-Project Relationship Protection Triggers
    op.execute(
        """
        CREATE OR REPLACE FUNCTION check_cross_project_reference() RETURNS trigger AS $$
        DECLARE
            parent_proj_id uuid;
            parent_table text := TG_ARGV[0];
            fk_column text := TG_ARGV[1];
            fk_value uuid;
        BEGIN
            EXECUTE format('SELECT ($1).%I', fk_column) INTO fk_value USING NEW;
            IF fk_value IS NOT NULL THEN
                EXECUTE format('SELECT project_id FROM %I WHERE id = $1', parent_table) INTO parent_proj_id USING fk_value;
                IF parent_proj_id IS NOT NULL AND parent_proj_id != NEW.project_id THEN
                    RAISE EXCEPTION 'Cross-project reference violation: % (project_id=%) references % (project_id=%)',
                        TG_TABLE_NAME, NEW.project_id, parent_table, parent_proj_id
                        USING ERRCODE = '23503';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    fk_checks = [
        ("scans", "targets", "target_id"),
        ("findings", "targets", "target_id"),
        ("findings", "scans", "scan_id"),
        ("validations", "findings", "finding_id"),
        ("scope_decisions", "scope_versions", "scope_version_id"),
        ("tool_executions", "scans", "scan_id"),
        ("agent_runs", "scans", "scan_id"),
        ("hosts", "targets", "target_id"),
        ("services", "hosts", "host_id"),
        ("endpoints", "services", "service_id"),
    ]

    for child_tbl, parent_tbl, fk_col in fk_checks:
        op.execute(
            f"""
            CREATE TRIGGER trg_{child_tbl}_check_proj_{fk_col}
            BEFORE INSERT OR UPDATE ON {child_tbl}
            FOR EACH ROW
            EXECUTE FUNCTION check_cross_project_reference('{parent_tbl}', '{fk_col}');
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # Drop cross-project triggers and trigger function
    fk_checks = [
        ("scans", "targets", "target_id"),
        ("findings", "targets", "target_id"),
        ("findings", "scans", "scan_id"),
        ("validations", "findings", "finding_id"),
        ("scope_decisions", "scope_versions", "scope_version_id"),
        ("tool_executions", "scans", "scan_id"),
        ("agent_runs", "scans", "scan_id"),
        ("hosts", "targets", "target_id"),
        ("services", "hosts", "host_id"),
        ("endpoints", "services", "service_id"),
    ]
    for child_tbl, _, fk_col in fk_checks:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{child_tbl}_check_proj_{fk_col} ON {child_tbl};")

    op.execute("DROP FUNCTION IF EXISTS check_cross_project_reference();")

    # Disable RLS on partitions
    for partition in PARTITION_TABLES:
        op.execute(f"ALTER TABLE {partition} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {partition} DISABLE ROW LEVEL SECURITY;")

    # Drop audit_logs policies and disable RLS
    op.execute("DROP POLICY IF EXISTS audit_logs_tenant_select ON audit_logs;")
    op.execute("DROP POLICY IF EXISTS audit_logs_tenant_insert ON audit_logs;")
    op.execute("ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;")

    # Drop validation_checks policies and disable RLS
    op.execute("DROP POLICY IF EXISTS validation_checks_tenant_select ON validation_checks;")
    op.execute("DROP POLICY IF EXISTS validation_checks_tenant_insert ON validation_checks;")
    op.execute("DROP POLICY IF EXISTS validation_checks_tenant_update ON validation_checks;")
    op.execute("DROP POLICY IF EXISTS validation_checks_tenant_delete ON validation_checks;")
    op.execute("ALTER TABLE validation_checks NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE validation_checks DISABLE ROW LEVEL SECURITY;")

    # Drop scope_rules policies and disable RLS
    op.execute("DROP POLICY IF EXISTS scope_rules_tenant_select ON scope_rules;")
    op.execute("DROP POLICY IF EXISTS scope_rules_tenant_insert ON scope_rules;")
    op.execute("DROP POLICY IF EXISTS scope_rules_tenant_update ON scope_rules;")
    op.execute("DROP POLICY IF EXISTS scope_rules_tenant_delete ON scope_rules;")
    op.execute("ALTER TABLE scope_rules NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scope_rules DISABLE ROW LEVEL SECURITY;")

    # Drop policies on direct project tables and disable RLS
    for table in DIRECT_PROJECT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {table};")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {table};")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {table};")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_delete ON {table};")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    # Drop projects policies and disable RLS
    op.execute("DROP POLICY IF EXISTS projects_tenant_select ON projects;")
    op.execute("DROP POLICY IF EXISTS projects_tenant_insert ON projects;")
    op.execute("DROP POLICY IF EXISTS projects_tenant_update ON projects;")
    op.execute("DROP POLICY IF EXISTS projects_tenant_delete ON projects;")
    op.execute("ALTER TABLE projects NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE projects DISABLE ROW LEVEL SECURITY;")

    # Drop context helper functions
    op.execute("DROP FUNCTION IF EXISTS current_user_id();")
    op.execute("DROP FUNCTION IF EXISTS current_project_id();")
