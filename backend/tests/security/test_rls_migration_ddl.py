"""Tests verifying RLS migration DDL completeness, consistency, and downgrade symmetry."""

import importlib
from unittest.mock import MagicMock

import pytest

import backend.app.db.models  # noqa: F401
from backend.app.db.base import Base

rls_migration = importlib.import_module("backend.alembic.versions.0002_phase2_rls")
DIRECT_PROJECT_TABLES = rls_migration.DIRECT_PROJECT_TABLES
PARTITION_TABLES = rls_migration.PARTITION_TABLES
revision = rls_migration.revision
down_revision = rls_migration.down_revision
upgrade = rls_migration.upgrade
downgrade = rls_migration.downgrade


def test_migration_chain() -> None:
    """Verify migration lineage and revision identifiers."""
    assert revision == "0002"
    assert down_revision == "0001"


def test_direct_project_tables_coverage() -> None:
    """Verify that all direct project tables exist in model metadata with project_id."""
    tables_meta = Base.metadata.tables

    # Every table declared in DIRECT_PROJECT_TABLES must exist
    for table_name in DIRECT_PROJECT_TABLES:
        assert table_name in tables_meta, f"{table_name} missing from Base.metadata"
        assert "project_id" in tables_meta[table_name].c, f"{table_name} missing project_id column"

    # Every table in metadata with non-nullable project_id must be in DIRECT_PROJECT_TABLES
    for name, table in tables_meta.items():
        if name in ("projects", "audit_logs", "secret_refs"):
            continue  # Handled separately with customized policies
        if "project_id" in table.c:
            msg = f"{name} with project_id missing from DIRECT_PROJECT_TABLES"
            assert name in DIRECT_PROJECT_TABLES, msg


def test_indirect_project_tables() -> None:
    """Verify indirect project tables exist and have expected foreign keys."""
    tables_meta = Base.metadata.tables

    assert "scope_rules" in tables_meta
    assert "scope_version_id" in tables_meta["scope_rules"].c
    assert "project_id" not in tables_meta["scope_rules"].c

    assert "validation_checks" in tables_meta
    assert "validation_id" in tables_meta["validation_checks"].c
    assert "project_id" not in tables_meta["validation_checks"].c


def test_partition_tables() -> None:
    """Verify partition tables list."""
    assert len(PARTITION_TABLES) == 3
    assert "scope_decisions_default" in PARTITION_TABLES
    assert "http_exchanges_default" in PARTITION_TABLES
    assert "audit_logs_default" in PARTITION_TABLES


def test_migration_upgrade_and_downgrade_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Execute upgrade and downgrade against a mock PostgreSQL dialect and collect all DDL."""
    mock_op = MagicMock()
    mock_bind = MagicMock()
    mock_bind.dialect.name = "postgresql"
    mock_op.get_bind.return_value = mock_bind

    executed_statements: list[str] = []

    def fake_execute(stmt: str) -> None:
        executed_statements.append(stmt.strip())

    mock_op.execute.side_effect = fake_execute

    monkeypatch.setattr(rls_migration, "op", mock_op)

    # Execute upgrade
    upgrade()
    assert len(executed_statements) > 0

    all_upgrade_sql = "\n".join(executed_statements)
    assert "CREATE OR REPLACE FUNCTION current_project_id()" in all_upgrade_sql
    assert "CREATE OR REPLACE FUNCTION current_user_id()" in all_upgrade_sql
    assert "ALTER TABLE projects ENABLE ROW LEVEL SECURITY;" in all_upgrade_sql
    assert "ALTER TABLE projects FORCE ROW LEVEL SECURITY;" in all_upgrade_sql

    for tbl in DIRECT_PROJECT_TABLES:
        assert f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;" in all_upgrade_sql
        assert f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;" in all_upgrade_sql
        assert f"CREATE POLICY {tbl}_tenant_select ON {tbl}" in all_upgrade_sql
        assert f"CREATE POLICY {tbl}_tenant_insert ON {tbl}" in all_upgrade_sql
        assert f"CREATE POLICY {tbl}_tenant_update ON {tbl}" in all_upgrade_sql
        assert f"CREATE POLICY {tbl}_tenant_delete ON {tbl}" in all_upgrade_sql

    # Audit log policy checks
    assert "CREATE POLICY audit_logs_tenant_select ON audit_logs" in all_upgrade_sql
    assert "CREATE POLICY audit_logs_tenant_insert ON audit_logs" in all_upgrade_sql
    assert "CREATE POLICY audit_logs_tenant_update ON audit_logs" not in all_upgrade_sql
    assert "CREATE POLICY audit_logs_tenant_delete ON audit_logs" not in all_upgrade_sql

    # Cross-project reference checks
    assert "CREATE OR REPLACE FUNCTION check_cross_project_reference()" in all_upgrade_sql

    # Execute downgrade
    executed_statements.clear()
    downgrade()
    assert len(executed_statements) > 0

    all_downgrade_sql = "\n".join(executed_statements)
    assert "DROP FUNCTION IF EXISTS current_project_id();" in all_downgrade_sql
    assert "DROP FUNCTION IF EXISTS current_user_id();" in all_downgrade_sql
    assert "DROP FUNCTION IF EXISTS check_cross_project_reference();" in all_downgrade_sql
    assert "ALTER TABLE projects DISABLE ROW LEVEL SECURITY;" in all_downgrade_sql

    for tbl in DIRECT_PROJECT_TABLES:
        assert f"DROP POLICY IF EXISTS {tbl}_tenant_select ON {tbl};" in all_downgrade_sql
        assert f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;" in all_downgrade_sql
