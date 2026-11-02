"""Tests for database constraints, naming conventions, unique keys, foreign keys, and indexes.

All tests operate on SQLAlchemy table metadata statically.
"""

from __future__ import annotations

from sqlalchemy import CheckConstraint, UniqueConstraint

import backend.app.db.models  # noqa: F401
from backend.app.db.base import Base


class TestConstraintNamingConventions:
    """Verify that constraints adhere to the naming conventions specified in Base."""

    def test_naming_convention_dict_configured(self) -> None:
        convention = Base.metadata.naming_convention
        assert "ix" in convention
        assert "uq" in convention
        assert "ck" in convention
        assert "fk" in convention
        assert "pk" in convention

    def test_check_constraints_have_names(self) -> None:
        """Every CheckConstraint explicitly defined on models must have a non-empty name."""
        for table in Base.metadata.tables.values():
            for constraint in table.constraints:
                if isinstance(constraint, CheckConstraint):
                    assert isinstance(constraint.name, str) and len(constraint.name) > 0, (
                        f"CheckConstraint on table {table.name} has no name: {constraint.sqltext}"
                    )
                    assert constraint.name.startswith("ck_"), (
                        f"CheckConstraint on {table.name} name '{constraint.name}' "
                        "does not start with ck_"
                    )


class TestForeignKeyCascadeBehaviors:
    """Verify ON DELETE behaviors are explicitly declared on critical foreign keys."""

    def test_project_members_cascade(self) -> None:
        table = Base.metadata.tables["project_members"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["project_id"].ondelete == "CASCADE"
        assert fks["user_id"].ondelete == "CASCADE"

    def test_scope_versions_cascade(self) -> None:
        table = Base.metadata.tables["scope_versions"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["project_id"].ondelete == "CASCADE"
        assert fks["authorization_id"].ondelete == "RESTRICT"

    def test_scans_cascade(self) -> None:
        table = Base.metadata.tables["scans"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["project_id"].ondelete == "CASCADE"

    def test_finding_clusters_cascade(self) -> None:
        table = Base.metadata.tables["finding_clusters"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["project_id"].ondelete == "CASCADE"
        assert fks["asset_id"].ondelete == "RESTRICT"

    def test_endpoints_cascade_from_assets(self) -> None:
        table = Base.metadata.tables["endpoints"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["asset_id"].ondelete == "CASCADE"

    def test_evidence_objects_cascade(self) -> None:
        table = Base.metadata.tables["evidence_objects"]
        fks = {fk.parent.name: fk for fk in table.foreign_keys}
        assert fks["project_id"].ondelete == "CASCADE"
        assert fks["created_by_execution_id"].ondelete == "SET NULL"


class TestUniqueConstraints:
    """Verify natural unique keys per DATABASE_DESIGN.md."""

    def test_project_slug_unique(self) -> None:
        table = Base.metadata.tables["projects"]
        uqs = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        uq_cols = [[col.name for col in uq.columns] for uq in uqs]
        assert ["slug"] in uq_cols

    def test_finding_clusters_canonical_key_unique_in_project(self) -> None:
        table = Base.metadata.tables["finding_clusters"]
        uqs = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        uq_cols = [[col.name for col in uq.columns] for uq in uqs]
        assert ["project_id", "canonical_key"] in uq_cols

    def test_endpoints_method_url_hash_unique_in_project(self) -> None:
        table = Base.metadata.tables["endpoints"]
        uqs = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        uq_cols = [[col.name for col in uq.columns] for uq in uqs]
        assert ["project_id", "method", "url_hash"] in uq_cols

    def test_reports_scan_version_format_unique(self) -> None:
        table = Base.metadata.tables["reports"]
        uqs = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        uq_cols = [[col.name for col in uq.columns] for uq in uqs]
        assert ["scan_id", "version", "format"] in uq_cols

    def test_operation_approvals_scan_action_unique(self) -> None:
        table = Base.metadata.tables["operation_approvals"]
        uqs = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        uq_cols = [[col.name for col in uq.columns] for uq in uqs]
        assert ["scan_id", "action_hash"] in uq_cols


class TestPartialAndSpecialIndexes:
    """Verify critical partial indexes and GIN indexes defined in models."""

    def test_agent_runs_active_unique_index(self) -> None:
        table = Base.metadata.tables["agent_runs"]
        indexes = {str(idx.name): idx for idx in table.indexes}
        assert "uq_agent_active_per_target" in indexes
        idx = indexes["uq_agent_active_per_target"]
        assert idx.unique is True
        where_clause = str(idx.dialect_options["postgresql"]["where"])
        assert "queued" in where_clause and "running" in where_clause

    def test_scope_versions_active_unique_index(self) -> None:
        table = Base.metadata.tables["scope_versions"]
        indexes = {str(idx.name): idx for idx in table.indexes}
        assert "uq_scope_active" in indexes
        idx = indexes["uq_scope_active"]
        assert idx.unique is True
        where_clause = str(idx.dialect_options["postgresql"]["where"])
        assert "active" in where_clause

    def test_tool_capabilities_gin_index(self) -> None:
        table = Base.metadata.tables["tool_capabilities"]
        indexes = {str(idx.name): idx for idx in table.indexes}
        assert "ix_tool_capabilities_vuln_classes" in indexes
        idx = indexes["ix_tool_capabilities_vuln_classes"]
        assert idx.dialect_options["postgresql"]["using"] == "gin"

    def test_evidence_objects_active_retention_index(self) -> None:
        table = Base.metadata.tables["evidence_objects"]
        indexes = {str(idx.name): idx for idx in table.indexes}
        assert "ix_evidence_objects_retention_active" in indexes
        idx = indexes["ix_evidence_objects_retention_active"]
        where_clause = str(idx.dialect_options["postgresql"]["where"])
        assert "deleted_at" in where_clause
