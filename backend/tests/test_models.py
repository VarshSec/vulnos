"""Tests for SQLAlchemy model registration, table metadata, column types, and relationships.

All tests operate on the static metadata — no live PostgreSQL connection required.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import inspect

# Force model registration by importing the models package
import backend.app.db.models  # noqa: F401
from backend.app.db.base import Base
from backend.app.db.models import (
    AgentRun,
    AIInvocation,
    AIModel,
    AIProvider,
    AIRoutingPolicy,
    APIKey,
    APISchema,
    Asset,
    AssetDiscovery,
    AssetTechnology,
    AuditLog,
    AuthContext,
    AuthorizationRecord,
    ClusterRelation,
    CostEntry,
    Domain,
    Endpoint,
    EvidenceObject,
    Finding,
    FindingCluster,
    FindingEvidence,
    FindingStateTransition,
    Host,
    HostAddress,
    HTTPExchange,
    OperationApproval,
    OutboxEvent,
    Parameter,
    Project,
    ProjectMember,
    PromptTemplate,
    Report,
    Scan,
    ScanStageRun,
    ScopeDecision,
    ScopeRule,
    ScopeVersion,
    SecretRef,
    Service,
    Target,
    Technology,
    TestCase,
    Tool,
    ToolCapability,
    ToolExecution,
    ToolSelectionDecision,
    ToolVersion,
    User,
    Validation,
    ValidationCheck,
)

# ─── Table Registration ────────────────────────────────────────────

EXPECTED_TABLES = {
    "users",
    "api_keys",
    "projects",
    "project_members",
    "authorization_records",
    "scope_versions",
    "scope_rules",
    "scope_decisions",
    "targets",
    "assets",
    "domains",
    "hosts",
    "host_addresses",
    "services",
    "endpoints",
    "parameters",
    "technologies",
    "asset_technologies",
    "api_schemas",
    "asset_discoveries",
    "tools",
    "tool_versions",
    "tool_capabilities",
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
    "validation_checks",
    "finding_state_transitions",
    "reports",
    "ai_providers",
    "ai_models",
    "prompt_templates",
    "ai_routing_policies",
    "ai_invocations",
    "audit_logs",
    "outbox_events",
    "cost_entries",
}


class TestTableRegistration:
    """Verify all 50 tables are registered in Base.metadata."""

    def test_all_50_tables_present(self) -> None:
        registered = set(Base.metadata.tables.keys())
        missing = EXPECTED_TABLES - registered
        assert not missing, f"Missing tables from metadata: {missing}"

    def test_table_count_is_50(self) -> None:
        # We expect exactly 50 tables
        registered = set(Base.metadata.tables.keys())
        counted = registered & EXPECTED_TABLES
        assert len(counted) == 50

    def test_no_unknown_tables(self) -> None:
        """No tables exist that aren't in the expected set."""
        registered = set(Base.metadata.tables.keys())
        unexpected = registered - EXPECTED_TABLES
        assert not unexpected, f"Unexpected tables in metadata: {unexpected}"


# ─── Model → Table Mapping ─────────────────────────────────────────

MODEL_TABLE_MAP = [
    (User, "users"),
    (APIKey, "api_keys"),
    (Project, "projects"),
    (ProjectMember, "project_members"),
    (AuthorizationRecord, "authorization_records"),
    (ScopeVersion, "scope_versions"),
    (ScopeRule, "scope_rules"),
    (ScopeDecision, "scope_decisions"),
    (Target, "targets"),
    (Asset, "assets"),
    (Domain, "domains"),
    (Host, "hosts"),
    (HostAddress, "host_addresses"),
    (Service, "services"),
    (Endpoint, "endpoints"),
    (Parameter, "parameters"),
    (Technology, "technologies"),
    (AssetTechnology, "asset_technologies"),
    (APISchema, "api_schemas"),
    (AssetDiscovery, "asset_discoveries"),
    (Tool, "tools"),
    (ToolVersion, "tool_versions"),
    (ToolCapability, "tool_capabilities"),
    (Scan, "scans"),
    (ScanStageRun, "scan_stage_runs"),
    (ToolExecution, "tool_executions"),
    (ToolSelectionDecision, "tool_selection_decisions"),
    (AgentRun, "agent_runs"),
    (TestCase, "test_cases"),
    (OperationApproval, "operation_approvals"),
    (AuthContext, "auth_contexts"),
    (SecretRef, "secret_refs"),
    (EvidenceObject, "evidence_objects"),
    (HTTPExchange, "http_exchanges"),
    (FindingCluster, "finding_clusters"),
    (Finding, "findings"),
    (FindingEvidence, "finding_evidence"),
    (ClusterRelation, "cluster_relations"),
    (Validation, "validations"),
    (ValidationCheck, "validation_checks"),
    (FindingStateTransition, "finding_state_transitions"),
    (Report, "reports"),
    (AIProvider, "ai_providers"),
    (AIModel, "ai_models"),
    (PromptTemplate, "prompt_templates"),
    (AIRoutingPolicy, "ai_routing_policies"),
    (AIInvocation, "ai_invocations"),
    (AuditLog, "audit_logs"),
    (OutboxEvent, "outbox_events"),
    (CostEntry, "cost_entries"),
]


class TestModelTableMapping:
    """Verify each model class maps to the correct table name."""

    @pytest.mark.parametrize("model_cls, expected_table", MODEL_TABLE_MAP)
    def test_tablename(self, model_cls: Any, expected_table: str) -> None:
        assert model_cls.__tablename__ == expected_table


# ─── Primary Key Verification ──────────────────────────────────────

UUID_PK_MODELS = [
    User,
    APIKey,
    Project,
    AuthorizationRecord,
    ScopeVersion,
    ScopeRule,
    Target,
    Asset,
    HostAddress,
    Parameter,
    Technology,
    APISchema,
    Tool,
    ToolVersion,
    ToolCapability,
    Scan,
    ScanStageRun,
    ToolExecution,
    ToolSelectionDecision,
    TestCase,
    OperationApproval,
    AuthContext,
    SecretRef,
    EvidenceObject,
    FindingCluster,
    Finding,
    FindingEvidence,
    ClusterRelation,
    Validation,
    ValidationCheck,
    Report,
    AIProvider,
    AIModel,
    PromptTemplate,
    AIRoutingPolicy,
    AIInvocation,
]

# Models with UUID PK that are also FK to another table (asset subtypes)
ASSET_SUBTYPE_MODELS = [Domain, Host, Service, Endpoint]

# Composite PK models
COMPOSITE_PK_MODELS = [
    (ProjectMember, ["project_id", "user_id"]),
    (AssetTechnology, ["asset_id", "technology_id"]),
    (ScopeDecision, ["id", "decided_at"]),
    (HTTPExchange, ["id", "occurred_at"]),
    (AuditLog, ["id", "created_at"]),
]

# Single PK FK models
SINGLE_FK_PK_MODELS = [
    (AgentRun, "execution_id"),
]

# Identity PK (bigint auto) models
IDENTITY_PK_MODELS = [
    (AssetDiscovery, "id"),
    (FindingStateTransition, "id"),
    (OutboxEvent, "id"),
    (CostEntry, "id"),
]


class TestPrimaryKeys:
    """Verify all primary key configurations are correct."""

    @pytest.mark.parametrize("model_cls", UUID_PK_MODELS)
    def test_uuid_pk(self, model_cls: Any) -> None:
        mapper: Any = inspect(model_cls)
        pk_cols = mapper.primary_key
        assert len(pk_cols) == 1
        assert pk_cols[0].name == "id"

    @pytest.mark.parametrize("model_cls", ASSET_SUBTYPE_MODELS)
    def test_asset_subtype_pk(self, model_cls: Any) -> None:
        mapper: Any = inspect(model_cls)
        pk_cols = mapper.primary_key
        assert len(pk_cols) == 1
        assert pk_cols[0].name == "asset_id"

    @pytest.mark.parametrize("model_cls, pk_names", COMPOSITE_PK_MODELS)
    def test_composite_pk(self, model_cls: Any, pk_names: list[str]) -> None:
        mapper: Any = inspect(model_cls)
        pk_cols = mapper.primary_key
        actual_names = [c.name for c in pk_cols]
        assert actual_names == pk_names

    @pytest.mark.parametrize("model_cls, pk_name", SINGLE_FK_PK_MODELS)
    def test_single_fk_pk(self, model_cls: Any, pk_name: str) -> None:
        mapper: Any = inspect(model_cls)
        pk_cols = mapper.primary_key
        assert len(pk_cols) == 1
        assert pk_cols[0].name == pk_name


# ─── Column Presence Spot-Checks ───────────────────────────────────


class TestColumnPresence:
    """Spot-check that critical columns exist on key models."""

    def test_user_has_email(self) -> None:
        cols = {c.name for c in User.__table__.columns}
        assert "email" in cols

    def test_user_has_password_hash(self) -> None:
        cols = {c.name for c in User.__table__.columns}
        assert "password_hash" in cols

    def test_project_has_slug(self) -> None:
        cols = {c.name for c in Project.__table__.columns}
        assert "slug" in cols

    def test_project_has_owner_id(self) -> None:
        cols = {c.name for c in Project.__table__.columns}
        assert "owner_id" in cols

    def test_scan_has_budget(self) -> None:
        cols = {c.name for c in Scan.__table__.columns}
        assert "budget" in cols

    def test_scan_has_scope_version_id(self) -> None:
        cols = {c.name for c in Scan.__table__.columns}
        assert "scope_version_id" in cols

    def test_finding_has_fingerprint(self) -> None:
        cols = {c.name for c in Finding.__table__.columns}
        assert "fingerprint" in cols

    def test_finding_cluster_has_confidence_score(self) -> None:
        cols = {c.name for c in FindingCluster.__table__.columns}
        assert "confidence_score" in cols

    def test_evidence_object_has_sha256(self) -> None:
        cols = {c.name for c in EvidenceObject.__table__.columns}
        assert "sha256" in cols

    def test_tool_execution_has_cost_usd(self) -> None:
        cols = {c.name for c in ToolExecution.__table__.columns}
        assert "cost_usd" in cols

    def test_ai_invocation_has_request_hash(self) -> None:
        cols = {c.name for c in AIInvocation.__table__.columns}
        assert "request_hash" in cols

    def test_audit_log_has_actor_type(self) -> None:
        cols = {c.name for c in AuditLog.__table__.columns}
        assert "actor_type" in cols

    def test_auth_context_has_identity_type(self) -> None:
        cols = {c.name for c in AuthContext.__table__.columns}
        assert "identity_type" in cols

    def test_secret_ref_has_backend(self) -> None:
        cols = {c.name for c in SecretRef.__table__.columns}
        assert "backend" in cols


# ─── Partitioned Tables ────────────────────────────────────────────


class TestPartitionedTables:
    """Verify that partitioned tables have correct table_args."""

    def test_scope_decisions_partitioned(self) -> None:
        args = ScopeDecision.__table_args__
        # Check for postgresql_partition_by in the dict part of __table_args__
        partition_config = None
        for arg in args:
            if isinstance(arg, dict) and "postgresql_partition_by" in arg:
                partition_config = arg["postgresql_partition_by"]
                break
        assert partition_config is not None
        assert "decided_at" in partition_config

    def test_http_exchanges_partitioned(self) -> None:
        args = HTTPExchange.__table_args__
        partition_config = None
        for arg in args:
            if isinstance(arg, dict) and "postgresql_partition_by" in arg:
                partition_config = arg["postgresql_partition_by"]
                break
        assert partition_config is not None
        assert "occurred_at" in partition_config

    def test_audit_logs_partitioned(self) -> None:
        args = AuditLog.__table_args__
        partition_config = None
        for arg in args:
            if isinstance(arg, dict) and "postgresql_partition_by" in arg:
                partition_config = arg["postgresql_partition_by"]
                break
        assert partition_config is not None
        assert "created_at" in partition_config


# ─── Relationship Presence ──────────────────────────────────────────


class TestRelationships:
    """Spot-check that critical relationships are defined."""

    def test_project_has_owner_relationship(self) -> None:
        mapper = inspect(Project)
        rel_names = {r.key for r in mapper.relationships}
        assert "owner" in rel_names

    def test_finding_cluster_has_findings(self) -> None:
        mapper = inspect(FindingCluster)
        rel_names = {r.key for r in mapper.relationships}
        assert "findings" in rel_names

    def test_finding_has_cluster(self) -> None:
        mapper = inspect(Finding)
        rel_names = {r.key for r in mapper.relationships}
        assert "cluster" in rel_names

    def test_validation_has_checks(self) -> None:
        mapper = inspect(Validation)
        rel_names = {r.key for r in mapper.relationships}
        assert "checks" in rel_names

    def test_ai_provider_has_models(self) -> None:
        mapper = inspect(AIProvider)
        rel_names = {r.key for r in mapper.relationships}
        assert "models" in rel_names

    def test_tool_has_versions(self) -> None:
        mapper = inspect(Tool)
        rel_names = {r.key for r in mapper.relationships}
        assert "versions" in rel_names
