"""SQLAlchemy models for Tool Catalog, Execution, Scans, and Agent Runs.

Covers tables:
- tools
- tool_versions
- tool_capabilities
- scans
- scan_stage_runs
- tool_executions
- tool_selection_decisions
- agent_runs
- test_cases
- operation_approvals
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7


class Tool(Base):
    """Tool catalog record."""

    __tablename__ = "tools"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    upstream_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    license: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    maintenance_status: Mapped[str] = mapped_column(Text, nullable=False, default="unknown")
    default_image: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "category IN ('recon','discovery','scanner','api','agent','sast','secrets','sca')",
            name="ck_tools_category",
        ),
        CheckConstraint(
            "maintenance_status IN ('active','maintenance','stale','unknown','abandoned')",
            name="ck_tools_maintenance_status",
        ),
    )

    versions: Mapped[list["ToolVersion"]] = relationship(
        "ToolVersion", back_populates="tool", cascade="all, delete-orphan"
    )


class ToolVersion(Base):
    """Pinned tool versions with image digests and verification state."""

    __tablename__ = "tool_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    tool_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[str] = mapped_column(Text, nullable=False)
    image_ref: Mapped[str] = mapped_column(Text, nullable=False)
    image_digest: Mapped[str] = mapped_column(Text, nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False, default="declared")
    capabilities_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "verification_status IN ('declared','smoke_tested','contract_tested',"
            "'production_verified','quarantined')",
            name="ck_tool_versions_verification_status",
        ),
        UniqueConstraint(
            "tool_id", "version", "image_digest", name="uq_tool_versions_tool_version_digest"
        ),
    )

    tool: Mapped["Tool"] = relationship("Tool", back_populates="versions")
    capabilities: Mapped["ToolCapability | None"] = relationship(
        "ToolCapability", back_populates="tool_version", uselist=False, cascade="all, delete-orphan"
    )


class ToolCapability(Base):
    """Declared capabilities, safety flags, and overlap groups for TISE."""

    __tablename__ = "tool_capabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    tool_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_versions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    vulnerability_classes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list
    )
    target_types: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    required_inputs: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    install_requirements: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list
    )
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    output_formats: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    auth_support: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    passive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state_changing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    destructive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cost_tier: Mapped[str] = mapped_column(Text, nullable=False, default="low")
    expected_duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    overlap_group: Mapped[str] = mapped_column(Text, nullable=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint("passive OR active", name="ck_tool_capabilities_passive_or_active"),
        CheckConstraint(
            "NOT destructive OR requires_approval",
            name="ck_tool_capabilities_destructive_requires_approval",
        ),
        CheckConstraint(
            "cost_tier IN ('low','medium','high')", name="ck_tool_capabilities_cost_tier"
        ),
        Index("ix_tool_capabilities_overlap_group", "overlap_group"),
        Index("ix_tool_capabilities_vuln_classes", "vulnerability_classes", postgresql_using="gin"),
    )

    tool_version: Mapped["ToolVersion"] = relationship("ToolVersion", back_populates="capabilities")


class Scan(Base):
    """Scan execution unit pinning scope version and authorization."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    scan_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_versions.id"), nullable=False
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("authorization_records.id"), nullable=False
    )
    target_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False)
    profile: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False, default=Decimal("0"))
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "scan_type IN ('recon','discovery','web','api','agent','full','validation')",
            name="ck_scans_scan_type",
        ),
        CheckConstraint(
            "status IN ('draft','queued','running','paused','completed','failed','cancelled')",
            name="ck_scans_status",
        ),
        Index("ix_scans_project_status", "project_id", "status"),
        Index("ix_scans_project_created", "project_id", "created_at"),
    )

    stage_runs: Mapped[list["ScanStageRun"]] = relationship(
        "ScanStageRun", back_populates="scan", cascade="all, delete-orphan"
    )
    executions: Mapped[list["ToolExecution"]] = relationship(
        "ToolExecution", back_populates="scan", cascade="all, delete-orphan"
    )


class ScanStageRun(Base):
    """Recorded stage attempts and metrics within a scan."""

    __tablename__ = "scan_stage_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint("attempt > 0", name="ck_scan_stage_runs_positive_attempt"),
        CheckConstraint(
            "stage IN ('scope','recon','discovery','selection','scanning','agent',"
            "'correlation','investigation','validation','reporting')",
            name="ck_scan_stage_runs_stage",
        ),
        CheckConstraint(
            "status IN ('pending','running','succeeded','partial','failed','skipped','cancelled')",
            name="ck_scan_stage_runs_status",
        ),
        UniqueConstraint(
            "scan_id", "stage", "attempt", name="uq_scan_stage_runs_scan_stage_attempt"
        ),
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="stage_runs")


class ToolExecution(Base):
    """Individual container execution of a scanner or agent job."""

    __tablename__ = "tool_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    tool_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tool_versions.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    target_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.asset_id"), nullable=True
    )
    auth_context_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    input: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    command_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tool_executions.id"), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    coverage_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False, default=Decimal("0"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','succeeded','failed','timeout','cancelled',"
            "'skipped','scope_violation')",
            name="ck_tool_executions_status",
        ),
        Index("ix_tool_executions_scan_status", "scan_id", "status"),
        Index("ix_tool_executions_project_created", "project_id", "created_at"),
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="executions")
    agent_run: Mapped["AgentRun | None"] = relationship(
        "AgentRun", back_populates="execution", uselist=False, cascade="all, delete-orphan"
    )


class ToolSelectionDecision(Base):
    """Explainable selection and suppression rationale from TISE."""

    __tablename__ = "tool_selection_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tool_versions.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    reason_code: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    coverage_gap: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    budget_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint("decision IN ('selected','skipped')", name="ck_tool_selection_decision"),
        Index("ix_tool_selection_scan_decision", "scan_id", "decision"),
    )


class AgentRun(Base):
    """Autonomous agent run execution state extending tool_executions."""

    __tablename__ = "agent_runs"

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_executions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    agent_name: Mapped[str] = mapped_column(Text, nullable=False)
    agent_version: Mapped[str] = mapped_column(Text, nullable=False)
    model_provider: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sandbox_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    transcript_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','succeeded','failed','timeout','cancelled',"
            "'scope_violation')",
            name="ck_agent_runs_status",
        ),
        Index(
            "uq_agent_active_per_target",
            "project_id",
            "target_asset_id",
            unique=True,
            postgresql_where="status IN ('queued', 'running')",
        ),
    )

    execution: Mapped["ToolExecution"] = relationship("ToolExecution", back_populates="agent_run")


class TestCase(Base):
    """Coverage units preventing redundant testing across tools."""

    __test__ = False
    __tablename__ = "test_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.asset_id"), nullable=False
    )
    vulnerability_class: Mapped[str] = mapped_column(Text, nullable=False)
    auth_context_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    coverage_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="planned")
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tool_executions.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('planned','running','tested','not_applicable','error','skipped')",
            name="ck_test_cases_status",
        ),
        UniqueConstraint("scan_id", "coverage_key", name="uq_test_cases_scan_coverage_key"),
        Index(
            "ix_test_cases_proj_endpoint_vuln",
            "project_id",
            "endpoint_id",
            "vulnerability_class",
        ),
    )


class OperationApproval(Base):
    """Human approvals required for destructive or state-changing operations."""

    __tablename__ = "operation_approvals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    action_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    action_description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tool_executions.id"), nullable=True
    )
    approved_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "risk_level IN ('state_changing','destructive')",
            name="ck_operation_approvals_risk_level",
        ),
        CheckConstraint(
            "expires_at > approved_at",
            name="ck_operation_approvals_validity",
        ),
        UniqueConstraint("scan_id", "action_hash", name="uq_operation_approvals_scan_action_hash"),
    )
