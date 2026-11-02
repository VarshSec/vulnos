"""SQLAlchemy models for raw findings, clusters, evidence attachments, and cluster relations.

Finding lifecycle rules:
- Scanners and agents output hypotheses, recorded in `findings`.
- Findings are correlated into `finding_clusters`.
- `finding_clusters` tracks triage, confidence factors, and lifecycle status.
- `cluster_relations` links duplicate candidates, conflicts, and shared endpoints.
"""

from __future__ import annotations

import datetime
import decimal
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7

if TYPE_CHECKING:
    from backend.app.db.models.assets import Asset, Endpoint, Parameter
    from backend.app.db.models.evidence import EvidenceObject
    from backend.app.db.models.execution import AgentRun, ToolVersion
    from backend.app.db.models.identity import Project, User
    from backend.app.db.models.security import AuthContext


class FindingCluster(Base):
    """Correlated cluster of findings representing a distinct vulnerability hypothesis."""

    __tablename__ = "finding_clusters"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_finding_clusters_severity",
        ),
        CheckConstraint(
            "status IN ('detected','needs_validation','validated','rejected','report_ready')",
            name="ck_finding_clusters_status",
        ),
        CheckConstraint(
            "confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 100)",
            name="ck_finding_clusters_confidence_score_range",
        ),
        UniqueConstraint(
            "project_id", "canonical_key", name="uq_finding_clusters_project_canonical_key"
        ),
        Index("ix_finding_clusters_project_status_sev", "project_id", "status", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    canonical_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="detected")
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
        nullable=True,
    )
    parameter_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parameters.id", ondelete="SET NULL"),
        nullable=True,
    )
    auth_context_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth_contexts.id", ondelete="SET NULL"),
        nullable=True,
    )
    first_detected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    validated_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    report_ready_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    confidence_score: Mapped[decimal.Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    confidence_factors: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    asset: Mapped[Asset] = relationship("Asset", foreign_keys=[asset_id])
    endpoint: Mapped[Endpoint | None] = relationship("Endpoint", foreign_keys=[endpoint_id])
    parameter: Mapped[Parameter | None] = relationship("Parameter", foreign_keys=[parameter_id])
    auth_context: Mapped[AuthContext | None] = relationship(
        "AuthContext", foreign_keys=[auth_context_id]
    )
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="cluster")


class Finding(Base):
    """Raw vulnerability occurrence reported by a tool, agent, or import."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('scanner','agent','static','import','manual','ai')",
            name="ck_findings_source_type",
        ),
        CheckConstraint(
            "status IN ('new','correlated','duplicate','suppressed')",
            name="ck_findings_status",
        ),
        Index("ix_findings_project_cluster", "project_id", "cluster_id"),
        Index("ix_findings_fingerprint", "fingerprint"),
        Index("ix_findings_project_detected", "project_id", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    source_tool_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_runs.execution_id", ondelete="SET NULL"),
        nullable=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
        nullable=True,
    )
    parameter_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parameters.id", ondelete="SET NULL"),
        nullable=True,
    )
    vulnerability_class: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity_claimed: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence_claimed: Mapped[decimal.Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_output_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    detected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new")
    fingerprint: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    cluster: Mapped[FindingCluster | None] = relationship(
        "FindingCluster", back_populates="findings"
    )
    source_tool_version: Mapped[ToolVersion | None] = relationship(
        "ToolVersion",
        foreign_keys=[source_tool_version_id],
    )
    agent_run: Mapped[AgentRun | None] = relationship("AgentRun", foreign_keys=[agent_run_id])
    asset: Mapped[Asset] = relationship("Asset", foreign_keys=[asset_id])
    endpoint: Mapped[Endpoint | None] = relationship("Endpoint", foreign_keys=[endpoint_id])
    parameter: Mapped[Parameter | None] = relationship("Parameter", foreign_keys=[parameter_id])
    raw_output_evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject",
        foreign_keys=[raw_output_evidence_id],
    )


class FindingEvidence(Base):
    """Associates evidence objects with findings or correlated clusters under specific roles."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        CheckConstraint(
            "cluster_id IS NOT NULL OR finding_id IS NOT NULL",
            name="ck_finding_evidence_target_present",
        ),
        CheckConstraint(
            "role IN ('request','response','poc','screenshot','log',"
            "'transcript','control','document','other')",
            name="ck_finding_evidence_role",
        ),
        Index(
            "uq_finding_evidence_finding_role",
            "finding_id",
            "evidence_id",
            "role",
            unique=True,
            postgresql_where="finding_id IS NOT NULL",
        ),
        Index(
            "uq_finding_evidence_cluster_role",
            "cluster_id",
            "evidence_id",
            "role",
            unique=True,
            postgresql_where="cluster_id IS NOT NULL",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="CASCADE"),
        nullable=True,
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=True,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    cluster: Mapped[FindingCluster | None] = relationship(
        "FindingCluster", foreign_keys=[cluster_id]
    )
    finding: Mapped[Finding | None] = relationship("Finding", foreign_keys=[finding_id])
    evidence: Mapped[EvidenceObject] = relationship("EvidenceObject", foreign_keys=[evidence_id])


class ClusterRelation(Base):
    """Explicit relationship between finding clusters (duplicates, conflicts, endpoint overlap)."""

    __tablename__ = "cluster_relations"
    __table_args__ = (
        CheckConstraint(
            "from_cluster_id <> to_cluster_id", name="ck_cluster_relations_no_self_ref"
        ),
        CheckConstraint(
            "relation_type IN ('duplicate_candidate','related','shares_endpoint','conflict')",
            name="ck_cluster_relations_relation_type",
        ),
        UniqueConstraint(
            "from_cluster_id",
            "to_cluster_id",
            "relation_type",
            name="uq_cluster_relations_from_to_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    to_cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    relation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[decimal.Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    from_cluster: Mapped[FindingCluster] = relationship(
        "FindingCluster", foreign_keys=[from_cluster_id]
    )
    to_cluster: Mapped[FindingCluster] = relationship(
        "FindingCluster", foreign_keys=[to_cluster_id]
    )
    reviewer: Mapped[User | None] = relationship("User", foreign_keys=[reviewed_by])
