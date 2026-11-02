"""SQLAlchemy models for validation workflows, checks, state transitions, and reports.

Validation rules:
- Findings cannot skip the validation lifecycle.
- Validations execute mandatory gates before a finding transitions to 'validated'.
- Transitions append to `finding_state_transitions`.
- Reports are versioned, format-specific artifacts linked to scans.
"""

from __future__ import annotations

import datetime
import decimal
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7

if TYPE_CHECKING:
    from backend.app.db.models.ai import AIInvocation
    from backend.app.db.models.evidence import EvidenceObject
    from backend.app.db.models.execution import Scan, ToolExecution
    from backend.app.db.models.findings import FindingCluster
    from backend.app.db.models.identity import Project, User


class Validation(Base):
    """Independent controlled validation process for a finding cluster."""

    __tablename__ = "validations"
    __table_args__ = (
        CheckConstraint(
            "stage IN ('evidence_review','plan','controlled_validation',"
            "'independent_review','complete')",
            name="ck_validations_stage",
        ),
        CheckConstraint(
            "status IN ('pending','running','passed','failed','inconclusive','cancelled')",
            name="ck_validations_status",
        ),
        CheckConstraint(
            "reviewer_type IS NULL OR reviewer_type IN ('human','model')",
            name="ck_validations_reviewer_type",
        ),
        CheckConstraint(
            "verdict IS NULL OR verdict IN ('validated','rejected','needs_more_evidence')",
            name="ck_validations_verdict",
        ),
        Index("ix_validations_cluster_created", "cluster_id", "created_at"),
        Index("ix_validations_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    stage: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    performed_by_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_executions.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewer_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reviewer_model_invocation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_invocations.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewer_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[decimal.Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    started_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(
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
    cluster: Mapped[FindingCluster] = relationship("FindingCluster", foreign_keys=[cluster_id])
    requester: Mapped[User | None] = relationship("User", foreign_keys=[requested_by])
    performed_by_execution: Mapped[ToolExecution | None] = relationship(
        "ToolExecution",
        foreign_keys=[performed_by_execution_id],
    )
    reviewer_model_invocation: Mapped[AIInvocation | None] = relationship(
        "AIInvocation",
        foreign_keys=[reviewer_model_invocation_id],
    )
    reviewer_user: Mapped[User | None] = relationship("User", foreign_keys=[reviewer_user_id])
    checks: Mapped[list[ValidationCheck]] = relationship(
        "ValidationCheck", back_populates="validation"
    )


class ValidationCheck(Base):
    """Specific check or gate evaluated during validation (e.g. reproducibility, control test)."""

    __tablename__ = "validation_checks"
    __table_args__ = (
        CheckConstraint(
            "check_type IN ('scope','reproducibility','evidence_completeness','control_comparison',"
            "'impact','alternative_explanation','duplicate','independent_review','authorization_context')",
            name="ck_validation_checks_check_type",
        ),
        CheckConstraint(
            "result IN ('pass','fail','inconclusive','not_applicable')",
            name="ck_validation_checks_result",
        ),
        Index("ix_validation_checks_validation_type", "validation_id", "check_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    validation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("validations.id", ondelete="CASCADE"),
        nullable=False,
    )
    check_type: Mapped[str] = mapped_column(String(50), nullable=False)
    result: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    validation: Mapped[Validation] = relationship("Validation", back_populates="checks")
    evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject", foreign_keys=[evidence_id]
    )


class FindingStateTransition(Base):
    """Append-only lifecycle audit recording each transition of a finding cluster's status."""

    __tablename__ = "finding_state_transitions"
    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('user','system','model')",
            name="ck_finding_state_transitions_actor_type",
        ),
        Index("ix_finding_state_transitions_cluster_created", "cluster_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    validation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("validations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    cluster: Mapped[FindingCluster] = relationship("FindingCluster", foreign_keys=[cluster_id])
    validation: Mapped[Validation | None] = relationship("Validation", foreign_keys=[validation_id])


class Report(Base):
    """Versioned security report artifact generated from a scan and validated findings."""

    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("format IN ('markdown','json','pdf')", name="ck_reports_format"),
        CheckConstraint(
            "status IN ('queued','running','ready','failed')",
            name="ck_reports_status",
        ),
        CheckConstraint("version > 0", name="ck_reports_version_positive"),
        UniqueConstraint("scan_id", "version", "format", name="uq_reports_scan_version_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False)
    filters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    artifact_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    content_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    generated_at: Mapped[datetime.datetime | None] = mapped_column(
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
    scan: Mapped[Scan] = relationship("Scan", foreign_keys=[scan_id])
    artifact_evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject",
        foreign_keys=[artifact_evidence_id],
    )
    generator: Mapped[User | None] = relationship("User", foreign_keys=[generated_by])
