"""SQLAlchemy models for evidence objects and HTTP exchanges.

Storage rule:
- Raw evidence never lives in PostgreSQL. EvidenceObject stores metadata and S3 references.
- HTTPExchange stores bounded request/response telemetry, referencing EvidenceObjects
  for payload bodies.
- http_exchanges is partitioned by range on occurred_at.
"""

from __future__ import annotations

import datetime
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7

if TYPE_CHECKING:
    from backend.app.db.models.assets import Endpoint
    from backend.app.db.models.execution import Scan, ToolExecution
    from backend.app.db.models.identity import Project


class EvidenceObject(Base):
    """Metadata record for raw evidence objects stored in S3-compatible storage.

    Content addressed by SHA-256 within project scope. Immutable.
    """

    __tablename__ = "evidence_objects"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('http_request','http_response','screenshot','tool_output',"
            "'agent_transcript','report','authorization_document','api_spec','other')",
            name="ck_evidence_objects_kind",
        ),
        CheckConstraint(
            "encryption_mode IN ('sse-s3','sse-kms','client_envelope')",
            name="ck_evidence_objects_encryption_mode",
        ),
        CheckConstraint(
            "redaction_status IN ('pending','redacted','not_required','failed')",
            name="ck_evidence_objects_redaction_status",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_evidence_objects_size_bytes_non_negative"),
        UniqueConstraint(
            "project_id", "sha256", "kind", name="uq_evidence_objects_project_sha_kind"
        ),
        Index(
            "ix_evidence_objects_retention_active",
            "retention_until",
            postgresql_where="deleted_at IS NULL",
        ),
        Index("ix_evidence_objects_project_id", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    storage_backend: Mapped[str] = mapped_column(String(20), nullable=False, default="s3")
    bucket: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    encryption_mode: Mapped[str] = mapped_column(String(50), nullable=False, default="sse-kms")
    encryption_key_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    redaction_status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    retention_until: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_by_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_executions.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    deleted_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    created_by_execution: Mapped[ToolExecution | None] = relationship(
        "ToolExecution",
        foreign_keys=[created_by_execution_id],
    )


class HTTPExchange(Base):
    """Bounded request/response telemetry recorded during scans, discovery, and validations.

    Partitioned by RANGE on occurred_at (monthly).
    """

    __tablename__ = "http_exchanges"
    __table_args__ = (
        Index("ix_http_exchanges_project_occurred", "project_id", "occurred_at"),
        Index("ix_http_exchanges_scan_id", "scan_id"),
        {"postgresql_partition_by": "RANGE (occurred_at)"},
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
    )
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
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tool_executions.id", ondelete="SET NULL"),
        nullable=True,
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.asset_id", ondelete="SET NULL"),
        nullable=True,
    )
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    url_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    request_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    response_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redirect_chain: Mapped[list[Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default="[]",
    )
    tls: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    scan: Mapped[Scan] = relationship("Scan", foreign_keys=[scan_id])
    tool_execution: Mapped[ToolExecution | None] = relationship(
        "ToolExecution",
        foreign_keys=[tool_execution_id],
    )
    endpoint: Mapped[Endpoint | None] = relationship("Endpoint", foreign_keys=[endpoint_id])
    request_evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject",
        foreign_keys=[request_evidence_id],
    )
    response_evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject",
        foreign_keys=[response_evidence_id],
    )
