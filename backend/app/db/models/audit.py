"""SQLAlchemy models for audit logs, transactional outbox events, and cost accounting.

Platform integrity rules:
- `audit_logs` is append-only, partitioned by range on created_at, and captures actor provenance.
- `outbox_events` implements the transactional outbox pattern for guaranteed event delivery.
- `cost_entries` aggregates dollar costs across compute, AI tokens, storage, and network.
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
    Identity,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now

if TYPE_CHECKING:
    from backend.app.db.models.execution import Scan
    from backend.app.db.models.identity import Project


class AuditLog(Base):
    """Immutable audit trail for all security-relevant mutations and operations.

    Partitioned by RANGE on created_at (monthly).
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('user','api_key','system','worker','model')",
            name="ck_audit_logs_actor_type",
        ),
        Index("ix_audit_logs_project_created", "project_id", "created_at"),
        Index("ix_audit_logs_actor", "actor_type", "actor_id"),
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
        default=utc_now,
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    before_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    after_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Relationships
    project: Mapped[Project | None] = relationship("Project", foreign_keys=[project_id])


class OutboxEvent(Base):
    """Transactional outbox event relay for reliable asynchronous messaging."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        Index(
            "ix_outbox_events_unpublished",
            "created_at",
            postgresql_where="published_at IS NULL",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    aggregate_type: Mapped[str] = mapped_column(String(100), nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    published_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CostEntry(Base):
    """Granular cost attribution entry tracking expenses across tools, AI models, and storage."""

    __tablename__ = "cost_entries"
    __table_args__ = (
        CheckConstraint(
            "category IN ('tool_compute','ai_tokens','storage','network','other')",
            name="ck_cost_entries_category",
        ),
        Index("ix_cost_entries_project_created", "project_id", "created_at"),
        Index("ix_cost_entries_scan_category", "scan_id", "category"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    amount_usd: Mapped[decimal.Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    quantity: Mapped[decimal.Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    unit: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reference_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reference_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    scan: Mapped[Scan | None] = relationship("Scan", foreign_keys=[scan_id])
