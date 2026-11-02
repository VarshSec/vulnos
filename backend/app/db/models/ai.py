"""SQLAlchemy models for AI model provider configurations, routing, prompts, and invocations.

AI architectural rules:
- AI models cannot independently confirm vulnerabilities.
- Invocations are tracked for cost, latency, token consumption, and auditability.
- Prompt templates are versioned with schema hashes.
- Routing policies enforce maximum token and dollar budgets.
"""

from __future__ import annotations

import datetime
import decimal
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
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
    from backend.app.db.models.evidence import EvidenceObject
    from backend.app.db.models.execution import Scan
    from backend.app.db.models.identity import Project
    from backend.app.db.models.security import SecretRef


class AIProvider(Base):
    """External or local AI model provider configuration."""

    __tablename__ = "ai_providers"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('openai_compatible','anthropic','google','local')",
            name="ck_ai_providers_kind",
        ),
        UniqueConstraint("name", name="uq_ai_providers_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    secret_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("secret_refs.id", ondelete="SET NULL"),
        nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(
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
    secret_ref: Mapped[SecretRef | None] = relationship("SecretRef", foreign_keys=[secret_ref_id])
    models: Mapped[list[AIModel]] = relationship("AIModel", back_populates="provider")


class AIModel(Base):
    """Specific model registered under a provider with price and context specifications."""

    __tablename__ = "ai_models"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active','degraded','disabled')",
            name="ck_ai_models_status",
        ),
        UniqueConstraint("provider_id", "model_id", name="uq_ai_models_provider_model_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    context_window: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    input_price_per_mtok: Mapped[decimal.Decimal | None] = mapped_column(
        Numeric(12, 6), nullable=True
    )
    output_price_per_mtok: Mapped[decimal.Decimal | None] = mapped_column(
        Numeric(12, 6), nullable=True
    )
    capabilities: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=list,
        server_default="{}",
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    provider: Mapped[AIProvider] = relationship("AIProvider", back_populates="models")


class PromptTemplate(Base):
    """Versioned prompt template with strict output schema definitions."""

    __tablename__ = "prompt_templates"
    __table_args__ = (
        CheckConstraint("version > 0", name="ck_prompt_templates_version_positive"),
        UniqueConstraint("name", "version", name="uq_prompt_templates_name_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    task_class: Mapped[str] = mapped_column(String(100), nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    output_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )


class AIRoutingPolicy(Base):
    """Policy defining model selection, fallback, token budget, and temperature per task class."""

    __tablename__ = "ai_routing_policies"
    __table_args__ = (
        CheckConstraint(
            "min_tier IN ('small','medium','strong')", name="ck_ai_routing_policies_min_tier"
        ),
        CheckConstraint(
            "temperature >= 0 AND temperature <= 2",
            name="ck_ai_routing_policies_temperature_range",
        ),
        UniqueConstraint("task_class", name="uq_ai_routing_policies_task_class"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    task_class: Mapped[str] = mapped_column(String(100), nullable=False)
    min_tier: Mapped[str] = mapped_column(String(20), nullable=False)
    preferred_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_models.id", ondelete="RESTRICT"),
        nullable=False,
    )
    fallback_model_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)),
        nullable=False,
        default=list,
        server_default="{}",
    )
    max_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    max_cost_usd: Mapped[decimal.Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    temperature: Mapped[decimal.Decimal] = mapped_column(
        Numeric(3, 2),
        nullable=False,
        default=decimal.Decimal("0.00"),
    )
    prompt_template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    # Relationships
    preferred_model: Mapped[AIModel] = relationship("AIModel", foreign_keys=[preferred_model_id])
    prompt_template: Mapped[PromptTemplate] = relationship(
        "PromptTemplate", foreign_keys=[prompt_template_id]
    )


class AIInvocation(Base):
    """Audit and telemetry record of an individual LLM/model request and response."""

    __tablename__ = "ai_invocations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('succeeded','failed','timeout','schema_error','budget_exceeded')",
            name="ck_ai_invocations_status",
        ),
        Index("ix_ai_invocations_project_created", "project_id", "created_at"),
        Index("ix_ai_invocations_scan_id", "scan_id"),
        Index("ix_ai_invocations_task_status", "task_class", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=True,
    )
    task_class: Mapped[str] = mapped_column(String(100), nullable=False)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_models.id", ondelete="RESTRICT"),
        nullable=False,
    )
    prompt_template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[decimal.Decimal] = mapped_column(
        Numeric(12, 6),
        nullable=False,
        default=decimal.Decimal("0.000000"),
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    response_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fallback_from_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_invocations.id", ondelete="SET NULL"),
        nullable=True,
    )
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    scan: Mapped[Scan | None] = relationship("Scan", foreign_keys=[scan_id])
    model: Mapped[AIModel] = relationship("AIModel", foreign_keys=[model_id])
    prompt_template: Mapped[PromptTemplate] = relationship(
        "PromptTemplate", foreign_keys=[prompt_template_id]
    )
    response_evidence: Mapped[EvidenceObject | None] = relationship(
        "EvidenceObject",
        foreign_keys=[response_evidence_id],
    )
