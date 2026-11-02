"""SQLAlchemy models for credentials, secrets references, and authentication contexts.

Security rules:
- SecretRef never stores actual secret material; only paths/names in the underlying provider.
- AuthContext holds non-secret metadata (roles, scopes, user labels) and references a SecretRef.
"""

from __future__ import annotations

import datetime
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7

if TYPE_CHECKING:
    from backend.app.db.models.identity import Project, User


class SecretRef(Base):
    """Reference to an externally stored secret (vault, aws secrets manager, env, etc).

    Contains NO plaintext or encrypted secret material.
    """

    __tablename__ = "secret_refs"
    __table_args__ = (
        CheckConstraint(
            "backend IN ('env','file','vault','aws_secrets_manager','gcp_secret_manager')",
            name="ck_secret_refs_backend",
        ),
        UniqueConstraint("project_id", "name", name="uq_secret_refs_project_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    backend: Mapped[str] = mapped_column(String(50), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    rotated_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    project: Mapped[Project | None] = relationship("Project", foreign_keys=[project_id])
    creator: Mapped[User] = relationship("User", foreign_keys=[created_by])


class AuthContext(Base):
    """Authentication and identity context for scans, test cases, and tool executions.

    Stores non-secret metadata (e.g. roles, token claims) and references an optional SecretRef.
    """

    __tablename__ = "auth_contexts"
    __table_args__ = (
        CheckConstraint(
            "identity_type IN ('anonymous','user','admin','service')",
            name="ck_auth_contexts_identity_type",
        ),
        UniqueConstraint("project_id", "label", name="uq_auth_contexts_project_label"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    secret_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("secret_refs.id", ondelete="SET NULL"),
        nullable=True,
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(
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
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    project: Mapped[Project] = relationship("Project", foreign_keys=[project_id])
    secret_ref: Mapped[SecretRef | None] = relationship("SecretRef", foreign_keys=[secret_ref_id])
