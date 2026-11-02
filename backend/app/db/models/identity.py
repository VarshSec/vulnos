"""SQLAlchemy models for Identity, Tenancy, Authorization, and Scope.

Covers tables:
- users
- api_keys
- projects
- project_members
- authorization_records
- scope_versions
- scope_rules
- scope_decisions (Partitioned)
- targets
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, INT4RANGE, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7


class User(Base):
    """Human user identities across the platform."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_provider: Mapped[str] = mapped_column(Text, nullable=False, default="local")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "auth_provider IN ('local', 'oidc')",
            name="ck_users_auth_provider",
        ),
    )

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey", back_populates="user", cascade="all, delete-orphan"
    )
    owned_projects: Mapped[list["Project"]] = relationship("Project", back_populates="owner")
    memberships: Mapped[list["ProjectMember"]] = relationship(
        "ProjectMember", back_populates="user", cascade="all, delete-orphan"
    )


class APIKey(Base):
    """Machine credentials bound to users."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    key_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")


class Project(Base):
    """Top-level tenancy and isolation boundary."""

    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    default_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("slug", name="uq_projects_slug"),
        CheckConstraint(
            "status IN ('active', 'archived')",
            name="ck_projects_status",
        ),
        CheckConstraint(
            "default_retention_days BETWEEN 1 AND 3650",
            name="ck_projects_default_retention_days",
        ),
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="owned_projects")
    members: Mapped[list["ProjectMember"]] = relationship(
        "ProjectMember", back_populates="project", cascade="all, delete-orphan"
    )
    authorizations: Mapped[list["AuthorizationRecord"]] = relationship(
        "AuthorizationRecord", back_populates="project", cascade="all, delete-orphan"
    )
    scope_versions: Mapped[list["ScopeVersion"]] = relationship(
        "ScopeVersion", back_populates="project", cascade="all, delete-orphan"
    )
    targets: Mapped[list["Target"]] = relationship(
        "Target", back_populates="project", cascade="all, delete-orphan"
    )


class ProjectMember(Base):
    """Association of users to projects with designated RBAC roles."""

    __tablename__ = "project_members"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    role: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'operator', 'viewer')",
            name="ck_project_members_role",
        ),
    )

    project: Mapped["Project"] = relationship("Project", back_populates="members")
    user: Mapped["User"] = relationship("User", back_populates="memberships")


class AuthorizationRecord(Base):
    """Legal/contractual scope authorization."""

    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reference: Mapped[str] = mapped_column(Text, nullable=False)
    document_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    authorized_by_name: Mapped[str] = mapped_column(Text, nullable=False)
    authorized_by_contact: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    destructive_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_private_ranges: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_requests_per_scan: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("valid_to > valid_from", name="ck_authorization_records_validity_window"),
    )

    project: Mapped["Project"] = relationship("Project", back_populates="authorizations")
    scope_versions: Mapped[list["ScopeVersion"]] = relationship(
        "ScopeVersion", back_populates="authorization"
    )


class ScopeVersion(Base):
    """Immutable versioned scope policy snapshots."""

    __tablename__ = "scope_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorization_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("version > 0", name="ck_scope_versions_positive_version"),
        CheckConstraint(
            "status IN ('draft', 'active', 'superseded')",
            name="ck_scope_versions_status",
        ),
        UniqueConstraint("project_id", "version", name="uq_scope_versions_project_version"),
        Index(
            "uq_scope_active",
            "project_id",
            unique=True,
            postgresql_where="status = 'active'",
            sqlite_where=text("status = 'active'"),
        ),
    )

    project: Mapped["Project"] = relationship("Project", back_populates="scope_versions")
    authorization: Mapped["AuthorizationRecord"] = relationship(
        "AuthorizationRecord", back_populates="scope_versions"
    )
    rules: Mapped[list["ScopeRule"]] = relationship(
        "ScopeRule", back_populates="scope_version", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    """Allow or deny scope policy rule within a scope version."""

    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scope_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    effect: Mapped[str] = mapped_column(Text, nullable=False)
    match_type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ports: Mapped[Any | None] = mapped_column(INT4RANGE, nullable=True)
    protocols: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint("effect IN ('allow', 'deny')", name="ck_scope_rules_effect"),
        CheckConstraint(
            "match_type IN ('exact_url', 'url_prefix', 'exact_host', 'domain_suffix', "
            "'wildcard_domain', 'ip', 'cidr')",
            name="ck_scope_rules_match_type",
        ),
        Index("ix_scope_rules_version_effect", "scope_version_id", "effect"),
    )

    scope_version: Mapped["ScopeVersion"] = relationship("ScopeVersion", back_populates="rules")


class ScopeDecision(Base):
    """Append-only audit of per-request scope authorization decisions (Partitioned)."""

    __tablename__ = "scope_decisions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_versions.id"), nullable=False
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("authorization_records.id"), nullable=False
    )
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason_code: Mapped[str] = mapped_column(Text, nullable=False)
    matched_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_rules.id"), nullable=True
    )
    resolved_ips: Mapped[list[Any]] = mapped_column(ARRAY(INET), nullable=False, default=list)
    policy_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        PrimaryKeyConstraint("id", "decided_at", name="pk_scope_decisions"),
        Index("ix_scope_decisions_proj_decided", "project_id", "decided_at"),
        Index("ix_scope_decisions_scan_id", "scan_id"),
        {"postgresql_partition_by": "RANGE (decided_at)"},
    )


class Target(Base):
    """Operator-provided target seeds for discovery and scope evaluation."""

    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    seed_type: Mapped[str] = mapped_column(Text, nullable=False)
    seed_value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "seed_type IN ('domain', 'host', 'ip', 'url', 'api_base', 'repository')",
            name="ck_targets_seed_type",
        ),
        CheckConstraint("status IN ('active', 'archived')", name="ck_targets_status"),
        UniqueConstraint(
            "project_id", "seed_type", "seed_value", name="uq_targets_project_seed_type_value"
        ),
        Index("ix_targets_project_status", "project_id", "status"),
    )

    project: Mapped["Project"] = relationship("Project", back_populates="targets")
