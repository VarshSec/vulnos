"""SQLAlchemy models for Assets, Reconnaissance, Discovery, and Intelligence.

Covers tables:
- assets
- domains
- hosts
- host_addresses
- services
- endpoints
- parameters
- technologies
- asset_technologies
- api_schemas
- asset_discoveries
"""

import uuid
from datetime import datetime
from decimal import Decimal
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
    Numeric,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base
from backend.app.db.types import utc_now, uuid7


class Asset(Base):
    """Canonical asset identity (domain, host, service, endpoint, repository)."""

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_key: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(4, 3), nullable=False, default=Decimal("1.000")
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('domain', 'host', 'service', 'endpoint', 'repository')",
            name="ck_assets_kind",
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_assets_confidence"),
        UniqueConstraint("project_id", "kind", "canonical_key", name="uq_assets_project_kind_key"),
        Index("ix_assets_project_last_seen", "project_id", "last_seen_at"),
    )

    domain_detail: Mapped["Domain | None"] = relationship(
        "Domain", back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    host_detail: Mapped["Host | None"] = relationship(
        "Host", back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    service_detail: Mapped["Service | None"] = relationship(
        "Service",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="Service.asset_id",
    )
    endpoint_detail: Mapped["Endpoint | None"] = relationship(
        "Endpoint",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="Endpoint.asset_id",
    )
    discoveries: Mapped[list["AssetDiscovery"]] = relationship(
        "AssetDiscovery", back_populates="asset", cascade="all, delete-orphan"
    )


class Domain(Base):
    """Domain detail extending assets."""

    __tablename__ = "domains"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    registrable_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_domain: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_domains_project_name"),)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="domain_detail")


class Host(Base):
    """Host detail extending assets."""

    __tablename__ = "hosts"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False)
    host_kind: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint("host_kind IN ('hostname', 'ip')", name="ck_hosts_host_kind"),
        UniqueConstraint("project_id", "canonical_name", name="uq_hosts_project_canonical_name"),
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="host_detail")
    addresses: Mapped[list["HostAddress"]] = relationship(
        "HostAddress", back_populates="host", cascade="all, delete-orphan"
    )
    services: Mapped[list["Service"]] = relationship(
        "Service", back_populates="host", cascade="all, delete-orphan"
    )


class HostAddress(Base):
    """DNS resolution history mapping hosts to IP addresses."""

    __tablename__ = "host_addresses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    ip: Mapped[Any] = mapped_column(INET, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    last_tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (UniqueConstraint("host_id", "ip", name="uq_host_addresses_host_ip"),)

    host: Mapped["Host"] = relationship("Host", back_populates="addresses")


class Service(Base):
    """Network port and transport service detail extending assets."""

    __tablename__ = "services"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    transport: Mapped[str] = mapped_column(Text, nullable=False)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_services_port_range"),
        CheckConstraint("transport IN ('tcp', 'udp')", name="ck_services_transport"),
        CheckConstraint(
            "state IN ('open', 'filtered', 'closed', 'unknown')", name="ck_services_state"
        ),
        UniqueConstraint("host_id", "port", "transport", name="uq_services_host_port_transport"),
    )

    asset: Mapped["Asset"] = relationship(
        "Asset", back_populates="service_detail", foreign_keys=[asset_id]
    )
    host: Mapped["Host"] = relationship("Host", back_populates="services")
    endpoints: Mapped[list["Endpoint"]] = relationship("Endpoint", back_populates="service")


class Endpoint(Base):
    """HTTP/API endpoint detail extending assets."""

    __tablename__ = "endpoints"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosts.asset_id"), nullable=False
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("services.asset_id"), nullable=True
    )
    method: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(Text, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    query_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    path_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    auth_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    content_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT')",
            name="ck_endpoints_method",
        ),
        CheckConstraint("scheme IN ('http','https')", name="ck_endpoints_scheme"),
        UniqueConstraint(
            "project_id", "method", "url_hash", name="uq_endpoints_project_method_url_hash"
        ),
        Index("ix_endpoints_project_host", "project_id", "host_id"),
    )

    asset: Mapped["Asset"] = relationship(
        "Asset", back_populates="endpoint_detail", foreign_keys=[asset_id]
    )
    service: Mapped["Service | None"] = relationship("Service", back_populates="endpoints")
    parameters: Mapped[list["Parameter"]] = relationship(
        "Parameter", back_populates="endpoint", cascade="all, delete-orphan"
    )


class Parameter(Base):
    """Parameters detected on endpoints."""

    __tablename__ = "parameters"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    location: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    data_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    sample_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "location IN ('query','path','header','cookie','body_json','body_form','graphql_arg')",
            name="ck_parameters_location",
        ),
        UniqueConstraint(
            "endpoint_id", "location", "name", name="uq_parameters_endpoint_location_name"
        ),
    )

    endpoint: Mapped["Endpoint"] = relationship("Endpoint", back_populates="parameters")


class Technology(Base):
    """Reusable technology catalog item."""

    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (UniqueConstraint("name", "category", name="uq_technologies_name_category"),)


class AssetTechnology(Base):
    """Technology fingerprint detected on an asset."""

    __tablename__ = "asset_technologies"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    technology_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("technologies.id"),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    version: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(4, 3), nullable=False, default=Decimal("1.000")
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class APISchema(Base):
    """Imported API specification schemas (OpenAPI, GraphQL, Postman, HAR)."""

    __tablename__ = "api_schemas"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    schema_type: Mapped[str] = mapped_column(Text, nullable=False)
    version_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    spec_evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    spec_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    operation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "schema_type IN ('openapi','graphql','postman','har')",
            name="ck_api_schemas_schema_type",
        ),
        UniqueConstraint(
            "project_id",
            "asset_id",
            "schema_type",
            "spec_hash",
            name="uq_api_schemas_project_asset_type_hash",
        ),
    )


class AssetDiscovery(Base):
    """Append-only observation provenance for assets."""

    __tablename__ = "asset_discoveries"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(4, 3), nullable=False, default=Decimal("1.000")
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_asset_discoveries_asset_discovered", "asset_id", "discovered_at"),
        Index("ix_asset_discoveries_scan_id", "scan_id"),
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="discoveries")
