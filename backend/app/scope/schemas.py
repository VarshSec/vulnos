"""Pydantic schemas for target seeds and scope configuration in VulnOS."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.scope.normalization import (
    TargetType,
    normalize_domain,
    normalize_target,
)

# -----------------------------------------------------------------------------
# Authorization Vocabulary & Reason Codes
# -----------------------------------------------------------------------------

VALID_AUTHORIZATION_ACTIONS: Final[frozenset[str]] = frozenset(
    {"scan", "validate", "agent_run", "crawl", "reconnaissance", "probe", "fuzz"}
)


class AuthorizationReasonCode(StrEnum):
    """Decision reason codes for deterministic authorization evaluation."""

    VALID = "AUTHORIZATION_VALID"
    NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    NOT_YET_VALID = "AUTHORIZATION_NOT_YET_VALID"
    EXPIRED = "AUTHORIZATION_EXPIRED"
    REVOKED = "AUTHORIZATION_REVOKED"
    ACTION_NOT_ALLOWED = "AUTHORIZATION_ACTION_NOT_ALLOWED"
    DESTRUCTIVE_NOT_ALLOWED = "AUTHORIZATION_DESTRUCTIVE_NOT_ALLOWED"
    PRIVATE_RANGE_NOT_ALLOWED = "AUTHORIZATION_PRIVATE_RANGE_NOT_ALLOWED"
    INVALID = "AUTHORIZATION_INVALID"
    PROJECT_MISMATCH = "AUTHORIZATION_PROJECT_MISMATCH"


# -----------------------------------------------------------------------------
# Target Schemas
# -----------------------------------------------------------------------------


class TargetCreateRequest(BaseModel):
    """Request payload for creating a new target seed."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable name or label for the target.",
        examples=["Primary Production API"],
    )
    seed_type: TargetType = Field(
        ...,
        description="Type of target seed (domain, host, ip, url, api_base, repository).",
        examples=[TargetType.DOMAIN],
    )
    seed_value: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Raw seed value. Will be deterministically normalized upon creation.",
        examples=["api.example.com"],
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional operator notes or context.",
        examples=["Main ingress gateway for v1 services."],
    )


class TargetUpdateRequest(BaseModel):
    """Request payload for updating target metadata or status."""

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Updated target name.",
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Updated operator notes.",
    )
    status: Literal["active", "archived"] | None = Field(
        default=None,
        description="Set to 'archived' to decommission target seed.",
    )


class TargetResponse(BaseModel):
    """API representation of a normalized target seed."""

    id: UUID
    project_id: UUID
    name: str
    seed_type: str
    seed_value: str
    description: str | None
    status: str
    created_by: UUID
    created_at: datetime
    archived_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class TargetListResponse(BaseModel):
    """Paginated collection of target seeds."""

    items: list[TargetResponse]
    total: int
    limit: int
    offset: int


# -----------------------------------------------------------------------------
# Authorization Schemas
# -----------------------------------------------------------------------------


class AuthorizationCreateRequest(BaseModel):
    """Request payload for registering a legal/contractual authorization record."""

    reference: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Engagement letter, ticket, contract, or compliance reference ID.",
        examples=["ENG-2026-041"],
    )
    document_evidence_id: UUID | None = Field(
        default=None,
        description="Optional foreign key to an uploaded evidence object (e.g. signed PDF).",
    )
    authorized_by_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Name of authorizing client officer or legal representative.",
        examples=["Jane Doe"],
    )
    authorized_by_contact: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Contact email or phone number for authorizing party.",
        examples=["security@example.com"],
    )
    valid_from: datetime = Field(
        ...,
        description="Start of the authorized testing window (timezone-aware UTC).",
        examples=["2026-11-01T00:00:00Z"],
    )
    valid_to: datetime = Field(
        ...,
        description="End of the authorized testing window (timezone-aware UTC).",
        examples=["2026-12-01T00:00:00Z"],
    )
    allowed_actions: list[str] = Field(
        ...,
        min_length=1,
        description="Explicit set of permitted operations.",
        examples=[["scan", "validate", "agent_run"]],
    )
    destructive_allowed: bool = Field(
        default=False,
        description="Explicit permission for intrusive or state-mutating security tests.",
    )
    allow_private_ranges: bool = Field(
        default=False,
        description="Permission to include RFC 1918 / intranet ranges in scope.",
    )
    max_requests_per_scan: int | None = Field(
        default=None,
        description="Optional hard request ceiling per scan. Null indicates no volume cap.",
        examples=[50000],
    )
    notes: str | None = Field(
        default=None,
        max_length=4000,
        description="Optional rules of engagement or operational constraints.",
        examples=["External testing only; exclude production database cluster."],
    )

    @field_validator("valid_from", "valid_to", mode="before")
    @classmethod
    def validate_timezone_aware(cls, val: Any) -> datetime:
        """Enforce timezone awareness and normalize to UTC."""
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val)
            except ValueError as exc:
                raise ValueError(f"Invalid timestamp format: {exc}") from exc
        elif isinstance(val, datetime):
            dt = val
        else:
            raise ValueError("Timestamp must be an ISO 8601 string or datetime object")

        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            raise ValueError("Timestamp must be timezone-aware (e.g. ISO 8601 with 'Z' or offset)")
        return dt.astimezone(UTC)

    @field_validator("reference", "authorized_by_name", "authorized_by_contact")
    @classmethod
    def validate_non_empty_strings(cls, val: str, info: Any) -> str:
        """Reject empty or whitespace-only required strings."""
        clean = val.strip()
        if not clean:
            raise ValueError(f"Field '{info.field_name}' must not be empty or whitespace-only")
        return clean

    @field_validator("allowed_actions")
    @classmethod
    def validate_allowed_actions(cls, actions: list[str]) -> list[str]:
        """Validate allowed actions against explicit allowlist and deduplicate deterministically."""
        if not actions:
            raise ValueError("allowed_actions must contain at least one action")
        cleaned_actions: list[str] = []
        for a in actions:
            clean_a = a.strip().lower()
            if not clean_a:
                raise ValueError("Action name must not be empty")
            if clean_a not in VALID_AUTHORIZATION_ACTIONS:
                valid_act = sorted(VALID_AUTHORIZATION_ACTIONS)
                raise ValueError(f"Unknown action '{clean_a}'. Permitted actions: {valid_act}")
            cleaned_actions.append(clean_a)
        return sorted(set(cleaned_actions))

    @field_validator("max_requests_per_scan")
    @classmethod
    def validate_max_requests(cls, val: int | None) -> int | None:
        """Validate request limit is positive and within architecture boundaries."""
        if val is None:
            return None
        if val <= 0:
            raise ValueError("max_requests_per_scan must be a positive integer (> 0)")
        if val > 10_000_000:
            raise ValueError(
                "max_requests_per_scan cannot exceed architecture ceiling of 10,000,000"
            )
        return val

    @model_validator(mode="after")
    def validate_validity_window(self) -> Self:
        """Ensure valid_to is strictly after valid_from."""
        if self.valid_to <= self.valid_from:
            raise ValueError(
                f"valid_to ({self.valid_to.isoformat()}) must be strictly after "
                f"valid_from ({self.valid_from.isoformat()})"
            )
        return self


class AuthorizationResponse(BaseModel):
    """API representation of a legal authorization record."""

    id: UUID
    project_id: UUID
    reference: str
    document_evidence_id: UUID | None
    authorized_by_name: str
    authorized_by_contact: str
    valid_from: datetime
    valid_to: datetime
    allowed_actions: list[str]
    destructive_allowed: bool
    allow_private_ranges: bool
    max_requests_per_scan: int | None
    notes: str | None
    created_by: UUID
    created_at: datetime
    revoked_at: datetime | None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("valid_from", "valid_to", "created_at", "revoked_at", mode="before")
    @classmethod
    def ensure_response_utc(cls, val: Any) -> Any:
        """Ensure all response datetimes are explicitly timezone-aware UTC."""
        if isinstance(val, datetime):
            if val.tzinfo is None or val.tzinfo.utcoffset(val) is None:
                return val.replace(tzinfo=UTC)
            return val.astimezone(UTC)
        return val


class AuthorizationListResponse(BaseModel):
    """Paginated collection of authorization records."""

    items: list[AuthorizationResponse]
    total: int
    limit: int
    offset: int


class AuthorizationEvaluationResult(BaseModel):
    """Structured decision output of deterministic authorization evaluation."""

    allowed: bool
    reason_code: AuthorizationReasonCode
    authorization_id: UUID | None
    project_id: UUID
    action: str
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    revoked_at: datetime | None = None
    max_requests_per_scan: int | None = None
    destructive_allowed: bool = False
    allow_private_ranges: bool = False


# -----------------------------------------------------------------------------
# Scope Rule Matching Contracts (P2.5.5)
# -----------------------------------------------------------------------------


class ScopeMatchReasonCode(StrEnum):
    """Reason codes for deterministic scope rule matching decisions."""

    ALLOWED_RULE = "allowed_rule"
    EXPLICIT_DENY = "explicit_deny"
    DEFAULT_DENY = "default_deny"
    INVALID_TARGET = "invalid_target"
    UNSUPPORTED_RULE = "unsupported_rule"


class ScopeRuleData(BaseModel):
    """In-memory representation of a scope rule for evaluation."""

    id: UUID
    effect: Literal["allow", "deny"]
    match_type: Literal[
        "exact_url",
        "url_prefix",
        "exact_host",
        "domain_suffix",
        "wildcard_domain",
        "ip",
        "cidr",
    ]
    value: str
    ports: Any | None = None
    protocols: list[str] | None = None
    priority: int = 100
    scope_version_id: UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class ScopeMatchResult(BaseModel):
    """Structured decision output of deterministic scope rule matching."""

    matched: bool
    effect: Literal["allow", "deny"]
    matched_rule_id: UUID | None = None
    match_type: str | None = None
    reason_code: ScopeMatchReasonCode
    normalized_destination: str | None = None
    evaluated_rule_count: int = 0


# -----------------------------------------------------------------------------
# Scope Version & Rule Lifecycle Schemas (P2.5.6)
# -----------------------------------------------------------------------------


class ScopeRuleCreateRequest(BaseModel):
    """Payload to create or update an individual scope rule."""

    effect: Literal["allow", "deny"] = Field(
        ...,
        description=(
            "Rule effect: 'allow' permits matched destinations, 'deny' explicitly excludes them."
        ),
    )
    match_type: Literal[
        "exact_url",
        "url_prefix",
        "exact_host",
        "domain_suffix",
        "wildcard_domain",
        "ip",
        "cidr",
    ] = Field(..., description="Target matching algorithm.")
    value: str = Field(..., min_length=1, max_length=2048, description="Target value or pattern.")
    ports: Any | None = Field(
        default=None,
        description="Optional port range [start, end] or single port. None indicates all ports.",
    )
    protocols: list[str] | None = Field(
        default=None,
        description="Optional protocols list (subset of 'http', 'https', 'tcp', 'udp').",
    )
    priority: int = Field(
        default=100,
        ge=0,
        le=1000000,
        description=(
            "Priority integer. Higher values indicate higher administrative preference "
            "within the same effect."
        ),
    )
    note: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional operator justification or context.",
    )

    @field_validator("protocols")
    @classmethod
    def validate_protocols(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        allowed = {"http", "https", "tcp", "udp"}
        lowered = [p.strip().lower() for p in v if p.strip()]
        for p in lowered:
            if p not in allowed:
                raise ValueError(f"Invalid protocol '{p}'. Allowed protocols: {sorted(allowed)}")
        return sorted(set(lowered))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (list, tuple)):
            if len(v) == 2:
                p_min, p_max = int(v[0]), int(v[1])
                if not (1 <= p_min <= 65535 and 1 <= p_max <= 65535 and p_min <= p_max):
                    raise ValueError(f"Invalid port range [{p_min}, {p_max}]")
                return [p_min, p_max]
            elif len(v) == 1:
                p = int(v[0])
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port {p} out of range (1-65535)")
                return [p, p]
            else:
                raise ValueError("Port range must have 1 or 2 elements")
        if isinstance(v, int):
            if not (1 <= v <= 65535):
                raise ValueError(f"Port {v} out of range (1-65535)")
            return [v, v]
        return v

    @model_validator(mode="after")
    def normalize_and_validate_value(self) -> Self:
        raw = self.value.strip()
        mt = self.match_type
        if mt in ("exact_url", "url_prefix"):
            self.value = normalize_target(TargetType.URL, raw).canonical_value
        elif mt == "exact_host":
            self.value = normalize_target(TargetType.HOST, raw).canonical_value
        elif mt == "domain_suffix":
            self.value = normalize_domain(raw)
        elif mt == "wildcard_domain":
            if not raw.startswith("*."):
                raise ValueError(f"Wildcard domain rule must start with '*.' (got: {raw})")
            suffix = normalize_domain(raw[2:])
            self.value = f"*.{suffix}"
        elif mt == "ip":
            self.value = normalize_target(TargetType.IP, raw).canonical_value
        elif mt == "cidr":
            net = ipaddress.ip_network(raw, strict=True)
            self.value = str(net)
        return self


class ScopeRuleResponse(BaseModel):
    """API representation of a scope rule."""

    id: UUID
    scope_version_id: UUID
    effect: str
    match_type: str
    value: str
    ports: Any | None = None
    protocols: list[str] | None = None
    priority: int
    note: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class ScopeVersionCreateRequest(BaseModel):
    """Payload to create a new draft scope version."""

    authorization_id: UUID = Field(
        ...,
        description="The authorization record binding this scope version.",
    )


class ScopeRuleSetUpdateRequest(BaseModel):
    """Payload to set or replace all rules in a draft scope version."""

    rules: list[ScopeRuleCreateRequest] = Field(
        ...,
        description="Exhaustive list of scope rules to define for this draft version.",
    )


class ScopeVersionResponse(BaseModel):
    """API representation of a scope version."""

    id: UUID
    project_id: UUID
    authorization_id: UUID
    version: int
    status: Literal["draft", "active", "superseded"]
    content_hash: str
    created_by: UUID
    created_at: datetime
    activated_at: datetime | None = None
    superseded_at: datetime | None = None
    rules: list[ScopeRuleResponse] | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("content_hash", mode="before")
    @classmethod
    def format_hash(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    @field_validator("created_at", "activated_at", "superseded_at")
    @classmethod
    def ensure_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class ScopeVersionListResponse(BaseModel):
    """Collection of scope versions."""

    items: list[ScopeVersionResponse]
    total: int


class ScopeValidationRequest(BaseModel):
    """Request payload to test or validate a target destination against project scope."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description=(
            "URL, hostname, or IP address to validate against project authorization and scope."
        ),
    )
    action: str = Field(
        default="scan",
        description=(
            "Action to validate against the authorization record (e.g., 'scan', 'probe', 'crawl')."
        ),
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Optional destination port.",
    )
    protocol: str | None = Field(
        default=None,
        description="Optional transport or application protocol ('http', 'https', 'tcp', 'udp').",
    )
    destructive: bool = Field(
        default=False,
        description="Flag indicating if the planned operation is state-changing or destructive.",
    )
    dry_run: bool = Field(
        default=True,
        description=(
            "If True, performs evaluation without persisting to scope_decisions audit table."
        ),
    )


class ScopeValidationDecision(BaseModel):
    """Authoritative decision output for scope validation."""

    allowed: bool
    reason_code: str
    project_id: UUID
    scope_version_id: UUID | None = None
    authorization_id: UUID | None = None
    matched_rule_id: UUID | None = None
    normalized_target: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    policy_hash: str | None = None
    decided_at: datetime
    context: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)

    @field_validator("policy_hash", mode="before")
    @classmethod
    def format_policy_hash(cls, v: Any) -> str | None:
        if isinstance(v, bytes):
            return v.hex()
        if v is None:
            return None
        return str(v)

    @field_validator("decided_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)
