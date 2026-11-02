# VulnOS — P3.1.2 / P3.1.3 Execution Contracts Specification
## Pydantic v2 Contracts, Schemas, Tool Manifests & Worker Envelopes

**Date:** 2026-11-02  
**Milestone:** P3.1.2 & P3.1.3.2  
**Status:** Canonical Design  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

This document specifies the typed Pydantic v2 contracts governing all interactions between the API layer, Recon Orchestrator, Task Queue, Isolated Workers, and Asset Normalizers.

### Core Contract Invariants:
1. **Strict Type Validation:** All schemas use Pydantic v2 with `extra="forbid"` to reject unexpected client-supplied parameters.
2. **UUIDv7 Primary Keys & UTC Timestamps:** All entity IDs use UUID (uuid7 compliant) and all datetime fields enforce timezone awareness (`timezone.utc`).
3. **No Raw Secrets in Task Payloads:** Task envelopes carry opaque references (`secret_ref_id`), never plaintext passwords, API keys, or tokens.
4. **No Arbitrary Commands:** Tool inputs are strictly mapped through declarative, static schemas; client-supplied shell commands or executable paths are strictly forbidden.

---

## 2. Reconnaissance Job Contracts

### 2.1 `ReconJobCreateRequest`
```python
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class ReconBudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_wall_clock_minutes: int = Field(
        default=60, ge=5, le=1440, description="Maximum wall-clock execution time in minutes."
    )
    max_requests: int = Field(
        default=5000, ge=100, le=100000, description="Total HTTP/network request ceiling."
    )
    max_cost_usd: float = Field(
        default=10.0, ge=0.0, le=500.0, description="Total budget limit in USD."
    )
    max_concurrency: int = Field(
        default=5, ge=1, le=50, description="Maximum concurrent worker tasks."
    )


class ReconJobCreateRequest(BaseModel):
    """Client request schema for creating and scheduling a reconnaissance job."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        min_length=3,
        max_length=120,
        description="Human-readable title for the reconnaissance job.",
    )
    target_ids: list[UUID] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of target seed UUIDs to include in reconnaissance.",
    )
    modules: list[str] = Field(
        default_factory=lambda: [
            "passive_dns",
            "certificate_transparency",
            "subdomain_discovery",
            "port_scan",
            "http_discovery",
            "tech_fingerprint",
        ],
        description="List of reconnaissance modules to execute in dependency order.",
    )
    budget: ReconBudgetConfig = Field(
        default_factory=ReconBudgetConfig,
        description="Resource and operational limits for the job.",
    )
```

### 2.2 `ReconJobResponse`
```python
from datetime import datetime
from decimal import Decimal
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class ReconStageSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stage: str
    status: str
    attempt: int
    started_at: datetime | None
    finished_at: datetime | None
    metrics: dict[str, int | float | str]


class ReconJobResponse(BaseModel):
    """Complete representation of a reconnaissance job."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    name: str
    scan_type: str  # Always 'recon'
    status: str  # draft | queued | running | paused | completed | failed | cancelled
    scope_version_id: UUID
    authorization_id: UUID
    target_ids: list[UUID]
    budget: dict[str, int | float]
    cost_usd: Decimal
    stats: dict[str, int | float]
    stages: list[ReconStageSummary] = []
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None
```

---

## 3. Tool Manifest & Registry Contracts

Tools are registered statically in application code. API clients select modules, not raw tools.

### 3.1 `ToolManifest`
```python
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ToolResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu_cores: float = Field(default=1.0, ge=0.1, le=8.0)
    memory_mb: int = Field(default=1024, ge=128, le=8192)
    pids_limit: int = Field(default=128, ge=32, le=1024)
    tmpfs_size_mb: int = Field(default=256, ge=64, le=2048)


class ToolManifest(BaseModel):
    """Static metadata and execution parameters for an integrated tool."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(..., pattern=r"^[a-z0-9_\-]+$")
    name: str
    version: str
    category: Literal["recon", "discovery", "scanner", "api"]
    image_ref: str
    image_digest: str = Field(..., pattern=r"^sha256:[a-f0-9]{64}$")
    capabilities: list[str]
    is_passive: bool
    is_active: bool
    is_destructive: bool = False
    requires_approval: bool = False
    timeout_seconds: int = Field(default=300, ge=30, le=3600)
    resource_limits: ToolResourceLimits = Field(default_factory=ToolResourceLimits)
    command_template: list[str] = Field(
        ...,
        description="Templated argv list; arguments are substituted deterministically.",
    )
```

---

## 4. Worker Task Envelope & Result Contracts

### 4.1 `WorkerTaskEnvelope`
The sealed payload dispatched by the Orchestrator to the worker queue.
```python
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class WorkerTaskEnvelope(BaseModel):
    """Cryptographically verifiable task instructions dispatched to an isolated worker."""

    model_config = ConfigDict(extra="forbid")

    envelope_version: str = "1.0"
    task_id: UUID = Field(..., description="Corresponds to tool_executions.id")
    job_id: UUID = Field(..., description="Corresponds to scans.id")
    project_id: UUID
    scope_version_id: UUID
    authorization_id: UUID
    tool_id: str
    tool_version: str
    image_digest: str
    stage: str
    destination: str = Field(
        ..., description="Normalized target destination approved by Scope Engine"
    )
    port: int | None = None
    protocol: str | None = None
    parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)
    secret_ref_ids: list[UUID] = Field(
        default_factory=list, description="Opaque pointers to secrets"
    )
    deadline: datetime
    max_requests: int = 1000
    egress_proxy_token: str = Field(
        ..., description="Ephemeral token allowing worker to access egress proxy"
    )
```

### 4.2 `WorkerTaskResult`
The output payload returned by the worker upon completion.
```python
from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class RawEvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["tool_output", "http_exchange", "screenshot"]
    sha256_hex: str = Field(..., min_length=64, max_length=64)
    size_bytes: int = Field(ge=0)
    content_type: str = "text/plain"
    s3_object_key: str


class WorkerTaskResult(BaseModel):
    """Structured report returned by worker upon container completion."""

    model_config = ConfigDict(extra="forbid")

    task_id: UUID
    job_id: UUID
    project_id: UUID
    worker_id: str
    exit_code: int
    status: Literal["succeeded", "failed", "timeout", "scope_violation"]
    started_at: datetime
    finished_at: datetime
    requests_sent: int = 0
    raw_evidence: list[RawEvidenceReference] = Field(default_factory=list)
    raw_stdout_truncated: str | None = None
    raw_stderr_truncated: str | None = None
    error_code: str | None = None
    error_message: str | None = None
```

---

## 5. Normalized Observation Contracts

Normalized observations represent structured facts discovered during reconnaissance before asset deduplication and database upsert.

### 5.1 `NormalizedObservation`
```python
from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class HostAddressObservation(BaseModel):
    ip_address: str
    dns_record_type: Literal["A", "AAAA", "CNAME", "PTR"]
    ttl: int | None = None


class ServiceObservation(BaseModel):
    port: int = Field(ge=1, le=65535)
    transport: Literal["tcp", "udp"] = "tcp"
    protocol: str | None = None
    banner: str | None = None
    tls: bool = False


class EndpointObservation(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str
    path: str
    status_code: int | None = None
    content_type: str | None = None


class TechnologyObservation(BaseModel):
    name: str
    category: str
    version: str | None = None
    cpe: str | None = None


class NormalizedObservation(BaseModel):
    """Standardized observation emitted by normalizer for database ingestion."""

    model_config = ConfigDict(extra="forbid")

    observation_id: UUID
    task_id: UUID
    job_id: UUID
    project_id: UUID
    observed_at: datetime
    source_tool: str
    source_tool_version: str
    confidence: float = Field(ge=0.0, le=1.0)

    # Discovered entities (at least one must be populated)
    domain_name: str | None = None
    host_name: str | None = None
    addresses: list[HostAddressObservation] = Field(default_factory=list)
    services: list[ServiceObservation] = Field(default_factory=list)
    endpoints: list[EndpointObservation] = Field(default_factory=list)
    technologies: list[TechnologyObservation] = Field(default_factory=list)

    raw_evidence_ref: str | None = None
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)
```

---

## 6. P3.1.3.2 Contract Clarifications & Field Disambiguation

1. **Authorization Context vs Legal Scope Authorization:**
   - `Scan.authorization_id`: References `authorization_records.id`. This is the mandatory legal scope permit with contract reference, authorized actions, validity window, and destructive permissions.
   - `ToolExecution.auth_context_id`: References `auth_contexts.id` (`backend/app/db/models/security.py`). This is the target web application testing identity (`anonymous`, `user`, `admin`, `service`) with associated roles and credentials (`secret_ref_id`).
   - Invariant: These two UUID references are completely orthogonal and must never be substituted.

2. **Partial Completion Representation:**
   - `Scan.status` remains `'completed'`.
   - `Scan.stats["partially_completed"] = True` and `ScanStageRun.status = 'partial'`.
   - `ReconJobResponse.is_partial: bool = Field(default=False)` is computed from `stats["partially_completed"]`.

