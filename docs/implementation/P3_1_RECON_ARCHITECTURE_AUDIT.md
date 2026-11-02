# VulnOS — P3.1.1 Reconnaissance Architecture Audit
## Baseline Inventory, Existing Infrastructure & Execution Contracts Audit

**Date:** 2026-11-02  
**Milestone:** P3.1.1  
**Status:** Completed  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

Phase 2 established a hardened security foundation across repository infrastructure (P2.1), PostgreSQL 16 schema with 50 models (P2.2), Row-Level Security and multi-tenant isolation (P2.3), Argon2id/JWT/Redis-session/API-key authorization (P2.4), and deterministic target normalization, authorization records, scope rule matching, versioning, and append-only decision auditing (P2.5).

Phase 3 builds the **reconnaissance and asset discovery foundation**. The purpose of milestone **P3.1** is to establish the formal execution contracts, orchestration architecture, tool registry definitions, worker sandboxing interfaces, and dual-boundary scope enforcement protocols that all future reconnaissance modules must follow.

**Critical Architectural Invariant:**
> **A target is a discovery seed, not an authorization permit. A project membership is not permission to test. An authorization record alone is not permission to test.**
> Every future reconnaissance operation must be bound to:
> `Project -> Target -> Authorization Record -> Active Scope Version -> Central Scope Validation -> Recon Job -> Orchestrator -> Isolated Worker -> Normalized Observation -> Evidence Collection -> Asset Correlation -> Persistence`.
> Under no circumstances may a worker or tool independently determine that a target is authorized.

---

## 2. Mandatory Repository Audit Findings

### 2.1 Git Status & Baseline Preservation
- **Current Branch:** `main`
- **HEAD Commit:** `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8`
- **Working Tree State:** Clean baseline preserved; no files committed, staged, or merged. Working tree contains only project code and untracked artifacts.
- **Python Environment:** Python 3.13 virtual environment managed with `uv`.

### 2.2 Quality Gates & Existing Verification Status
- **Pytest Suite:** 417 passed in ~11.97s (100% passing across models, migrations, RLS, auth, targets, authorizations, rules, and scope versioning).
- **Type Checking (`mypy backend tests`):** 0 issues across 93 source files.
- **Linter (`ruff check .`):** Clean (0 errors).
- **Alembic Migrations:** 4 revisions applied (`0001_phase2_baseline`, `0002_phase2_rls`, `0003_phase2_authorization_records`, `0004_phase2_scope_rules`).

---

## 3. Existing Codebase & Infrastructure Inventory

### 3.1 Existing Infrastructure Components
| Component | Existing Implementation | Reusability in Phase 3 |
|---|---|---|
| **FastAPI Backend** | `backend/app/main.py`, lifespan handler, structured exception formatting (`{"error": ...}`), `/api/v1` routers. | Central API surface for Recon Job creation, inspection, and cancellation. |
| **Settings Configuration** | `backend/app/core/config.py` with Pydantic Settings v2. Includes `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_DEFAULT_QUEUE`, `S3_BUCKET_EVIDENCE`, `S3_BUCKET_REPORTS`. | Reusable as-is for Celery task queuing and S3 evidence references. |
| **PostgreSQL RLS & Tenant Context** | `backend/app/db/tenant.py` (`set_tenant_context()`, `tenant_context()`, `get_tenant_db()`). `session.py` pool event listeners executing `RESET ALL;`. | Mandatory tenant boundary for all recon job queries and asset writes. |
| **Authentication & RBAC** | `backend/app/auth/dependencies.py` (`get_current_user`, `get_project_access_guard`). Role hierarchy: `viewer` < `operator` < `admin` < `owner`. | Job creation restricted to `operator+`, job cancellation to `operator+`, job inspection to `viewer+`. |
| **Audit Trail & Outbox** | `backend/app/db/models/audit.py` (`AuditLog` and `OutboxEvent`). Automatic sensitive credential redaction. | Append-only event tracking for job creation, task state transitions, scope denials, and budget alerts. |
| **Worker & Engine Directories** | `engine/` and `workers/` packages present with `__init__.py`. | Dedicated locations for orchestration engine logic and isolated worker abstractions. |

### 3.2 Existing Database Models (Scan, Tool, Asset & Evidence)

The database schema defined in P2.2 and baseline migrations already contains comprehensive models specifically structured for scans, tools, assets, and evidence:

#### 1. Execution & Scans (`backend/app/db/models/execution.py`)
- **`Scan` (`scans` table):**
  - Primary execution unit pinning `project_id`, `scope_version_id`, `authorization_id`, `target_ids`, `profile`, `budget`, `requested_by`, `status`, `cost_usd`, `stats`.
  - Check constraints: `scan_type IN ('recon','discovery','web','api','agent','full','validation')`, `status IN ('draft','queued','running','paused','completed','failed','cancelled')`.
  - Fully supports Recon Jobs without schema changes.
- **`ScanStageRun` (`scan_stage_runs` table):**
  - Tracks stage attempts within a scan (`stage IN ('scope','recon','discovery','selection','scanning','agent','correlation','investigation','validation','reporting')`, `status IN ('pending','running','succeeded','partial','failed','skipped','cancelled')`).
- **`ToolExecution` (`tool_executions` table):**
  - Individual task / container execution record (`stage`, `tool_version_id`, `status IN ('queued','running','succeeded','failed','timeout','cancelled','skipped','scope_violation')`, `input`, `command_redacted`, `worker_id`, `attempt`, `parent_execution_id`, `exit_code`, `error_code`, `coverage_summary`, `stats`, `cost_usd`).
  - Represents individual recon tasks dispatched to workers.
- **`ToolSelectionDecision` (`tool_selection_decisions` table):**
  - Explainable selection rationale from TISE (`decision IN ('selected','skipped')`, `reason_code`, `score`, `budget_snapshot`).
- **`Tool`, `ToolVersion`, `ToolCapability` (`tools`, `tool_versions`, `tool_capabilities` tables):**
  - Tool catalog, image references, cryptographic digests, and verified capabilities (`passive`, `active`, `state_changing`, `destructive`, `cost_tier`, `max_concurrency`, `requires_approval`, `input_schema`, `output_formats`).

#### 2. Asset Inventory & Provenance (`backend/app/db/models/assets.py`)
- **`Asset` (`assets` table):**
  - Canonical identity (`kind IN ('domain', 'host', 'service', 'endpoint', 'repository')`, `canonical_key`, `confidence`, `first_seen_at`, `last_seen_at`, `attributes`).
- **Specialized Asset Detail Tables:**
  - `domains`, `hosts`, `host_addresses` (DNS resolution history), `services` (ports/transports/banners), `endpoints` (HTTP paths, methods, auth requirements), `parameters`, `technologies`, `asset_technologies`, `api_schemas`.
- **`AssetDiscovery` (`asset_discoveries` table):**
  - Append-only observation provenance linking `asset_id` to `scan_id`, `tool_execution_id`, `source`, `discovered_at`, `confidence`, `metadata`.

#### 3. Evidence & Telemetry (`backend/app/db/models/evidence.py`)
- **`EvidenceObject` (`evidence_objects` table):**
  - Metadata record for raw payloads stored in S3-compatible storage (`kind IN ('http_request','http_response','screenshot','tool_output',...)`, `sha256`, `size_bytes`, `storage_backend`, `bucket`, `object_key`, `redaction_status`, `created_by_execution_id`).
- **`HTTPExchange` (`http_exchanges` table):**
  - Telemetry record for outbound HTTP requests/responses during discovery, partitioned by range on `occurred_at`, linking `scan_id` and `tool_execution_id`.

#### 4. Scope & Identity (`backend/app/db/models/identity.py`)
- `Target`, `AuthorizationRecord`, `ScopeVersion`, `ScopeRule`, `ScopeDecision`.

---

## 4. Existing Scope Enforcement Interfaces

Phase 2.5 delivered a robust, deterministic scope enforcement engine in `backend/app/scope/`:

1. **Target Normalization & Security Classification (`backend/app/scope/normalization.py`):**
   - Canonicalizes domains, hosts, IPs, CIDRs, URLs, and repositories.
   - Enforces IDNA UTS #46, RFC 5952 IPv6 compression, RFC 3986 URL path normalization.
   - Detects and hard-blocks non-overridable cloud metadata (IMDS) targets (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`).
2. **Deterministic Rule Matching (`backend/app/scope/matching.py`):**
   - Pure function `match_scope_rules(rules, destination, port, protocol)`.
   - Global deny-overrides-allow precedence across all 7 match types (`exact_url`, `url_prefix`, `exact_host`, `domain_suffix`, `wildcard_domain`, `ip`, `cidr`).
   - Wildcard apex exclusion invariant (`*.example.com` rejects `example.com`).
   - Safe path-boundary prefix matching (`/api` rejects `/api-docs`).
3. **Comprehensive Scope Validation Engine (`backend/app/scope/versions.py`):**
   - Function `evaluate_scope_validation(db, project_id, request, scan_id, evaluation_time)`:
     1. Validates that an active, non-revoked `AuthorizationRecord` exists for the project within the validity time window.
     2. Validates that the requested action is present in `allowed_actions`, and verifies destructive operation gating.
     3. Validates that an active `ScopeVersion` exists with valid rules.
     4. Executes pure rule matching against the active rules.
     5. Re-evaluates cloud IMDS and RFC 1918 private range restrictions against `AuthorizationRecord.allow_private_ranges`.
     6. Atomically writes an append-only audit row to `ScopeDecision` (when `dry_run=False`), recording `scan_id`, `subject`, `method`, `allowed`, `reason_code`, `policy_hash`.
4. **Validation Endpoint (`backend/app/api/v1/scope.py`):**
   - `POST /api/v1/projects/{project_id}/scope/validate` (requires `operator` role).

---

## 5. Architectural Gap Analysis

While the underlying database models and scope validation engine are mature, the following orchestration and contract components are missing and must be established in Phase 3.1:

```text
+-----------------------------------------------------------------------------------+
| MISSING ARCHITECTURAL COMPONENTS IN PHASE 3.1                                     |
+-----------------------------------------------------------------------------------+
| 1. Recon Orchestrator Service Layer:                                              |
|    - High-level coordinator managing Recon Job lifecycle using existing Scan model|
|    - Dependency DAG resolver for scheduling ordered reconnaissance tasks           |
|    - Centralized budget controller tracking duration, requests, and costs         |
| 2. Formal Reconnaissance Contracts:                                              |
|    - Pydantic v2 schemas for Recon Job creation, status, and task envelopes       |
|    - Strict input/output schemas for tool execution and worker task envelopes     |
| 3. Tool Registry Architecture:                                                    |
|    - In-memory / configuration-driven manifest catalog for tools and capabilities |
|    - Strict allowlist preventing arbitrary client-supplied commands or executables|
| 4. Worker Execution Abstraction:                                                  |
|    - Standardized WorkerTaskEnvelope and WorkerTaskResult                         |
|    - Isolation contracts: non-root, read-only FS, no Docker socket, restricted net |
| 5. Dual-Boundary Scope Enforcement Specification:                                 |
|    - Boundary 1: Pre-execution policy check in Orchestrator before queuing tasks  |
|    - Boundary 2: Runtime egress guard / proxy intercepting all outbound packets   |
| 6. Observation & Evidence Normalization Contracts:                                |
|    - Standardized observation envelopes distinguishing raw output from assets     |
+-----------------------------------------------------------------------------------+
```

---

## 6. Security Analysis & Threat Boundaries

### 6.1 Critical Security Invariants
1. **Never Trust the Worker for Scope:** Workers and tool adapters execute in hostile environments. They must never be trusted to decide whether a destination is within scope. Scope validation must occur centrally in the orchestrator before scheduling, and at runtime via an isolated egress proxy.
2. **Target is Not a Permit:** A Target in `targets` is merely a discovery seed. A Recon Job cannot be created or executed unless an active `AuthorizationRecord` and active `ScopeVersion` exist and authorize the target.
3. **No Dynamic Code or Shell Injection:** Tool definitions must be statically registered in a trusted Tool Registry. API clients must never supply executable paths, CLI flags, or arbitrary shell commands.
4. **No Raw Secrets in Task Envelopes:** Worker envelopes must never contain database credentials, JWT secrets, API key peppers, or platform session tokens. Target credentials must use opaque `secret_ref_id` references resolved at execution time.
5. **Fail-Closed Passive Reconnaissance:** Passive reconnaissance (e.g., querying external CT logs or DNS APIs) must not be exempted from scope checks. Unbounded third-party API lookups could be leveraged to leak internal hostnames or trigger SSRF attacks against internal network metadata services.
6. **Strict Project Isolation:** Every entity (Target, AuthorizationRecord, ScopeVersion, Scan, ToolExecution, Asset, EvidenceObject) must carry a verified `project_id`. Cross-project references must fail closed with HTTP 404 (preventing project existence enumeration).

---

## 7. Proposed Phase 3.1 Reconnaissance Architecture

### 7.1 Pipeline Overview

```text
[Operator Request: POST /projects/{id}/recon/jobs]
                    |
                    v
    +--------------------------------+
    |    Recon Orchestrator Gate     |
    | 1. Authenticate & Verify RBAC  |
    | 2. Enforce Tenant Context (RLS)|
    | 3. Validate Target Ownership   |
    | 4. Check Active Authorization  |
    | 5. Check Active Scope Version  |
    +--------------------------------+
                    |
                    v
    +--------------------------------+
    |   Central Scope Engine Check   |
    | evaluate_scope_validation()    |
    | (Authorization + Rules + IMDS) |
    +--------------------------------+
                    | (Allowed)
                    v
    +--------------------------------+
    |   Create Scan & Stage Run      |
    | Persist Scan(type='recon')     |
    | ScanStageRun(stage='recon')    |
    | Initialize Resource Budgets    |
    +--------------------------------+
                    |
                    v
    +--------------------------------+
    |    Task Plan & Tool Registry   |
    | Resolve Task Dependencies      |
    | Verify Tool Manifests          |
    | Generate WorkerTaskEnvelopes   |
    +--------------------------------+
                    |
                    v
    +--------------------------------+
    |   Task Queue (Celery / Redis)  |
    | Push Envelopes to Worker Queue |
    +--------------------------------+
                    |
                    v
    +--------------------------------+
    |    Isolated Worker Runtime     |
    | (Non-root, read-only FS,       |
    |  No Docker socket, Egress Guard|
    |  intercepts outbound traffic)  |
    +--------------------------------+
                    |
                    v
    +--------------------------------+
    | Output & Evidence Normalizer   |
    | 1. Stream Raw to EvidenceObject|
    | 2. Normalize Observations      |
    | 3. Append AssetDiscovery       |
    | 4. Update ToolExecution State  |
    +--------------------------------+
```

### 7.2 Integration with Existing Phase 2 Architecture
- **Schema Compatibility:** The proposed architecture uses existing PostgreSQL tables (`scans`, `scan_stage_runs`, `tool_executions`, `tools`, `tool_versions`, `tool_capabilities`, `assets`, `asset_discoveries`, `evidence_objects`, `scope_decisions`, `audit_logs`). No speculative or redundant tables are required.
- **Scope Compatibility:** Reuses `evaluate_scope_validation` directly. Every active recon job and task creates linked `ScopeDecision` records with `scan_id`.
- **Tenant Context Compatibility:** All orchestrator operations run within `get_tenant_db()`, ensuring PostgreSQL Row-Level Security automatically partitions all reads and writes.

---

## 8. Milestone Execution Plan (P3.1.2 through P3.1.10)

| Milestone | Deliverable | Focus Area |
|---|---|---|
| **P3.1.1** | `P3_1_RECON_ARCHITECTURE_AUDIT.md` | Repository audit, infrastructure discovery, gap analysis, and architecture baseline. *(This document)* |
| **P3.1.2** | `P3_1_RECON_ARCHITECTURE.md` | Reconnaissance architecture specification, orchestrator design, task DAG, and state machines. |
| **P3.1.3** | `P3_1_EXECUTION_CONTRACTS.md` | Pydantic v2 schemas: `ReconJobCreateRequest`, `ReconJobResponse`, `ReconTaskRequest`, `ReconTaskResponse`. |
| **P3.1.4** | `backend/app/recon/tools.py` | Tool registry contracts, `ToolManifest`, capability declarations, and static tool validation. |
| **P3.1.5** | `backend/app/recon/worker_contracts.py` | Worker execution contracts: `WorkerTaskEnvelope`, `WorkerTaskResult`, isolation constraints. |
| **P3.1.6** | `P3_1_SCOPE_ENFORCEMENT.md` | Dual-boundary scope enforcement specification (pre-dispatch and runtime egress guard). |
| **P3.1.7** | `backend/app/recon/observation_contracts.py` | Evidence and result contracts: `AssetObservation`, `ReconEvidenceReference`, provenance tracking. |
| **P3.1.8** | `backend/app/recon/budgets.py` | Resource budget contracts, duration timeouts, request quotas, and audit log events. |
| **P3.1.9** | `backend/tests/security/recon/` | Security test suite validating lifecycle states, invalid transitions, scope gates, and isolation. |
| **P3.1.10** | `PHASE_3_PROGRESS.md` | Final documentation, progress tracking, and Phase 3.1 review. |

---

## 9. Conclusion

The repository audit verifies that VulnOS possesses a strong, mature foundation for Phase 3. The existing models in `backend/app/db/models/execution.py`, `assets.py`, `evidence.py`, and `identity.py` directly satisfy the architectural needs of reconnaissance jobs, tasks, tools, observations, and telemetry. Milestone P3.1 will define the strict execution contracts and orchestration interfaces that bind these layers into a fail-closed, deterministic reconnaissance engine.
