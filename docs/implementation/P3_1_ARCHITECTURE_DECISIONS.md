# VulnOS — P3.1.2 Architectural Decision Records (ADRs)
## Canonical Design Decisions & Rationale for Phase 3 Reconnaissance

**Date:** 2026-11-02  
**Milestone:** P3.1.2  
**Status:** Approved  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## ADR-001: Reuse Existing `Scan` and `ToolExecution` Models

- **Status:** Accepted
- **Context:** Phase 3 requires tracking reconnaissance jobs and individual tool tasks. We evaluated whether to create dedicated `recon_jobs` and `recon_tasks` tables or reuse the existing `scans` and `tool_executions` tables.
- **Decision:** Reuse `Scan` (`scans` table with `scan_type='recon'`) for reconnaissance jobs and `ToolExecution` (`tool_executions` table with `stage='recon'`) for individual tasks.
- **Rationale:**
  1. `scans` already provides full tenant isolation (`project_id`), pinned `scope_version_id`, `authorization_id`, `target_ids`, `budget`, `profile`, `status`, and telemetry timestamps.
  2. `tool_executions` already supports container execution state, `tool_version_id`, `status` (including `scope_violation`), `input`, `attempt`, `cost_usd`, and parent execution lineage.
  3. Reusing existing models avoids duplicate migrations, redundant code paths, and schema drift, while seamlessly integrating with existing Row-Level Security (RLS) policies.
- **Consequences:** API schemas may expose user-friendly terms like `ReconJobResponse`, but the internal persistence layer maps directly to `Scan` and `ToolExecution`.

---

## ADR-002: Dual-Boundary Scope Enforcement Architecture

- **Status:** Accepted
- **Context:** A single point of failure in scope enforcement could result in unauthorized scanning or SSRF attacks against internal infrastructure.
- **Decision:** Implement two independent, non-bypassable scope enforcement boundaries:
  1. *Boundary 1 (Control Plane):* Pre-dispatch validation in the Recon Orchestrator using `evaluate_scope_validation()`.
  2. *Boundary 2 (Data Plane):* Runtime network interception via a Scope-Pinned Egress Proxy.
- **Rationale:**
  1. Workers and tool containers execute third-party code and must be treated as untrusted. A compromised worker must not be able to bypass scope simply by making an outbound socket connection.
  2. The Egress Proxy inspects actual outbound packets and HTTP redirects at runtime, mitigating DNS rebinding and redirect-based scope escapes.
- **Consequences:** Requires running an egress proxy container or sidecar along with worker containers in production environments.

---

## ADR-003: Opaque Secret References (`secret_ref_id`)

- **Status:** Accepted
- **Context:** Reconnaissance tools sometimes require authentication headers or API keys. Passing secrets via command-line flags or environment variables exposes them in `/proc`, container inspection, and error logs.
- **Decision:** Worker task envelopes will only contain opaque `secret_ref_id` UUIDs. Secrets are resolved just-in-time and injected by the Egress Proxy or an ephemeral helper directly into network headers, never appearing in task payloads, command lines, or plain logs.
- **Rationale:** Eliminates credential leakage in Celery task payloads, Redis queues, container inspect logs, and exception tracebacks.
- **Consequences:** All tools requiring auth must route through the proxy layer or implement a standardized credentials-helper interface.

---

## ADR-004: Static, Declarative Tool Registry Manifests

- **Status:** Accepted
- **Context:** Allowing API clients or workers to supply arbitrary executable paths, container images, or shell flags creates high-risk remote code execution and command injection vectors.
- **Decision:** Tools must be registered statically in trusted application configuration (`backend/app/recon/tools.py`). Each tool manifest declares an immutable `tool_id`, pinned container image, cryptographic `image_digest`, required capabilities, and templated argv array.
- **Rationale:** API clients select modules and high-level profiles, never shell commands or binaries. Arguments are deterministically mapped to argv arrays without invoking a shell interpreter (`shell=False`).
- **Consequences:** Adding a new security tool requires defining a static manifest and undergoing verification before it can be executed.

---

## ADR-005: Two-Stage Asset Ingestion & Provenance Recording

- **Status:** Accepted
- **Context:** Security tools produce diverse, verbose, and potentially unvalidated output (e.g., hundreds of megabytes of raw JSON or HTML).
- **Decision:** Implement a two-stage ingestion architecture:
  1. *Stage 1 (Raw Evidence Storage):* Full, unaltered tool outputs are streamed directly to S3-compatible storage, indexed content-addressed by SHA-256 in `evidence_objects`.
  2. *Stage 2 (Normalized Observations):* The Result Normalizer parses raw outputs into typed `NormalizedObservation` records, which are correlated into canonical `assets` (`domains`, `hosts`, `services`, `endpoints`) and appended to `asset_discoveries`.
- **Rationale:**
  1. Prevents database bloat from large raw payloads.
  2. Preserves non-repudiable raw evidence for legal verification and manual audit.
  3. Guarantees that only validated, sanitized data enters the relational database.
- **Consequences:** Reading full raw tool outputs requires fetching an S3 signed URL rather than reading directly from PostgreSQL.

---

## ADR-006: Immutable Job Pinning & Immediate Revocation

- **Status:** Accepted
- **Context:** Projects may update scope versions or revoke authorization records while reconnaissance jobs are queued or running.
- **Decision:**
  1. At creation, each `Scan` permanently pins `scope_version_id` and `authorization_id`. Running jobs never silently switch to a new scope version.
  2. If an `AuthorizationRecord` is revoked or expires during execution, the job is immediately aborted with status `'cancelled'`. There is zero grace period.
- **Rationale:** Ensures complete legal compliance and deterministic repeatability of past scans.
- **Consequences:** If an operator updates scope rules, they must create a new scan or stage run to test against the new rules.

---

## ADR-007: Celery Task Distribution with Late Acknowledgment

- **Status:** Accepted
- **Context:** Reconnaissance tasks can run for several minutes. If a worker container crashes or experiences an Out-Of-Memory (OOM) kill, the task state must not be lost or silently discarded.
- **Decision:** Configure Celery tasks with `acks_late=True` and `reject_on_worker_lost=True`. The task is acknowledged only after output is safely persisted.
- **Rationale:** Guarantees that task failures are accurately classified and logged. Crashed tasks can be retried up to the task's maximum retry limit.
- **Consequences:** Tasks must be designed to be idempotent in case a worker crashes after partial execution.
