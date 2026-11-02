# VulnOS — P3.1.3.2 Lifecycle Gap Analysis & Validation Design
## Analysis of Schemas, State Machines, Retries & Concurrency Controls

**Date:** 2026-11-02  
**Milestone:** P3.1.3.2  
**Status:** Completed  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

This gap analysis reviews the conceptual contracts established in P3.1.2 against the existing Python codebase, identifies missing runtime validation, and specifies the concrete architecture for `backend/app/recon/` to be implemented in milestone P3.1.3.3 onward.

---

## 2. Existing Schema Inventory & Gap Analysis

| Conceptual Contract | Python Implementation Status | Existing Location | Validation Gaps / Required Extensions |
|---|---|---|---|
| `ReconJobCreateRequest` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/schemas.py` | Must enforce `extra="forbid"`, target list bounds (1 to 50), duplicate target rejection, and positive budget limits. |
| `ReconJobResponse` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/schemas.py` | Must support `from_attributes=True` for SQLAlchemy `Scan` instances, serialize UTC timestamps, and summarize stage runs. |
| `ToolManifest` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/tools.py` | Must enforce SHA-256 image digest format (`^sha256:[a-f0-9]{64}$`), resource bounds, and static argv template lists. |
| `WorkerTaskEnvelope` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/worker_contracts.py` | Must reject plaintext credentials, enforce opaque `secret_ref_ids`, and bind to `project_id`, `scan_id`, and `scope_version_id`. |
| `WorkerTaskResult` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/worker_contracts.py` | Must enforce attempt counter, bounded output truncations, exit code validation, and structured error codes. |
| `NormalizedObservation` | Documented in `P3_1_EXECUTION_CONTRACTS.md`; not yet implemented in Python. | *To be created in* `backend/app/recon/observation_contracts.py` | Must require at least one discovered entity (domain, host, service, or endpoint) and bounded confidence (0.0 to 1.0). |

---

## 3. Lifecycle Gap Analysis & Solutions

### 3.1 Partial Completion Semantics
- **Problem:** Conceptual state machines often suggest `PARTIALLY_COMPLETED`, but `ck_scans_status` strictly permits only:
  `'draft'`, `'queued'`, `'running'`, `'paused'`, `'completed'`, `'failed'`, `'cancelled'`.
- **Solution:**
  1. A job where some non-critical tasks succeeded and some failed is marked `status = 'completed'`.
  2. The `Scan.stats` dictionary records `stats["partially_completed"] = True` and detailed counts: `{"tasks_succeeded": 5, "tasks_failed": 1}`.
  3. The associated `ScanStageRun.status` is set to `'partial'`.
  4. The `ReconJobResponse` Pydantic schema exposes `is_partial: bool = Field(default=False)` computed from `stats["partially_completed"]`.
  This provides full semantic fidelity without requiring a database migration.

### 3.2 Timeout Handling
- **Problem:** `ToolExecution` supports `status = 'timeout'`, but `Scan` does not have a separate `'timeout'` status.
- **Solution:**
  1. When a job exceeds its `budget.max_wall_clock_minutes`, the job transitions to `status = 'failed'`.
  2. The failure cause is explicitly recorded in `Scan.stats["failure_reason"] = "job_wall_clock_timeout"`.
  3. An `AuditLog` event is emitted with `action = "recon_job.timed_out"`.

### 3.3 Paused State Semantics
- **Permitted Actors:** Only project `operator`, `admin`, or `owner` can pause or resume a job.
- **Behavior Upon Pause:**
  1. Queued tasks in Redis/Celery are revoked or held.
  2. Running workers receive cooperative pause/drain signals.
  3. Job status updates to `paused`.
- **Behavior Upon Resume:**
  1. **Mandatory Revalidation:** Before resuming, the orchestrator checks that the pinned `AuthorizationRecord` is still valid and not revoked, and that the pinned `ScopeVersion` is still valid.
  2. If the authorization record has expired or been revoked while paused, the job cannot be resumed and must transition to `cancelled`.

### 3.4 Task Retries & Scope Violations
- **Problem:** Automatic retries on failed tasks could repeatedly hammer unapproved destinations if not restricted.
- **Rules:**
  1. Retries are allowed only for transient errors (`NETWORK_TIMEOUT`, `CONTAINER_CRASH`) where `attempt < max_retries` (default: 2).
  2. **Non-Retryable Invariant:** Any task failing with `status == 'scope_violation'` is **strictly non-retryable**. A scope violation indicates that the tool attempted to access an out-of-scope host, IP, or IMDS metadata service. Retrying against a denied destination is a security violation.
  3. A retry creates a new `ToolExecution` record with incremented `attempt = previous.attempt + 1` and `parent_execution_id = previous.id`.

### 3.5 Stale Worker Result Defense
- **Problem:** A delayed worker from an earlier, timed-out or cancelled attempt could report results and accidentally mark a cancelled task as succeeded.
- **Defense:**
  1. When a worker returns `WorkerTaskResult`, the Orchestrator checks the current database state of `ToolExecution` using `SELECT ... FOR UPDATE`.
  2. If `execution.status` is already terminal (`cancelled`, `timeout`, `succeeded`), or if `result.attempt != execution.attempt`, the worker result is rejected as stale and an `AuditLog` event (`recon_task.stale_result_rejected`) is recorded.
