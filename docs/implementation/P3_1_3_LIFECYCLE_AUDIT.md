# VulnOS — P3.1.3.1 Reconnaissance Job & Task Lifecycle Audit
## Database Schema Inventory, Constraint Analysis & Lifecycle Gap Analysis

**Date:** 2026-11-02  
**Milestone:** P3.1.3.1  
**Status:** Completed  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

Milestone P3.1.3 establishes typed contracts and deterministic lifecycle state transitions for reconnaissance jobs and individual tasks.

This audit examines the existing database models (`Scan`, `ScanStageRun`, `ToolExecution`), constraints, indices, schema validators, concurrency mechanisms, and identifies the missing lifecycle guarantees that must be implemented in Python service and schema layers without modifying the underlying database tables.

---

## 2. Existing Model & Schema Inventory

### 2.1 Job Model: `Scan` (`backend/app/db/models/execution.py`)
- **Primary Key:** `id` (`UUID`, generated via `uuid7`).
- **Tenant Isolation:** `project_id` (`UUID`, FK `projects.id ON DELETE CASCADE`, indexed).
- **Core Fields:**
  - `name`: `Text` (human-readable title).
  - `scan_type`: `Text` (`ck_scans_scan_type`: `'recon','discovery','web','api','agent','full','validation'`).
  - `status`: `Text` (default `'draft'`, `ck_scans_status`: `'draft','queued','running','paused','completed','failed','cancelled'`).
  - `scope_version_id`: `UUID` (FK `scope_versions.id`). Immutable during execution.
  - `authorization_id`: `UUID` (FK `authorization_records.id`). Immutable during execution.
  - `target_ids`: `ARRAY(UUID)`. List of target discovery seeds.
  - `profile`: `JSONB` (configuration and module selection).
  - `budget`: `JSONB` (max requests, duration, concurrency, cost).
  - `requested_by`: `UUID` (FK `users.id`).
  - `started_at`: `DateTime(timezone=True)`, nullable.
  - `finished_at`: `DateTime(timezone=True)`, nullable.
  - `cancel_requested_at`: `DateTime(timezone=True)`, nullable.
  - `cost_usd`: `Numeric(12, 6)` (default 0.0).
  - `stats`: `JSONB` (summary metrics: requests, assets, errors).
  - `created_at`, `updated_at`: `DateTime(timezone=True)`.
- **Database Constraints & Indices:**
  - `ck_scans_scan_type`
  - `ck_scans_status`
  - `ix_scans_project_status` (`project_id`, `status`)
  - `ix_scans_project_created` (`project_id`, `created_at`)

### 2.2 Stage Model: `ScanStageRun` (`backend/app/db/models/execution.py`)
- **Primary Key:** `id` (`UUID`, generated via `uuid7`).
- **Core Fields:**
  - `project_id`: `UUID` (FK `projects.id`).
  - `scan_id`: `UUID` (FK `scans.id ON DELETE CASCADE`).
  - `stage`: `Text` (`ck_scan_stage_runs_stage`: `'scope','recon','discovery','selection','scanning','agent','correlation','investigation','validation','reporting'`).
  - `attempt`: `Integer` (default 1, `ck_scan_stage_runs_positive_attempt`: `attempt > 0`).
  - `status`: `Text` (`ck_scan_stage_runs_status`: `'pending','running','succeeded','partial','failed','skipped','cancelled'`).
  - `started_at`, `finished_at`: `DateTime(timezone=True)`, nullable.
  - `metrics`: `JSONB` (stage metrics).
  - `error_code`, `error_message`: `Text`, nullable.
- **Database Constraints & Indices:**
  - `uq_scan_stage_runs_scan_stage_attempt` (`scan_id`, `stage`, `attempt`)

### 2.3 Task Model: `ToolExecution` (`backend/app/db/models/execution.py`)
- **Primary Key:** `id` (`UUID`, generated via `uuid7`).
- **Core Fields:**
  - `project_id`: `UUID` (FK `projects.id`).
  - `scan_id`: `UUID` (FK `scans.id ON DELETE CASCADE`).
  - `stage`: `Text`.
  - `tool_version_id`: `UUID` (FK `tool_versions.id`).
  - `status`: `Text` (`ck_tool_executions_status`: `'queued','running','succeeded','failed','timeout','cancelled','skipped','scope_violation'`).
  - `target_asset_id`: `UUID | None` (FK `assets.id`).
  - `endpoint_id`: `UUID | None` (FK `endpoints.asset_id`).
  - `auth_context_id`: `UUID | None`.
  - `input`: `JSONB` (parameters passed to worker).
  - `command_redacted`: `Text | None` (safe command log).
  - `worker_id`: `Text | None` (worker container or node ID).
  - `attempt`: `Integer` (default 1).
  - `parent_execution_id`: `UUID | None` (FK `tool_executions.id`).
  - `started_at`, `finished_at`: `DateTime(timezone=True)`, nullable.
  - `exit_code`: `Integer | None`.
  - `error_code`, `error_message`: `Text | None`.
  - `coverage_summary`: `JSONB`.
  - `stats`: `JSONB`.
  - `cost_usd`: `Numeric(12, 6)` (default 0.0).
- **Database Constraints & Indices:**
  - `ck_tool_executions_status`
  - `ix_tool_executions_scan_status` (`scan_id`, `status`)
  - `ix_tool_executions_project_created` (`project_id`, `created_at`)

---

## 3. Status Mapping & Conceptual Alignment

### 3.1 Job Status Mapping (`Scan.status`)
The prompt outlines conceptual job states: `DRAFT`, `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, `TIMED_OUT`, `CANCELLED`.

In the canonical PostgreSQL schema, `Scan.status` is strictly constrained by:
```sql
CheckConstraint("status IN ('draft','queued','running','paused','completed','failed','cancelled')")
```

**Mapping Analysis:**
1. `DRAFT` -> `'draft'` (exact match).
2. `QUEUED` -> `'queued'` (exact match).
3. `RUNNING` -> `'running'` (exact match).
4. `COMPLETED` -> `'completed'` (exact match).
5. `PARTIALLY_COMPLETED`: Represented as `'completed'` with `stats["partially_completed"] = True` and/or `ScanStageRun.status = 'partial'`. This cleanly avoids modifying the database check constraint while preserving semantic distinction.
6. `FAILED` -> `'failed'` (exact match).
7. `TIMED_OUT`: Represented as `'failed'` with `stats["failure_reason"] = "timeout"` (or `error_code = "JOB_TIMEOUT"`).
8. `CANCELLED` -> `'cancelled'` (exact match).

**Conclusion:** The existing `Scan.status` check constraint is 100% adequate. **No database migration or schema modification is required.**

### 3.2 Task Status Mapping (`ToolExecution.status`)
The canonical check constraint is:
```sql
CheckConstraint("status IN ('queued','running','succeeded','failed','timeout','cancelled','skipped','scope_violation')")
```
All required states (`queued`, `running`, `succeeded`, `failed`, `timeout`, `cancelled`, `scope_violation`) are natively supported by the existing schema!

---

## 4. Existing Concurrency & Isolation Controls

1. **Row-Level Security (RLS):**
   - Direct project tables (`scans`, `scan_stage_runs`, `tool_executions`) enforce `project_id = current_project_id()`.
   - RLS prevents cross-tenant read or write access at the database engine level.
2. **Connection Scavenging:**
   - Database connection checkin/checkout listeners in `backend/app/db/session.py` execute `RESET ALL;` preventing state leakage across requests.
3. **Optimistic & Row-Level Locking:**
   - PostgreSQL `SELECT FOR UPDATE` (`with_for_update()`) provides transaction-local pessimistic locking on `Scan` and `ToolExecution` rows to guarantee atomic, non-conflicting state transitions.

---

## 5. Missing Lifecycle Guarantees to Implement in P3.1.3

1. **Typed Lifecycle Schemas:**
   - Currently, no Pydantic v2 schemas exist in Python code for reconnaissance jobs (`backend/app/recon/` does not exist).
   - Implement `backend/app/recon/schemas.py` containing `ReconJobCreateRequest`, `ReconJobResponse`, `ReconBudgetConfig`, `WorkerTaskEnvelope`, `WorkerTaskResult`, and `NormalizedObservation`.
2. **State Transition Validation Engine:**
   - Create `backend/app/recon/lifecycle.py` enforcing legal state machines for jobs and tasks:
     - Block reactivation of terminal states (`completed`, `failed`, `cancelled` for jobs; `succeeded`, `failed`, `timeout`, `cancelled`, `scope_violation` for tasks).
     - Forbid API clients from directly setting `running` or `completed`.
     - Update timestamps atomically (`started_at`, `finished_at`, `cancel_requested_at`).
3. **Scheduling Preconditions Guard:**
   - Function `validate_recon_task_scheduling()` verifying:
     - Project matching across `Scan`, `Target`, `AuthorizationRecord`, and `ScopeVersion`.
     - Authorization record is active, valid, and permits requested action.
     - Pinned scope version matches active scope version at job creation.
     - Destination passes `evaluate_scope_validation()`.
4. **Task Retry & Scope Violation Invariants:**
   - Enforce bounded retries (`attempt <= max_retries`).
   - Hard invariant: `status == 'scope_violation'` must **never** be automatically retried against the same denied destination.
5. **Stale Worker Defense:**
   - Discard/reject worker results if `result.attempt != execution.attempt` or if the task has already entered a terminal state (`cancelled`, `timeout`).
6. **Typed Lifecycle Exceptions:**
   - Implement `backend/app/recon/exceptions.py` with structured error codes (`RECON_JOB_NOT_FOUND`, `RECON_JOB_INVALID_STATE`, `RECON_TASK_ALREADY_TERMINAL`, `RECON_TASK_SCOPE_DENIED`, etc.).
7. **Audit Trail Recording:**
   - Emit transaction-consistent `AuditLog` records for every state change.

---

## 6. Audit Verdict

The existing PostgreSQL schema (`scans`, `scan_stage_runs`, `tool_executions`, `tools`, `tool_versions`, `assets`, `scope_decisions`, `audit_logs`) fully supports all required lifecycle states and relationships.

No database migrations are needed. Implementation will proceed by creating the dedicated `backend/app/recon/` package containing typed Pydantic schemas, exception classes, lifecycle transition validators, and scheduling precondition guards.
