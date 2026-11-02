# VulnOS — P3.1.3.2 Task Scheduling Preconditions & Concurrency Design
## Precondition Rules, Authorization Checks & Database Locking Architecture

**Date:** 2026-11-02  
**Milestone:** P3.1.3.2  
**Status:** Canonical Design  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

This document specifies the exact pre-dispatch verification requirements that the Orchestrator must satisfy before creating a `ToolExecution` and queueing a `WorkerTaskEnvelope`.

---

## 2. Scheduling Preconditions Specification

The scheduling validation function is defined as:
```python
def validate_recon_task_scheduling(
    db: Session,
    project_id: UUID,
    scan_id: UUID,
    destination: str,
    tool_manifest: ToolManifest,
    now: datetime | None = None,
) -> TaskSchedulingDecision: ...
```

### 2.1 The 13 Mandatory Preconditions

| # | Check Name | Verification Rule | Failure Error Code |
|---|---|---|---|
| **1** | **Scan Existence** | `Scan` record exists with `Scan.id == scan_id`. | `RECON_JOB_NOT_FOUND` |
| **2** | **Scan Project Match** | `Scan.project_id == project_id`. | `RECON_JOB_PROJECT_MISMATCH` |
| **3** | **Scan Type Verification** | `Scan.scan_type == 'recon'`. | `RECON_JOB_INVALID_STATE` |
| **4** | **Scan Schedulable State** | `Scan.status IN ('draft', 'queued', 'running')`. Must not be `paused`, `completed`, `failed`, or `cancelled`. | `RECON_JOB_INVALID_STATE` |
| **5** | **Target Project Match** | Target seed IDs in `Scan.target_ids` belong to `project_id`. | `TARGET_PROJECT_MISMATCH` |
| **6** | **Authorization Project Match** | `Scan.authorization_id` belongs to `project_id`. | `AUTHORIZATION_PROJECT_MISMATCH` |
| **7** | **Authorization Active & Valid** | `AuthorizationRecord.revoked_at IS NULL` and `valid_from <= now <= valid_to`. | `AUTHORIZATION_NOT_ACTIVE` |
| **8** | **Authorization Action Permitted** | Requested action (e.g. `'recon'`, `'discovery'`) is present in `AuthorizationRecord.allowed_actions`. | `ACTION_NOT_PERMITTED` |
| **9** | **Scope Version Project Match** | `Scan.scope_version_id` belongs to `project_id`. | `SCOPE_VERSION_PROJECT_MISMATCH` |
| **10** | **Pinned Scope Consistency** | `Scan.scope_version_id` matches the active scope version at scheduling time, or matches the previously pinned immutable version. | `SCOPE_VERSION_MISMATCH` |
| **11** | **Tool Manifest Trusted** | `tool_manifest.tool_id` is registered in the static Tool Registry with verified `image_digest`. | `TOOL_NOT_REGISTERED` |
| **12** | **Budget Not Exceeded** | `Scan.stats.get("requests_sent", 0) < Scan.budget.get("max_requests")` and wall clock duration < `max_wall_clock_minutes`. | `BUDGET_EXCEEDED` |
| **13** | **Deterministic Scope Engine Approval** | `evaluate_scope_validation(db, project_id, validation_request, scan_id=scan_id)` returns `allowed == True`. | `SCOPE_VALIDATION_DENIED` |

**Security Guarantee:** If any of these 13 checks fails, the task is **not** scheduled, no envelope is queued, and the failure reason is recorded.

---

## 3. Concurrency & Transactional Locking Design

To avoid race conditions and guarantee idempotency under concurrent API or worker requests, the following database locking and state transition protocols are enforced:

### 3.1 Job Status Transitions (`Scan`)
```python
# Acquire transaction-local row-level lock on the Scan record
scan = (
    db.query(Scan)
    .filter(Scan.id == scan_id, Scan.project_id == project_id)
    .with_for_update()
    .one_or_none()
)
```
- **Simultaneous Scheduling Requests:** Two concurrent requests to queue a draft scan will serialize on the row lock; the first transitions `draft -> queued`, while the second detects `status == 'queued'` and returns the current state idempotently without creating duplicate tasks.
- **Simultaneous Cancellation Requests:** Concurrent cancellation calls serialize on the lock; the first updates `cancel_requested_at`, while the second detects cancellation is already in progress and succeeds idempotently.

### 3.2 Task Status Transitions (`ToolExecution`)
```python
execution = (
    db.query(ToolExecution)
    .filter(ToolExecution.id == task_id, ToolExecution.project_id == project_id)
    .with_for_update()
    .one_or_none()
)
```
- **Worker Completion vs Cancellation Race:**
  - If an operator cancels a job, all tasks are marked `status = 'cancelled'`.
  - If a worker finishes after cancellation and attempts to report `status = 'succeeded'`, the orchestrator locks the task row, observes `execution.status == 'cancelled'`, discards the worker output, logs a warning, and prevents resurrecting the cancelled task.
- **Stale Worker Result Defense:**
  - If a task timed out and was retried as attempt 2, and worker 1 belatedly reports, the check `result.attempt == execution.attempt` rejects worker 1's result.

---

## 4. Typed Error Contracts

The following stable error codes and exceptions will be defined in `backend/app/recon/exceptions.py`:

```python
class ReconError(Exception):
    """Base exception for reconnaissance operations."""

    code: str = "RECON_ERROR"
    message: str = "A reconnaissance error occurred."


class ReconJobNotFoundError(ReconError):
    code = "RECON_JOB_NOT_FOUND"


class ReconJobInvalidStateError(ReconError):
    code = "RECON_JOB_INVALID_STATE"


class ReconJobProjectMismatchError(ReconError):
    code = "RECON_JOB_PROJECT_MISMATCH"


class ReconTaskNotFoundError(ReconError):
    code = "RECON_TASK_NOT_FOUND"


class ReconTaskInvalidStateError(ReconError):
    code = "RECON_TASK_INVALID_STATE"


class ReconTaskAlreadyTerminalError(ReconError):
    code = "RECON_TASK_ALREADY_TERMINAL"


class ReconTaskScopeDeniedError(ReconError):
    code = "RECON_TASK_SCOPE_DENIED"


class ReconTaskBudgetExceededError(ReconError):
    code = "RECON_TASK_BUDGET_EXCEEDED"


class ReconToolNotRegisteredError(ReconError):
    code = "RECON_TOOL_NOT_REGISTERED"


class ReconStaleWorkerResultError(ReconError):
    code = "RECON_STALE_WORKER_RESULT"
```
