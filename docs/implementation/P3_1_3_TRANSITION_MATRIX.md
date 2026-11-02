# VulnOS — P3.1.3.2 Lifecycle Transition Matrix
## Formal State Machines, Permitted Actors, Preconditions & Invariants

**Date:** 2026-11-02  
**Milestone:** P3.1.3.2 / P3.1.3.3  
**Status:** Job Transitions Implemented in P3.1.3.3 (`backend/app/recon/lifecycle.py`); Task Transitions Scheduled for P3.1.3.4  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Reconnaissance Job Transition Matrix (`Scan.status`)

Database constraint: `ck_scans_status IN ('draft','queued','running','paused','completed','failed','cancelled')`.

| Transition | From State | To State | Permitted Actor | Preconditions | Timestamp & Attribute Side Effects | Audit Event | Idempotent |
|---|---|---|---|---|---|---|---|
| **T-J01** | `[*] / None` | `draft` | `operator+` | Request passes schema validation; project exists. | `created_at = utc_now()`. | `recon_job.created` | Yes (via idempotency key) |
| **T-J02** | `draft` | `queued` | System / Orchestrator | Target ownership verified; legal consent valid; active scope version exists; central scope check passes. | `scope_version_id` & `authorization_id` pinned; tasks generated. | `recon_job.queued` | Yes |
| **T-J03** | `draft` | `cancelled` | `operator+` | Job in `draft` state. | `finished_at = utc_now()`; `cancel_requested_at = utc_now()`. | `recon_job.cancelled` | Yes |
| **T-J04** | `queued` | `running` | System / Worker | First worker task claims lease. | `started_at = utc_now()`. | `recon_job.started` | Yes |
| **T-J05** | `queued` | `cancelled` | `operator+` | Job in `queued` state. | `finished_at = utc_now()`; `cancel_requested_at = utc_now()`; tasks purged from queue. | `recon_job.cancelled` | Yes |
| **T-J06** | `running` | `completed` | System / Orchestrator | All planned tasks terminal; at least one task succeeded; zero fatal errors. | `finished_at = utc_now()`; `stats` aggregated. | `recon_job.completed` | Yes |
| **T-J07** | `running` | `failed` | System / Orchestrator | Unrecoverable error, database failure, or budget wall-clock timeout exceeded. | `finished_at = utc_now()`; `stats["failure_reason"]` recorded. | `recon_job.failed` | Yes |
| **T-J08** | `running` | `cancelled` | `operator+` | Operator requests cancel during execution. | `cancel_requested_at = utc_now()`; `finished_at = utc_now()`; workers sent cooperative cancel. | `recon_job.cancelled` | Yes |
| **T-J09** | `running` | `paused` | `operator+` | Operator requests temporary pause. | Queued tasks paused; in-flight workers allowed to complete or drain. | `recon_job.paused` | Yes |
| **T-J10** | `paused` | `running` | `operator+` | Pinned authorization & scope version revalidated as still active and valid. | Queue resumed. | `recon_job.resumed` | Yes |
| **T-J11** | `paused` | `cancelled` | `operator+` | Operator cancels while paused (or auth revoked while paused). | `finished_at = utc_now()`; `cancel_requested_at = utc_now()`. | `recon_job.cancelled` | Yes |

### 1.1 Forbidden Job Transitions
- `completed -> *` (Terminal state; reactivation strictly forbidden).
- `failed -> *` (Terminal state; reactivation strictly forbidden).
- `cancelled -> *` (Terminal state; reactivation strictly forbidden).
- `* -> draft` (Cannot revert backward to draft).
- Client-directed transitions: API clients can only request creation (`draft`), scheduling (`queued`), pausing (`paused`), or cancellation (`cancelled`). Clients can **never** directly set `running` or `completed`.

---

## 2. Reconnaissance Task Transition Matrix (`ToolExecution.status`)

Database constraint: `ck_tool_executions_status IN ('queued','running','succeeded','failed','timeout','cancelled','skipped','scope_violation')`.

| Transition | From State | To State | Permitted Actor | Preconditions | Timestamp & Attribute Side Effects | Audit Event | Idempotent |
|---|---|---|---|---|---|---|---|
| **T-T01** | `[*] / None` | `queued` | Orchestrator | Scheduling preconditions pass; `WorkerTaskEnvelope` generated. | `created_at = utc_now()`. | `recon_task.scheduled` | Yes |
| **T-T02** | `queued` | `running` | Worker | Worker claims task lease from queue. | `started_at = utc_now()`; `worker_id` recorded. | `recon_task.started` | Yes |
| **T-T03** | `queued` | `cancelled` | Orchestrator | Parent job cancelled before worker claimed task. | `finished_at = utc_now()`; `error_code = 'JOB_CANCELLED'`. | `recon_task.cancelled` | Yes |
| **T-T04** | `running` | `succeeded` | Orchestrator | Worker exit code 0; raw output uploaded to S3; observations parsed. | `finished_at = utc_now()`; `exit_code = 0`; stats updated. | `recon_task.succeeded` | Yes |
| **T-T05** | `running` | `failed` | Orchestrator | Non-zero exit code or uncaught container exception. | `finished_at = utc_now()`; `exit_code != 0`; `error_code` recorded. | `recon_task.failed` | Yes |
| **T-T06** | `running` | `timeout` | Orchestrator | Container execution duration exceeded `timeout_seconds`. | `finished_at = utc_now()`; `error_code = 'TIMEOUT'`. | `recon_task.timed_out` | Yes |
| **T-T07** | `running` | `cancelled` | Orchestrator | Cooperative cancel token acknowledged by worker. | `finished_at = utc_now()`; `error_code = 'CANCELLED'`. | `recon_task.cancelled` | Yes |
| **T-T08** | `running` | `scope_violation` | Egress Proxy / Orchestrator | Egress guard or runtime check detected unauthorized outbound destination. | `finished_at = utc_now()`; `error_code = 'SCOPE_VIOLATION'`. | `recon_task.scope_violation` | Yes |
| **T-T09** | `queued` | `skipped` | Orchestrator | Upstream dependency failed, or prerequisite missing. | `finished_at = utc_now()`; `error_code = 'DEPENDENCY_FAILED'`. | `recon_task.skipped` | Yes |

### 2.1 Forbidden Task Transitions & Invariants
1. **Scope Violation Non-Retryable:** Any task transitioning to `scope_violation` must **never** be retried automatically.
2. **Terminal Invariance:** Transitions out of terminal states (`succeeded`, `failed`, `timeout`, `cancelled`, `skipped`, `scope_violation`) are **strictly rejected**.
3. **Stale Result Rejection:** If a worker delivers a result for a task that has already transitioned to `timeout` or `cancelled`, the result is dropped with an audit event (`recon_task.stale_result_rejected`).
