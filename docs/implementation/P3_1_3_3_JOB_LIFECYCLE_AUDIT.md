# VulnOS — P3.1.3.3.1 Job Lifecycle Audit & Implementation Plan
## Reconnaissance Job State Machine, Row-Level Locking & Implementation Roadmap

**Date:** 2026-11-02  
**Milestone:** P3.1.3.3.1  
**Status:** Completed  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

Milestone P3.1.3.3 focuses strictly on implementing the deterministic, transactional lifecycle state machine for reconnaissance jobs using the existing SQLAlchemy `Scan` model.

This audit establishes:
1. Exact verification of existing database constraints (`ck_scans_status`, `ck_scans_scan_type`, `ck_scan_stage_runs_status`).
2. Current code inventory: no Scan services, transition logic, or lifecycle validation currently exists in the backend.
3. PostgreSQL row-level locking (`with_for_update()`) architecture to guarantee concurrency safety and atomic status transitions.
4. Step-by-step roadmap for implementing `backend/app/recon/exceptions.py` and `backend/app/recon/lifecycle.py`.

---

## 2. Actual Database Model Verification

### 2.1 `Scan` Model (`backend/app/db/models/execution.py`)
```python
class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    scan_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_versions.id"), nullable=False)
    authorization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("authorization_records.id"), nullable=False)
    target_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False)
    profile: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False, default=Decimal("0"))
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
```
- **Constraints:**
  - `ck_scans_scan_type`: `scan_type IN ('recon','discovery','web','api','agent','full','validation')`
  - `ck_scans_status`: `status IN ('draft','queued','running','paused','completed','failed','cancelled')`
  - Indices: `ix_scans_project_status` (`project_id`, `status`), `ix_scans_project_created` (`project_id`, `created_at`).

### 2.2 `ScanStageRun` Model (`backend/app/db/models/execution.py`)
```python
class ScanStageRun(Base):
    __tablename__ = "scan_stage_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
```
- **Constraints:**
  - `ck_scan_stage_runs_positive_attempt`: `attempt > 0`
  - `ck_scan_stage_runs_stage`: `stage IN ('scope','recon','discovery','selection','scanning','agent','correlation','investigation','validation','reporting')`
  - `ck_scan_stage_runs_status`: `status IN ('pending','running','succeeded','partial','failed','skipped','cancelled')`
  - `uq_scan_stage_runs_scan_stage_attempt`: `UniqueConstraint("scan_id", "stage", "attempt")`

---

## 3. Canonical Job Transition Matrix Verification

Confirming the 11 valid transitions from `P3_1_3_TRANSITION_MATRIX.md` against `ck_scans_status`:

| ID | From Status | To Status | Permitted Actor | Purpose |
|---|---|---|---|---|
| **T-J01** | `None` | `draft` | `operator`, `admin`, `owner` | Initial plan creation. |
| **T-J02** | `draft` | `queued` | `system` (Orchestrator Gate) | Preconditions and scope pass; pinned to scope version. |
| **T-J03** | `draft` | `cancelled` | `operator`, `admin`, `owner` | Early cancellation of unqueued plan. |
| **T-J04** | `queued` | `running` | `system` (Worker Lease) | First worker task commences execution. |
| **T-J05** | `queued` | `cancelled` | `operator`, `admin`, `owner`, `system` | Cancellation while waiting in queue. |
| **T-J06** | `running` | `completed` | `system` (Orchestrator) | All planned tasks complete (including partial completion). |
| **T-J07** | `running` | `failed` | `system` (Orchestrator) | Fatal job error or wall-clock budget timeout. |
| **T-J08** | `running` | `cancelled` | `operator`, `admin`, `owner`, `system` | Operator cancel request or legal consent revocation. |
| **T-J09** | `running` | `paused` | `operator`, `admin`, `owner` | Operator holds job execution. |
| **T-J10** | `paused` | `running` | `operator`, `admin`, `owner` | Operator resumes job after scope re-validation. |
| **T-J11** | `paused` | `cancelled` | `operator`, `admin`, `owner`, `system` | Job cancelled while paused. |

### Terminal States
- `completed`, `failed`, `cancelled` are strictly terminal. No transitions out of these states are allowed.

---

## 4. Concurrency & Transactional Architecture

### 4.1 Row-Level Pessimistic Locking
```python
scan = (
    db.query(Scan)
    .filter(Scan.id == scan_id, Scan.project_id == project_id)
    .with_for_update()
    .one_or_none()
)
```
- Acquiring `with_for_update()` inside a database transaction guarantees that competing requests (e.g. concurrent cancel requests or worker completion racing against cancellation) are serialized.
- The status is rechecked **after** acquiring the lock to prevent lost updates or stale-state transitions.

### 4.2 Immutable Context Enforcement
Once a `Scan` moves from `draft` to `queued` (or subsequent states), the following fields cannot be modified:
- `project_id`
- `scan_type`
- `scope_version_id`
- `authorization_id`
- `target_ids`
- `budget`
- `requested_by`

Any attempt to update these fields after the job has been queued raises `ReconJobContextImmutableError`.

---

## 5. Implementation Roadmap (P3.1.3.3.2 through P3.1.3.3.9)

1. **P3.1.3.3.2 — Job Transition Validation Function:**
   Implement pure transition validation function in `backend/app/recon/lifecycle.py` and exception classes in `backend/app/recon/exceptions.py`.
2. **P3.1.3.3.3 — Transactional Scan Transition Service:**
   Implement `transition_scan()` with tenant context verification, `with_for_update()`, status recheck, timestamp updates, and audit log generation.
3. **P3.1.3.3.4 — Timestamp & Cancellation Handling:**
   Implement `started_at`, `finished_at`, `cancel_requested_at`, and idempotent cancellation helper `request_scan_cancellation()`.
4. **P3.1.3.3.5 — Partial Completion & Timeout Handling:**
   Implement `complete_scan()` with partial completion recording (`stats["partially_completed"] = True`, `ScanStageRun.status = 'partial'`) and timeout failure handler (`stats["failure_reason"] = "timeout"`).
5. **P3.1.3.3.6 — Pause/Resume & Immutability Guard:**
   Implement `pause_scan()` and `resume_scan()` with authorization and scope revalidation, and `assert_scan_context_immutable()`.
6. **P3.1.3.3.7 — Concurrency & Audit Integration:**
   Verify atomic audit log writes within the same transaction (`db.flush()` / commit boundary).
7. **P3.1.3.3.8 — Adversarial Security Tests:**
   Author `backend/tests/security/recon/test_job_lifecycle.py` testing every valid transition, forbidden transitions, terminal-state immutability, timestamps, cancellation, and concurrency.
8. **P3.1.3.3.9 — Documentation & Quality Gates:**
   Update `P3_1_3_TRANSITION_MATRIX.md`, `PHASE_3_PROGRESS.md`, and author `P3_1_3_3_JOB_LIFECYCLE_DESIGN.md`.
