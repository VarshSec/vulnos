# VulnOS — P3.1.3.4.4.2 Claim Lease Service Implementation Report
## Atomic Task Lease Claiming, Fencing Token Generation & Concurrency Serialization

**Date:** 2026-11-02  
**Milestone:** P3.1.3.4.4.2  
**Status:** Completed & Tested (37/37 Focused Tests Passed | 514/514 Total Project Tests Passed)  
**Author:** Principal Security Architect & Senior Python Backend Engineer  
**Baseline Git Commit:** `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8`  

---

## 1. Overview & Architectural Responsibilities

Milestone **P3.1.3.4.4.2** implements the atomic task lease claiming service (`claim_task_lease`) for the VulnOS reconnaissance subsystem.

The service provides:
1. **Hierarchical Pessimistic Locking:** Guarantees DAG lock order (**Parent `Scan` FOR UPDATE first $\rightarrow$ Child `ToolExecution` FOR UPDATE second**) to eliminate deadlocks and prevent concurrent task claims.
2. **Project & Parent-Child Isolation:** Revalidates that the task and parent scan exist within the caller's tenant (`project_id`) and maintain consistent associations under lock.
3. **Parent Scan State Gating:** Permits claims only if the parent scan is in `'queued'` or `'running'` status. Rejects draft, paused, or terminal scans fail-closed.
4. **State Machine Conformance:** Permits claims only for tasks in `'queued'` status. Rejects already claimed/running tasks (`ReconTaskAlreadyClaimedError`) and terminal/failed tasks (`ReconTaskTerminalStateError`).
5. **Preserved Monotonic Attempt Semantics:** Binds the current active attempt (`task.attempt`). Does **NOT** increment the attempt counter during claiming.
6. **Cryptographic 256-bit Token Generation:** Generates `secrets.token_urlsafe(32)`. Returns the plaintext token only once in the immutable `TaskLeaseClaim` response.
7. **One-Way Hash Persistence (Zero Plaintext Leakage):** Persists only the SHA-256 hash (`task.stats["lease_token_hash"]`) in PostgreSQL. Raw token is never written to disk, audit metadata, or application logs.
8. **Timezone-Aware UTC Expiration:** Computes `lease_expires_at = now + timedelta(seconds=timeout_seconds)` using `utc_now()`.
9. **Timeout Boundary Enforcement:** Validates `30 <= timeout_seconds <= 86400`. Non-integers, booleans, and out-of-range values raise `ReconTaskInvalidTimeoutError`.
10. **Atomic Audit Logging:** Writes `recon_task.lease_claimed` in the exact same transaction. Failure during audit insertion rolls back the claim atomically.

---

## 2. Implemented Code & Interfaces

### 2.1 Exception Additions (`backend/app/recon/exceptions.py`)
- `ReconTaskAlreadyClaimedError`: Raised when a worker attempts to claim a task that is already running, claimed, or not queued.
- `ReconTaskInvalidTimeoutError`: Raised when a claim specifies a timeout outside permitted bounds (30–86400s).
- `ReconTaskInvalidTokenError`: Raised when a worker submits a missing, malformed, or mismatched lease token.
- `ReconTaskLeaseExpiredError`: Raised when a worker submits a result after its lease deadline has passed.

### 2.2 Data Contract: `TaskLeaseClaim` (`backend/app/recon/task_lifecycle.py`)
```python
@dataclass(frozen=True)
class TaskLeaseClaim:
    """Immutable confirmation returned once upon successful lease claim.

    Contains the raw plaintext lease token. The raw token is NEVER persisted in the DB.
    """

    execution_id: UUID
    scan_id: UUID
    project_id: UUID
    attempt: int
    worker_id: str
    lease_token: str  # Raw 256-bit token; returned ONLY once
    lease_expires_at: datetime
    started_at: datetime
```

### 2.3 Service Implementation: `claim_task_lease` (`backend/app/recon/task_lifecycle.py`)
```python
def claim_task_lease(
    db: Session,
    project_id: UUID,
    execution_id: UUID,
    worker_id: str,
    timeout_seconds: int = DEFAULT_LEASE_TIMEOUT_SECONDS,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    evaluation_time: datetime | None = None,
) -> tuple[ToolExecution, TaskLeaseClaim]:
```

---

## 3. Test Coverage Summary (`backend/tests/security/recon/test_claim_task_lease.py`)

37 dedicated security and concurrency test cases validate all aspects of the claim service:

| Test Name | Validated Behavior | Security Invariant |
|---|---|---|
| `test_claim_task_lease_success` | Happy path: status $\rightarrow$ `running`, `started_at` set, `TaskLeaseClaim` returned, token hash persisted in `stats`, `AuditLog` written. | Atomicity & server-controlled UTC timestamps |
| `test_claim_task_lease_parent_scan_queued_permitted` | Parent scan in `queued` status permits task claim. | Lifecycle transition matrix |
| `test_claim_task_lease_parent_scan_disallowed_states` (x5) | Parent scan in `draft`, `paused`, `completed`, `failed`, `cancelled` raises `ReconTaskParentStateInvalidError`. | Fail-closed parent gating |
| `test_claim_task_lease_timeout_boundaries` | Exact boundary checks: 30s and 86400s succeed. | Strict timeout boundary enforcement |
| `test_claim_task_lease_invalid_timeout_rejected` (x10) | Values 29s, 86401s, 0s, -1s, -300s, "300", True, False, 30.5, None raise `ReconTaskInvalidTimeoutError`. | Strict type and range validation |
| `test_claim_task_lease_invalid_worker_id` (x5) | Empty `""`, whitespace `"   "`, None, int, list raise `ReconTaskInvalidActorError`. | Worker identity validation |
| `test_claim_task_lease_duplicate_claim_rejected` | Task in `running` status rejects subsequent claim by competing worker with `ReconTaskAlreadyClaimedError`. Same worker re-claim also rejected. | Race prevention |
| `test_claim_task_lease_terminal_task_rejected` (x6) | Tasks in `succeeded`, `failed`, `timeout`, `cancelled`, `skipped`, `scope_violation` raise `ReconTaskTerminalStateError`. | Terminal state immutability |
| `test_claim_task_lease_attempt_preservation` | Claiming does NOT increment attempt (attempt 1 remains 1, retried attempt 3 remains 3). | Monotonic attempt semantics |
| `test_claim_task_lease_token_cryptographic_uniqueness` | `claim.lease_token` is 256-bit URL-safe string. Verified via `secrets.compare_digest` against SHA-256 hash. | Cryptographic verification & zero token leakage |
| `test_claim_task_lease_cross_project_rejection` | Mismatched `project_id` raises `ReconTaskNotFoundError`. | Multi-tenant isolation |
| `test_claim_task_lease_parent_child_mismatch` | `task.project_id != scan.project_id` raises `ReconJobNotFoundError`. | Tenant consistency |
| `test_claim_task_lease_audit_write_failure_rolls_back` | Database failure during `AuditLog` write rolls back `ToolExecution` status back to `queued`. | Transactional atomicity |
| `test_claim_task_lease_timestamp_timezone_aware` | `started_at` and `lease_expires_at` have timezone `UTC`. | Server-controlled UTC time |
| `test_claim_task_lease_concurrent_claiming_serialization` | Two concurrent claimers: Worker A claims task, Worker B discovers `status == 'running'` and fails closed. | Concurrency serialization |

---

## 4. Verification Evidence

### Quality Gates:
- `uv run ruff check .` $\rightarrow$ **All checks passed! (0 errors)**
- `uv run ruff format --check .` $\rightarrow$ **111 files already formatted**
- `uv run mypy backend tests` $\rightarrow$ **Success: no issues found in 100 source files**
- `uv run alembic heads` $\rightarrow$ **0004 (head)**
- `uv run pytest -v backend/tests/security/recon/test_claim_task_lease.py` $\rightarrow$ **37 passed in 1.19s**
- `uv run pytest -v backend/tests/security/recon/` $\rightarrow$ **97 passed in 2.23s**
- `uv run pytest -q` $\rightarrow$ **514 passed in 12.98s**
