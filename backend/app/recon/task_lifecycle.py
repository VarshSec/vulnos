"""Deterministic task lifecycle state machine and transactional service for VulnOS ToolExecution.

Enforces the canonical Task State Machine (T-T01 to T-T11), permitted actor categories,
terminal-state invariance, non-retryability of scope violations, explicit retry contexts,
hierarchical parent-first lock ordering (Scan -> ToolExecution), server-controlled timestamps,
and append-only audit logging.

CRITICAL INVARIANTS:
1. HIERARCHICAL LOCKING: Parent Scan is locked first, ToolExecution second.
2. PURE VALIDATION: Logic separated into deterministic validator and transactional engine.
3. TERMINAL INVARIANCE: 'succeeded', 'cancelled', 'skipped', and 'scope_violation'
   are strictly terminal.
4. SCOPE VIOLATION NON-RETRYABLE: 'scope_violation' can NEVER be retried under any circumstances.
5. IMMUTABLE TIMESTAMPS: Server-controlled UTC timestamps; untrusted worker times discarded.
6. TRANSACTIONAL ATOMICITY: Status mutation and AuditLog persist in the exact same transaction.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.execution import Scan, ToolExecution
from backend.app.db.types import utc_now
from backend.app.recon.exceptions import (
    ReconJobNotFoundError,
    ReconTaskAlreadyClaimedError,
    ReconTaskInvalidActorError,
    ReconTaskInvalidAttemptError,
    ReconTaskInvalidTimeoutError,
    ReconTaskInvalidTransitionError,
    ReconTaskNotFoundError,
    ReconTaskParentStateInvalidError,
    ReconTaskProjectMismatchError,
    ReconTaskRetryNotAllowedError,
    ReconTaskTerminalStateError,
)

# Canonical ToolExecution status values matching ck_tool_executions_status
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_CANCELLED = "cancelled"
STATUS_SKIPPED = "skipped"
STATUS_SCOPE_VIOLATION = "scope_violation"

ALL_TASK_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_TIMEOUT,
        STATUS_CANCELLED,
        STATUS_SKIPPED,
        STATUS_SCOPE_VIOLATION,
    }
)

# Terminal states that cannot transition out under ANY circumstances
PERMANENTLY_TERMINAL_TASK_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_SUCCEEDED,
        STATUS_CANCELLED,
        STATUS_SKIPPED,
        STATUS_SCOPE_VIOLATION,
    }
)

# Canonical Parent Scan status values matching ck_scans_status
SCAN_STATUS_DRAFT = "draft"
SCAN_STATUS_QUEUED = "queued"
SCAN_STATUS_RUNNING = "running"
SCAN_STATUS_PAUSED = "paused"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED = "failed"
SCAN_STATUS_CANCELLED = "cancelled"

ALL_SCAN_STATUSES: frozenset[str] = frozenset(
    {
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_QUEUED,
        SCAN_STATUS_RUNNING,
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    }
)

# Permitted parent Scan statuses for specific task operations
PERMITTED_PARENT_SCAN_STATES_SCHEDULING: frozenset[str] = frozenset(
    {SCAN_STATUS_DRAFT, SCAN_STATUS_QUEUED, SCAN_STATUS_RUNNING}
)
PERMITTED_PARENT_SCAN_STATES_CLAIM: frozenset[str] = frozenset(
    {SCAN_STATUS_QUEUED, SCAN_STATUS_RUNNING}
)
PERMITTED_PARENT_SCAN_STATES_COMPLETION: frozenset[str] = frozenset(
    {SCAN_STATUS_RUNNING, SCAN_STATUS_PAUSED}
)
PERMITTED_PARENT_SCAN_STATES_CANCELLATION: frozenset[str] = frozenset(
    {
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_QUEUED,
        SCAN_STATUS_RUNNING,
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_CANCELLED,
    }
)
PERMITTED_PARENT_SCAN_STATES_SKIPPING: frozenset[str] = frozenset(
    {SCAN_STATUS_DRAFT, SCAN_STATUS_QUEUED, SCAN_STATUS_RUNNING}
)
PERMITTED_PARENT_SCAN_STATES_RETRY: frozenset[str] = frozenset({SCAN_STATUS_RUNNING})

# Permitted lease timeout boundaries
MIN_LEASE_TIMEOUT_SECONDS: int = 30
MAX_LEASE_TIMEOUT_SECONDS: int = 86400  # 24 hours
DEFAULT_LEASE_TIMEOUT_SECONDS: int = 300


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


# Permitted actor categories
ACTOR_SYSTEM = "system"
ACTOR_ORCHESTRATOR = "orchestrator"
ACTOR_WORKER = "worker"
ACTOR_OPERATOR = "operator"
ACTOR_ADMIN = "admin"
ACTOR_OWNER = "owner"
ACTOR_TIMEOUT_CONTROLLER = "timeout_controller"
ACTOR_SCOPE_ENFORCEMENT = "scope_enforcement"

ALL_ACTORS: frozenset[str] = frozenset(
    {
        ACTOR_SYSTEM,
        ACTOR_ORCHESTRATOR,
        ACTOR_WORKER,
        ACTOR_OPERATOR,
        ACTOR_ADMIN,
        ACTOR_OWNER,
        ACTOR_TIMEOUT_CONTROLLER,
        ACTOR_SCOPE_ENFORCEMENT,
    }
)

# Groupings
ORCHESTRATOR_ACTORS: frozenset[str] = frozenset({ACTOR_ORCHESTRATOR, ACTOR_SYSTEM})
OPERATOR_ACTORS: frozenset[str] = frozenset({ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER})
MANAGEMENT_ACTORS: frozenset[str] = ORCHESTRATOR_ACTORS | OPERATOR_ACTORS

# Canonical task transitions mapping: (current_status | None, requested_status) -> allowed actors
VALID_TASK_TRANSITIONS: dict[tuple[str | None, str], frozenset[str]] = {
    # T-T01: None -> queued (Task creation / scheduling)
    (None, STATUS_QUEUED): MANAGEMENT_ACTORS,
    # T-T02: queued -> running (Worker claims lease)
    (STATUS_QUEUED, STATUS_RUNNING): frozenset({ACTOR_WORKER}) | ORCHESTRATOR_ACTORS,
    # T-T03: queued -> cancelled (Cancelled before claim)
    (STATUS_QUEUED, STATUS_CANCELLED): MANAGEMENT_ACTORS,
    # T-T04: running -> succeeded (Worker successful exit 0)
    (STATUS_RUNNING, STATUS_SUCCEEDED): frozenset({ACTOR_WORKER}) | ORCHESTRATOR_ACTORS,
    # T-T05: running -> failed (Worker non-zero exit or container crash)
    (STATUS_RUNNING, STATUS_FAILED): frozenset({ACTOR_WORKER}) | ORCHESTRATOR_ACTORS,
    # T-T06: running -> timeout (Duration exceeded)
    (STATUS_RUNNING, STATUS_TIMEOUT): frozenset({ACTOR_TIMEOUT_CONTROLLER}) | ORCHESTRATOR_ACTORS,
    # T-T07: running -> cancelled (Cancelled while in flight)
    (STATUS_RUNNING, STATUS_CANCELLED): MANAGEMENT_ACTORS,
    # T-T08: running -> scope_violation (Egress guard / scope engine violation)
    (STATUS_RUNNING, STATUS_SCOPE_VIOLATION): frozenset({ACTOR_SCOPE_ENFORCEMENT})
    | ORCHESTRATOR_ACTORS,
    # T-T09: queued -> skipped (Dependency failure)
    (STATUS_QUEUED, STATUS_SKIPPED): ORCHESTRATOR_ACTORS,
    # T-T10: failed -> queued (Authorized retry)
    (STATUS_FAILED, STATUS_QUEUED): MANAGEMENT_ACTORS,
    # T-T11: timeout -> queued (Authorized retry)
    (STATUS_TIMEOUT, STATUS_QUEUED): MANAGEMENT_ACTORS,
}


def validate_tool_execution_transition(
    current_status: str | None,
    requested_status: str,
    actor_type: str,
    parent_scan_status: str | None = None,
    context: dict[str, Any] | None = None,
) -> bool:
    """Validate whether an individual task (ToolExecution) state transition is permitted.

    Pure deterministic validation function. Never queries the database, mutates objects,
    or writes audit logs.

    Args:
        current_status: Current status of the task ('queued', 'running', etc.), or None
            for newly created tasks.
        requested_status: Desired destination status.
        actor_type: Category of the actor requesting the transition.
        parent_scan_status: Optional current status of the parent Scan record.
        context: Optional dictionary containing execution context ('is_retry', 'attempt',
            'max_attempts', 'worker_id', etc.). Must not be mutated.

    Returns:
        True if the transition is fully authorized and valid.

    Raises:
        ReconTaskInvalidActorError: If actor_type is unknown or unauthorized for this transition.
        ReconTaskInvalidTransitionError: If the transition path is illegal or status is unknown.
        ReconTaskTerminalStateError: If attempting to transition out of a terminal state.
        ReconTaskRetryNotAllowedError: If a retry is attempted on a non-retryable state or
            without explicit retry context.
        ReconTaskInvalidAttemptError: If attempt context contains invalid attempt numbers.
        ReconTaskParentStateInvalidError: If parent Scan state forbids this task transition.
    """
    # 1. Validate actor category
    if actor_type not in ALL_ACTORS:
        raise ReconTaskInvalidActorError(
            f"Unknown or unauthorized actor type '{actor_type}'. Permitted actors: "
            f"{sorted(ALL_ACTORS)}."
        )

    # 2. Validate status values
    if requested_status not in ALL_TASK_STATUSES:
        raise ReconTaskInvalidTransitionError(
            f"Requested status '{requested_status}' is invalid. Allowed statuses: "
            f"{sorted(ALL_TASK_STATUSES)}."
        )
    if current_status is not None and current_status not in ALL_TASK_STATUSES:
        raise ReconTaskInvalidTransitionError(
            f"Current status '{current_status}' is invalid. Allowed statuses: "
            f"{sorted(ALL_TASK_STATUSES)}."
        )

    # 3. Idempotent self-transition check
    if current_status == requested_status:
        if current_status is None:
            raise ReconTaskInvalidTransitionError("Cannot transition None to None.")
        return True

    # 4. Strict terminal-state invariance checks
    if current_status == STATUS_SCOPE_VIOLATION:
        raise ReconTaskRetryNotAllowedError(
            "Task reached status 'scope_violation'. Scope violations are permanently non-retryable "
            "to prevent unauthorized network egress or repeated hammering of unapproved targets."
        )
    if current_status in PERMANENTLY_TERMINAL_TASK_STATUSES:
        raise ReconTaskTerminalStateError(
            f"Cannot transition task from terminal status '{current_status}' to "
            f"'{requested_status}'. Terminal states are immutable."
        )

    # 5. Retry validation logic
    is_retry_transition = (
        current_status in (STATUS_FAILED, STATUS_TIMEOUT) and requested_status == STATUS_QUEUED
    )
    is_retry_requested = context is not None and bool(context.get("is_retry", False))

    if is_retry_transition:
        if not is_retry_requested:
            raise ReconTaskRetryNotAllowedError(
                f"Transition from '{current_status}' to 'queued' represents a retry and requires "
                "an explicit retry context ('is_retry=True')."
            )
        # Validate attempt parameter if supplied in context
        if context is not None and "attempt" in context:
            attempt_val = context["attempt"]
            if isinstance(attempt_val, bool) or not isinstance(attempt_val, int) or attempt_val < 1:
                raise ReconTaskInvalidAttemptError(
                    f"Attempt must be a positive integer, got: {attempt_val!r}."
                )
            max_attempts = context.get("max_attempts", 3)
            if attempt_val >= max_attempts:
                raise ReconTaskRetryNotAllowedError(
                    f"Task attempt {attempt_val} has reached or exceeded maximum allowed attempts "
                    f"({max_attempts})."
                )
    elif is_retry_requested:
        raise ReconTaskRetryNotAllowedError(
            f"Cannot retry task with status '{current_status}'. Only 'failed' and 'timeout' tasks "
            "are eligible for authorized retries."
        )
    elif current_status in (STATUS_FAILED, STATUS_TIMEOUT):
        # Failed or timeout without is_retry cannot jump to other statuses
        raise ReconTaskTerminalStateError(
            f"Cannot transition task from '{current_status}' to '{requested_status}'. "
            "Failed and timeout tasks can only return to 'queued' via an authorized retry."
        )

    # 6. Validate transition path
    transition_key = (current_status, requested_status)
    if transition_key not in VALID_TASK_TRANSITIONS:
        raise ReconTaskInvalidTransitionError(
            f"Transition from '{current_status}' to '{requested_status}' is not permitted."
        )

    # 7. Validate actor authorization for this specific transition
    permitted_actors = VALID_TASK_TRANSITIONS[transition_key]
    if actor_type not in permitted_actors:
        raise ReconTaskInvalidActorError(
            f"Actor '{actor_type}' is not authorized for transition '{current_status}' -> "
            f"'{requested_status}'. Authorized actors: {sorted(permitted_actors)}."
        )

    # 8. Validate worker context requirements
    if actor_type == ACTOR_WORKER:
        if context is None or not context.get("worker_id"):
            raise ReconTaskInvalidActorError(
                "Worker-originated task transitions require a non-empty 'worker_id' in context."
            )
        # Worker completions require attempt in context
        if requested_status in (STATUS_SUCCEEDED, STATUS_FAILED):
            if context is None or "attempt" not in context:
                raise ReconTaskInvalidAttemptError(
                    "Worker completion transitions require 'attempt' in context."
                )
            attempt_val = context["attempt"]
            if isinstance(attempt_val, bool) or not isinstance(attempt_val, int) or attempt_val < 1:
                raise ReconTaskInvalidAttemptError(
                    f"Worker attempt must be a positive integer, got: {attempt_val!r}."
                )

    # 9. Validate parent Scan status if provided
    if parent_scan_status is not None:
        if parent_scan_status not in ALL_SCAN_STATUSES:
            raise ReconTaskParentStateInvalidError(
                f"Unknown parent Scan status '{parent_scan_status}'."
            )

        if transition_key == (None, STATUS_QUEUED):
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_SCHEDULING:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot schedule task while parent Scan has status '{parent_scan_status}'. "
                    f"Permitted: {sorted(PERMITTED_PARENT_SCAN_STATES_SCHEDULING)}."
                )
        elif transition_key == (STATUS_QUEUED, STATUS_RUNNING):
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_CLAIM:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot claim task lease while parent Scan has status '{parent_scan_status}'. "
                    f"Permitted: {sorted(PERMITTED_PARENT_SCAN_STATES_CLAIM)}."
                )
        elif transition_key in (
            (STATUS_RUNNING, STATUS_SUCCEEDED),
            (STATUS_RUNNING, STATUS_FAILED),
            (STATUS_RUNNING, STATUS_TIMEOUT),
            (STATUS_RUNNING, STATUS_SCOPE_VIOLATION),
        ):
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_COMPLETION:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot report task completion while parent Scan has status "
                    f"'{parent_scan_status}'. Permitted: "
                    f"{sorted(PERMITTED_PARENT_SCAN_STATES_COMPLETION)}."
                )
        elif requested_status == STATUS_CANCELLED:
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_CANCELLATION:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot cancel task while parent Scan has status '{parent_scan_status}'. "
                    f"Permitted: {sorted(PERMITTED_PARENT_SCAN_STATES_CANCELLATION)}."
                )
        elif transition_key == (STATUS_QUEUED, STATUS_SKIPPED):
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_SKIPPING:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot skip task while parent Scan has status '{parent_scan_status}'. "
                    f"Permitted: {sorted(PERMITTED_PARENT_SCAN_STATES_SKIPPING)}."
                )
        elif is_retry_transition:
            if parent_scan_status not in PERMITTED_PARENT_SCAN_STATES_RETRY:
                raise ReconTaskParentStateInvalidError(
                    f"Cannot retry task while parent Scan has status '{parent_scan_status}'. "
                    f"Tasks can only be retried when parent Scan is '{SCAN_STATUS_RUNNING}'."
                )

    return True


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _map_to_audit_actor_type(actor_type: str) -> str:
    """Map task lifecycle actor roles to database AuditLog.actor_type.

    Constraint: ck_audit_logs_actor_type IN ('user','api_key','system','worker','model').
    """
    if actor_type in (ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER):
        return "user"
    if actor_type == ACTOR_WORKER:
        return "worker"
    if actor_type in (
        ACTOR_SYSTEM,
        ACTOR_ORCHESTRATOR,
        ACTOR_TIMEOUT_CONTROLLER,
        ACTOR_SCOPE_ENFORCEMENT,
    ):
        return "system"
    if actor_type in ("user", "api_key", "system", "worker", "model"):
        return actor_type
    return "system"


def transition_tool_execution(
    db: Session,
    project_id: UUID,
    execution_id: UUID,
    new_status: str,
    actor_id: str,
    actor_type: str = ACTOR_SYSTEM,
    reason: str | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
    exit_code: int | None = None,
    worker_id: str | None = None,
    cost_usd: Decimal | None = None,
    stats: dict[str, Any] | None = None,
    coverage_summary: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    evaluation_time: datetime | None = None,
    context: dict[str, Any] | None = None,
) -> ToolExecution:
    """Perform a transactional, concurrency-safe ToolExecution state transition.

    Enforces hierarchical row-level locking (Parent Scan FIRST, ToolExecution SECOND),
    validates the state machine via validate_tool_execution_transition(), updates
    server-controlled UTC timestamps, and writes an append-only AuditLog in the same transaction.

    Raises:
        ReconTaskNotFoundError: If task does not exist in project.
        ReconJobNotFoundError: If parent Scan does not exist in project.
        ReconTaskProjectMismatchError: If task and scan have mismatched projects.
        ReconTaskInvalidTransitionError: If transition is illegal.
        ReconTaskTerminalStateError: If task is in a terminal state.
        ReconTaskInvalidActorError: If actor lacks permission.
        ReconTaskParentStateInvalidError: If parent Scan status forbids transition.
    """
    now = evaluation_time or utc_now()

    if new_status == STATUS_QUEUED:
        raise ReconTaskInvalidTransitionError(
            "Direct transition to 'queued' is not supported in transition_tool_execution. "
            "Task retries must be performed via retry_tool_execution."
        )

    # 1. Lookup task reference to obtain parent scan_id
    task_scan_id = db.scalar(
        select(ToolExecution.scan_id).where(
            ToolExecution.id == execution_id,
            ToolExecution.project_id == project_id,
        )
    )
    if task_scan_id is None:
        raise ReconTaskNotFoundError(
            f"Tool execution '{execution_id}' not found in project '{project_id}'."
        )

    # 2. Acquire pessimistic row-level lock on Parent Scan FIRST (Hierarchical Lock Order)
    scan = db.scalar(
        select(Scan)
        .where(
            Scan.id == task_scan_id,
            Scan.project_id == project_id,
        )
        .with_for_update()
    )
    if scan is None:
        raise ReconJobNotFoundError(
            f"Parent reconnaissance job '{task_scan_id}' not found in project '{project_id}'."
        )

    # 3. Acquire pessimistic row-level lock on ToolExecution row SECOND
    task = db.scalar(
        select(ToolExecution)
        .where(
            ToolExecution.id == execution_id,
            ToolExecution.project_id == project_id,
        )
        .with_for_update()
    )
    if task is None:
        raise ReconTaskNotFoundError(
            f"Tool execution '{execution_id}' not found in project '{project_id}'."
        )

    # 4. Re-verify parent-child association under locks
    if task.scan_id != scan.id or task.project_id != project_id:
        raise ReconTaskProjectMismatchError(
            f"Task '{execution_id}' has inconsistent parent scan or project association."
        )

    current_status = task.status

    # 5. Idempotent self-transition check under lock
    if current_status == new_status:
        return task

    # 6. Prepare validation context
    ctx = dict(context) if context else {}
    if worker_id and "worker_id" not in ctx:
        ctx["worker_id"] = worker_id
    elif task.worker_id and "worker_id" not in ctx:
        ctx["worker_id"] = task.worker_id

    if "attempt" not in ctx:
        ctx["attempt"] = task.attempt

    # 7. Validate transition using pure validator
    validate_tool_execution_transition(
        current_status=current_status,
        requested_status=new_status,
        actor_type=actor_type,
        parent_scan_status=scan.status,
        context=ctx,
    )

    # 8. Apply server-controlled timestamps and state updates
    if new_status == STATUS_RUNNING:
        if task.started_at is None:
            task.started_at = now
        effective_worker_id = worker_id or ctx.get("worker_id")
        if effective_worker_id:
            task.worker_id = effective_worker_id

    terminal_statuses = (
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_TIMEOUT,
        STATUS_CANCELLED,
        STATUS_SCOPE_VIOLATION,
        STATUS_SKIPPED,
    )
    if new_status in terminal_statuses and task.finished_at is None:
        task.finished_at = now

    if exit_code is not None:
        task.exit_code = exit_code

    if error_code is not None:
        task.error_code = error_code
    elif new_status == STATUS_CANCELLED and task.error_code is None:
        task.error_code = "CANCELLED"
    elif new_status == STATUS_TIMEOUT and task.error_code is None:
        task.error_code = "TIMEOUT"
    elif new_status == STATUS_SCOPE_VIOLATION and task.error_code is None:
        task.error_code = "SCOPE_VIOLATION"
    elif new_status == STATUS_SKIPPED and task.error_code is None:
        task.error_code = "DEPENDENCY_FAILED"

    if error_message is not None:
        task.error_message = error_message
    elif reason is not None and task.error_message is None:
        task.error_message = reason

    if cost_usd is not None:
        task.cost_usd = cost_usd

    if stats:
        updated_stats = dict(task.stats) if task.stats else {}
        updated_stats.update(stats)
        task.stats = updated_stats
        flag_modified(task, "stats")

    if coverage_summary:
        updated_cov = dict(task.coverage_summary) if task.coverage_summary else {}
        updated_cov.update(coverage_summary)
        task.coverage_summary = updated_cov
        flag_modified(task, "coverage_summary")

    # 9. Apply new status and flush
    task.status = new_status
    db.flush()

    # 10. Record transaction-consistent AuditLog entry
    action_map = {
        STATUS_RUNNING: "recon_task.started",
        STATUS_SUCCEEDED: "recon_task.succeeded",
        STATUS_FAILED: "recon_task.failed",
        STATUS_TIMEOUT: "recon_task.timed_out",
        STATUS_CANCELLED: "recon_task.cancelled",
        STATUS_SCOPE_VIOLATION: "recon_task.scope_violation",
        STATUS_SKIPPED: "recon_task.skipped",
    }
    audit_action = action_map.get(new_status, f"recon_task.{new_status}")

    audit_entry = AuditLog(
        action=audit_action,
        actor_type=_map_to_audit_actor_type(actor_type),
        actor_id=actor_id,
        project_id=project_id,
        entity_type="tool_execution",
        entity_id=str(task.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "actor_role": actor_type,
            "scan_id": str(scan.id),
            "previous_status": current_status,
            "new_status": new_status,
            "attempt": task.attempt,
            "worker_id": task.worker_id,
            "exit_code": task.exit_code,
            "error_code": task.error_code,
            "reason": reason,
            "correlation_id": correlation_id,
        },
    )
    db.add(audit_entry)
    db.flush()

    return task


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
    """Atomically claim a queued ToolExecution lease for a specific worker.

    Enforces:
    1. Parent Scan row lock FIRST, ToolExecution row lock SECOND.
    2. Revalidates project ownership and parent-child consistency under lock.
    3. Permits claims only for eligible queued tasks and permitted parent Scan
       states ('queued', 'running').
    4. Binds the existing active attempt; does NOT increment attempt during claim.
    5. Generates cryptographically secure token using secrets.token_urlsafe(32).
    6. Returns raw token only once in immutable TaskLeaseClaim.
    7. Persists only the SHA-256 token hash in stats['lease_token_hash'].
    8. Sets lease expiry using timezone-aware server UTC time.
    9. Enforces timeout bounds between 30 and 86400 seconds.
    10. Inserts 'recon_task.lease_claimed' AuditLog in the exact same transaction.
    11. Rollback on audit failure rolls back the claim atomically.

    Raises:
        ReconTaskInvalidActorError: If worker_id is empty or invalid.
        ReconTaskInvalidTimeoutError: If timeout_seconds is outside 30-86400s or not an int.
        ReconTaskNotFoundError: If task not found in project.
        ReconJobNotFoundError: If parent Scan not found in project.
        ReconTaskProjectMismatchError: If task and scan have mismatched projects.
        ReconTaskParentStateInvalidError: If parent Scan state forbids claim.
        ReconTaskAlreadyClaimedError: If task is already running/claimed.
        ReconTaskTerminalStateError: If task is in a terminal state.
        ReconTaskInvalidTransitionError: If task is not in queued status.
    """
    now = _ensure_utc(evaluation_time or utc_now())
    if now is None:
        now = utc_now()

    # 1. Validate worker_id
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ReconTaskInvalidActorError("Worker ID must be a non-empty string.")
    sanitized_worker_id = worker_id.strip()

    # 2. Validate timeout_seconds
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds < MIN_LEASE_TIMEOUT_SECONDS
        or timeout_seconds > MAX_LEASE_TIMEOUT_SECONDS
    ):
        raise ReconTaskInvalidTimeoutError(
            f"Lease timeout must be an integer between {MIN_LEASE_TIMEOUT_SECONDS} and "
            f"{MAX_LEASE_TIMEOUT_SECONDS} seconds, got: {timeout_seconds!r}."
        )

    # 3. Read scan_id for task to prepare hierarchical lock
    task_scan_id = db.scalar(
        select(ToolExecution.scan_id).where(
            ToolExecution.id == execution_id,
            ToolExecution.project_id == project_id,
        )
    )
    if task_scan_id is None:
        raise ReconTaskNotFoundError(
            f"Tool execution '{execution_id}' not found in project '{project_id}'."
        )

    # 4. Acquire pessimistic row-level lock on Parent Scan FIRST (Hierarchical Lock Order)
    scan = db.scalar(
        select(Scan)
        .where(
            Scan.id == task_scan_id,
            Scan.project_id == project_id,
        )
        .with_for_update()
    )
    if scan is None:
        raise ReconJobNotFoundError(
            f"Parent reconnaissance job '{task_scan_id}' not found in project '{project_id}'."
        )

    # 5. Acquire pessimistic row-level lock on ToolExecution row SECOND
    task = db.scalar(
        select(ToolExecution)
        .where(
            ToolExecution.id == execution_id,
            ToolExecution.project_id == project_id,
        )
        .with_for_update()
    )
    if task is None:
        raise ReconTaskNotFoundError(
            f"Tool execution '{execution_id}' not found in project '{project_id}'."
        )

    # 6. Re-verify parent-child association under locks
    if task.scan_id != scan.id or task.project_id != project_id:
        raise ReconTaskProjectMismatchError(
            f"Task '{execution_id}' has inconsistent parent scan or project association."
        )

    # 7. Validate parent Scan state permits task claim
    if scan.status not in PERMITTED_PARENT_SCAN_STATES_CLAIM:
        raise ReconTaskParentStateInvalidError(
            f"Cannot claim task lease while parent Scan has status '{scan.status}'. "
            f"Permitted: {sorted(PERMITTED_PARENT_SCAN_STATES_CLAIM)}."
        )

    # 8. Validate task status permits claim
    if task.status == STATUS_RUNNING:
        raise ReconTaskAlreadyClaimedError(
            f"Task '{execution_id}' is already running/claimed by worker '{task.worker_id}'."
        )
    if task.status in PERMANENTLY_TERMINAL_TASK_STATUSES or task.status in (
        STATUS_FAILED,
        STATUS_TIMEOUT,
    ):
        raise ReconTaskTerminalStateError(
            f"Cannot claim task '{execution_id}' with terminal or completed status '{task.status}'."
        )
    if task.status != STATUS_QUEUED:
        raise ReconTaskInvalidTransitionError(
            f"Cannot claim task '{execution_id}' with status '{task.status}'. "
            "Expected status 'queued'."
        )

    # 9. Bind existing active attempt without incrementing
    active_attempt = task.attempt

    # 10. Run pure validator to ensure state machine compliance
    validate_tool_execution_transition(
        current_status=STATUS_QUEUED,
        requested_status=STATUS_RUNNING,
        actor_type=ACTOR_WORKER,
        parent_scan_status=scan.status,
        context={"worker_id": sanitized_worker_id, "attempt": active_attempt},
    )

    # 11. Generate cryptographically secure token & hash
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    lease_expires_at = now + timedelta(seconds=timeout_seconds)

    # 12. Apply state mutations to task
    task.status = STATUS_RUNNING
    task.worker_id = sanitized_worker_id
    task.started_at = now

    updated_stats = dict(task.stats) if task.stats else {}
    updated_stats["lease_token_hash"] = token_hash
    updated_stats["lease_expires_at"] = lease_expires_at.isoformat()
    updated_stats["lease_timeout_seconds"] = timeout_seconds
    task.stats = updated_stats
    flag_modified(task, "stats")

    db.flush()

    # 13. Persist recon_task.lease_claimed AuditLog (ZERO token material in metadata)
    audit_entry = AuditLog(
        action="recon_task.lease_claimed",
        actor_type="worker",
        actor_id=sanitized_worker_id,
        project_id=project_id,
        entity_type="tool_execution",
        entity_id=str(task.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "scan_id": str(scan.id),
            "attempt": active_attempt,
            "worker_id": sanitized_worker_id,
            "timeout_seconds": timeout_seconds,
            "lease_expires_at": lease_expires_at.isoformat(),
            "correlation_id": correlation_id,
        },
    )
    db.add(audit_entry)
    db.flush()

    # 14. Return immutable claim confirmation and task
    claim = TaskLeaseClaim(
        execution_id=task.id,
        scan_id=scan.id,
        project_id=project_id,
        attempt=active_attempt,
        worker_id=sanitized_worker_id,
        lease_token=raw_token,
        lease_expires_at=lease_expires_at,
        started_at=now,
    )
    return task, claim
