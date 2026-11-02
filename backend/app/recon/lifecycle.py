"""Deterministic, transactional lifecycle state machine for VulnOS reconnaissance jobs (Scan).

Provides state transition validation, PostgreSQL row-level locking (with_for_update),
server-controlled UTC timestamps, immutable execution context protection,
idempotent cancellation, partial completion handling, and append-only audit logging.

CRITICAL INVARIANTS:
1. Terminal states ('completed', 'failed', 'cancelled') can NEVER be reactivated.
2. API clients can NEVER directly transition a scan to 'running' or 'completed'.
3. Execution context ('authorization_id', 'scope_version_id', 'target_ids', 'budget')
   is strictly immutable once the scan is queued or running.
4. Cancellation is strictly idempotent and cannot overwrite terminal timestamps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.execution import Scan, ScanStageRun
from backend.app.db.models.identity import AuthorizationRecord, ScopeVersion
from backend.app.db.types import utc_now
from backend.app.recon.exceptions import (
    ReconInvalidActorError,
    ReconJobAlreadyTerminalError,
    ReconJobAuthorizationInvalidError,
    ReconJobContextImmutableError,
    ReconJobInvalidStateError,
    ReconJobNotFoundError,
    ReconJobScopeInvalidError,
)

# Canonical Scan status values matching ck_scans_status
STATUS_DRAFT = "draft"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

ALL_JOB_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_DRAFT,
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_PAUSED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    }
)

TERMINAL_JOB_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    }
)

# Immutable execution fields that cannot be altered after a Scan leaves 'draft'
IMMUTABLE_EXECUTION_FIELDS: frozenset[str] = frozenset(
    {
        "project_id",
        "scan_type",
        "scope_version_id",
        "authorization_id",
        "target_ids",
        "budget",
        "requested_by",
    }
)

# Permitted actor categories
ACTOR_SYSTEM = "system"
ACTOR_WORKER = "worker"
ACTOR_OPERATOR = "operator"
ACTOR_ADMIN = "admin"
ACTOR_OWNER = "owner"

# Authorized transitions mapping: (current_status, requested_status) -> allowed actor categories
VALID_JOB_TRANSITIONS: dict[tuple[str, str], frozenset[str]] = {
    # T-J02: draft -> queued
    (STATUS_DRAFT, STATUS_QUEUED): frozenset(
        {ACTOR_SYSTEM, ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER}
    ),
    # T-J03: draft -> cancelled
    (STATUS_DRAFT, STATUS_CANCELLED): frozenset({ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER}),
    # T-J04: queued -> running
    (STATUS_QUEUED, STATUS_RUNNING): frozenset({ACTOR_SYSTEM, ACTOR_WORKER}),
    # T-J05: queued -> cancelled
    (STATUS_QUEUED, STATUS_CANCELLED): frozenset(
        {ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER, ACTOR_SYSTEM}
    ),
    # T-J06: running -> completed
    (STATUS_RUNNING, STATUS_COMPLETED): frozenset({ACTOR_SYSTEM}),
    # T-J07: running -> failed
    (STATUS_RUNNING, STATUS_FAILED): frozenset({ACTOR_SYSTEM}),
    # T-J08: running -> cancelled
    (STATUS_RUNNING, STATUS_CANCELLED): frozenset(
        {ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER, ACTOR_SYSTEM}
    ),
    # T-J09: running -> paused
    (STATUS_RUNNING, STATUS_PAUSED): frozenset({ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER}),
    # T-J10: paused -> running
    (STATUS_PAUSED, STATUS_RUNNING): frozenset({ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER}),
    # T-J11: paused -> cancelled
    (STATUS_PAUSED, STATUS_CANCELLED): frozenset(
        {ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER, ACTOR_SYSTEM}
    ),
}


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _map_to_audit_actor_type(actor_type: str) -> str:
    """Map lifecycle actor roles ('operator', 'admin', 'owner') to database AuditLog.actor_type.

    Constraint: ck_audit_logs_actor_type IN ('user','api_key','system','worker','model').
    """
    if actor_type in (ACTOR_OPERATOR, ACTOR_ADMIN, ACTOR_OWNER):
        return "user"
    if actor_type in ("user", "api_key", "system", "worker", "model"):
        return actor_type
    return "system"


def validate_scan_transition(
    current_status: str,
    requested_status: str,
    actor_type: str,
    context: dict[str, Any] | None = None,
) -> bool:
    """Validate whether a scan state transition is permitted.

    Pure deterministic validation function. Never mutates the Scan instance.

    Returns:
        True if transition is valid (or an idempotent no-op).

    Raises:
        ReconJobInvalidStateError: If status is unknown or transition is illegal.
        ReconJobAlreadyTerminalError: If attempting to transition out of a terminal state.
        ReconInvalidActorError: If actor lacks permission for this transition.
    """
    if current_status not in ALL_JOB_STATUSES:
        raise ReconJobInvalidStateError(f"Unknown current scan status: '{current_status}'.")
    if requested_status not in ALL_JOB_STATUSES:
        raise ReconJobInvalidStateError(f"Unknown requested scan status: '{requested_status}'.")

    # Idempotent no-op check
    if current_status == requested_status:
        return True

    # Terminal state reactivation check
    if current_status in TERMINAL_JOB_STATUSES:
        raise ReconJobAlreadyTerminalError(
            f"Cannot transition scan from terminal state '{current_status}' "
            f"to '{requested_status}'."
        )

    # Valid transition lookup
    transition_key = (current_status, requested_status)
    allowed_actors = VALID_JOB_TRANSITIONS.get(transition_key)
    if allowed_actors is None:
        raise ReconJobInvalidStateError(
            f"Illegal scan state transition from '{current_status}' to '{requested_status}'."
        )

    # Actor authorization check
    norm_actor = actor_type.lower()
    if norm_actor not in allowed_actors:
        raise ReconInvalidActorError(
            f"Actor '{norm_actor}' is not authorized to transition scan from "
            f"'{current_status}' to '{requested_status}'. Permitted: {sorted(allowed_actors)}."
        )

    return True


def assert_scan_context_immutable(scan: Scan, incoming_data: dict[str, Any]) -> None:
    """Enforce that execution context fields cannot be modified after leaving 'draft' status.

    Raises:
        ReconJobContextImmutableError: If any immutable field differs from the persisted record.
    """
    if scan.status == STATUS_DRAFT:
        return

    violations: list[str] = []
    for field in IMMUTABLE_EXECUTION_FIELDS:
        if field in incoming_data:
            incoming_val = incoming_data[field]
            current_val = getattr(scan, field)

            # Handle list comparison for target_ids
            if field == "target_ids":
                if [str(tid) for tid in incoming_val] != [str(tid) for tid in current_val]:
                    violations.append(field)
            # Handle UUID comparison
            elif (
                isinstance(current_val, UUID) and str(current_val) != str(incoming_val)
            ) or incoming_val != current_val:
                violations.append(field)

    if violations:
        msg = (
            f"Cannot modify immutable execution context fields on scan with status "
            f"'{scan.status}': {sorted(violations)}."
        )
        raise ReconJobContextImmutableError(msg)


def transition_scan(
    db: Session,
    project_id: UUID,
    scan_id: UUID,
    new_status: str,
    actor_id: str,
    actor_type: str = ACTOR_SYSTEM,
    reason: str | None = None,
    failure_reason: str | None = None,
    is_partial: bool = False,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    evaluation_time: datetime | None = None,
) -> Scan:
    """Perform a transactional, concurrency-safe scan state transition.

    Enforces PostgreSQL row-level locking (with_for_update), re-checks status under the lock,
    updates server-controlled timestamps, synchronizes ScanStageRun, and logs an append-only
    AuditLog.

    Raises:
        ReconJobNotFoundError: If scan does not exist in project.
        ReconJobAlreadyTerminalError: If scan is already in a terminal state.
        ReconJobInvalidStateError: If transition is illegal.
        ReconInvalidActorError: If actor is unauthorized for transition.
    """
    now = evaluation_time or utc_now()

    # 1. Acquire pessimistic row-level lock on the Scan record
    stmt = select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id).with_for_update()
    scan = db.scalar(stmt)
    if scan is None:
        raise ReconJobNotFoundError(
            f"Reconnaissance job '{scan_id}' not found in project '{project_id}'."
        )

    current_status = scan.status

    # 2. Idempotency handling under lock
    if current_status == new_status:
        return scan

    # 3. Validate state transition rules and actor permissions
    validate_scan_transition(current_status, new_status, actor_type)

    # 4. Server-controlled timestamp management
    if new_status == STATUS_RUNNING and scan.started_at is None:
        scan.started_at = now

    if new_status in TERMINAL_JOB_STATUSES and scan.finished_at is None:
        scan.finished_at = now

    if new_status == STATUS_CANCELLED and scan.cancel_requested_at is None:
        scan.cancel_requested_at = now

    # 5. Partial completion and failure telemetry handling
    updated_stats = dict(scan.stats) if scan.stats else {}
    if new_status == STATUS_COMPLETED and is_partial:
        updated_stats["partially_completed"] = True
    if new_status == STATUS_FAILED and failure_reason:
        updated_stats["failure_reason"] = failure_reason
    if correlation_id:
        updated_stats["correlation_id"] = correlation_id

    scan.stats = updated_stats
    flag_modified(scan, "stats")

    # 6. Apply status change
    scan.status = new_status
    scan.updated_at = now
    db.flush()

    # 7. Synchronize associated ScanStageRun (if present)
    stage_run = db.scalar(
        select(ScanStageRun)
        .where(
            ScanStageRun.scan_id == scan.id,
            ScanStageRun.project_id == project_id,
            ScanStageRun.stage == "recon",
        )
        .order_by(ScanStageRun.attempt.desc())
        .limit(1)
        .with_for_update()
    )
    if stage_run is not None:
        if new_status == STATUS_RUNNING and stage_run.status == "pending":
            stage_run.status = "running"
            stage_run.started_at = now
        elif new_status == STATUS_COMPLETED:
            stage_run.status = "partial" if is_partial else "succeeded"
            stage_run.finished_at = now
        elif new_status == STATUS_FAILED:
            stage_run.status = "failed"
            stage_run.finished_at = now
            stage_run.error_code = failure_reason or "JOB_FAILED"
            stage_run.error_message = reason
        elif new_status == STATUS_CANCELLED:
            stage_run.status = "cancelled"
            stage_run.finished_at = now
            stage_run.error_code = "JOB_CANCELLED"
            stage_run.error_message = reason
        db.flush()

    # 8. Record transaction-consistent AuditLog entry
    audit_action = f"recon_job.{new_status}"
    if is_partial and new_status == STATUS_COMPLETED:
        audit_action = "recon_job.partial_completed"
    elif new_status == STATUS_FAILED and failure_reason == "timeout":
        audit_action = "recon_job.timed_out"

    audit_entry = AuditLog(
        action=audit_action,
        actor_type=_map_to_audit_actor_type(actor_type),
        actor_id=actor_id,
        project_id=project_id,
        entity_type="scan",
        entity_id=str(scan.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "actor_role": actor_type,
            "previous_status": current_status,
            "new_status": new_status,
            "reason": reason,
            "failure_reason": failure_reason,
            "is_partial": is_partial,
            "correlation_id": correlation_id,
        },
    )
    db.add(audit_entry)
    db.flush()

    return scan


def request_scan_cancellation(
    db: Session,
    project_id: UUID,
    scan_id: UUID,
    actor_id: str,
    actor_type: str = ACTOR_OPERATOR,
    reason: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    evaluation_time: datetime | None = None,
) -> Scan:
    """Idempotently request cancellation of a reconnaissance job.

    - If the scan is already 'cancelled', returns the scan without updating historical timestamps.
    - If the scan is 'completed' or 'failed', raises ReconJobAlreadyTerminalError.
    - If the scan is 'running', records cancel_requested_at and transitions to 'cancelled'.
    - If the scan is 'draft', 'queued', or 'paused', transitions directly to 'cancelled'.

    Raises:
        ReconJobNotFoundError: If scan not found in project.
        ReconJobAlreadyTerminalError: If scan is completed or failed.
    """
    now = evaluation_time or utc_now()

    stmt = select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id).with_for_update()
    scan = db.scalar(stmt)
    if scan is None:
        raise ReconJobNotFoundError(
            f"Reconnaissance job '{scan_id}' not found in project '{project_id}'."
        )

    # Idempotent no-op if already cancelled
    if scan.status == STATUS_CANCELLED:
        return scan

    if scan.status in (STATUS_COMPLETED, STATUS_FAILED):
        raise ReconJobAlreadyTerminalError(
            f"Cannot cancel scan '{scan_id}' because it has already finished with "
            f"status '{scan.status}'."
        )

    # Set cancel_requested_at timestamp
    if scan.cancel_requested_at is None:
        scan.cancel_requested_at = now

    # Emit audit log for cancel request
    audit_entry = AuditLog(
        action="recon_job.cancel_requested",
        actor_type=_map_to_audit_actor_type(actor_type),
        actor_id=actor_id,
        project_id=project_id,
        entity_type="scan",
        entity_id=str(scan.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "actor_role": actor_type,
            "reason": reason,
            "previous_status": scan.status,
        },
    )
    db.add(audit_entry)
    db.flush()

    # Transition to cancelled
    return transition_scan(
        db=db,
        project_id=project_id,
        scan_id=scan_id,
        new_status=STATUS_CANCELLED,
        actor_id=actor_id,
        actor_type=actor_type,
        reason=reason,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        evaluation_time=now,
    )


def pause_scan(
    db: Session,
    project_id: UUID,
    scan_id: UUID,
    actor_id: str,
    actor_type: str = ACTOR_OPERATOR,
    reason: str | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
) -> Scan:
    """Transition a running scan into 'paused' status."""
    return transition_scan(
        db=db,
        project_id=project_id,
        scan_id=scan_id,
        new_status=STATUS_PAUSED,
        actor_id=actor_id,
        actor_type=actor_type,
        reason=reason,
        ip_address=ip_address,
        request_id=request_id,
    )


def resume_scan(
    db: Session,
    project_id: UUID,
    scan_id: UUID,
    actor_id: str,
    actor_type: str = ACTOR_OPERATOR,
    ip_address: str | None = None,
    request_id: str | None = None,
    evaluation_time: datetime | None = None,
) -> Scan:
    """Resume a paused scan back to 'running' status.

    Revalidates legal authorization and scope before unpausing.

    Preconditions:
    1. Scan must currently be in 'paused' status.
    2. Associated AuthorizationRecord must exist, be unrevoked, and currently valid.
    3. Associated ScopeVersion must exist and be valid.

    Raises:
        ReconJobAuthorizationInvalidError: If authorization is expired or revoked.
        ReconJobScopeInvalidError: If pinned scope version is invalid.
    """
    now = evaluation_time or utc_now()

    stmt = select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id).with_for_update()
    scan = db.scalar(stmt)
    if scan is None:
        raise ReconJobNotFoundError(
            f"Reconnaissance job '{scan_id}' not found in project '{project_id}'."
        )

    if scan.status != STATUS_PAUSED:
        raise ReconJobInvalidStateError(
            f"Cannot resume scan with status '{scan.status}'. Only 'paused' scans can be resumed."
        )

    # Revalidate legal authorization record
    auth_record = db.scalar(
        select(AuthorizationRecord).where(
            AuthorizationRecord.id == scan.authorization_id,
            AuthorizationRecord.project_id == project_id,
        )
    )
    if auth_record is None:
        raise ReconJobAuthorizationInvalidError(
            "Pinned authorization record for this scan was not found."
        )
    if auth_record.revoked_at is not None:
        raise ReconJobAuthorizationInvalidError(
            f"Cannot resume scan: authorization '{auth_record.reference}' was revoked on "
            f"{auth_record.revoked_at.isoformat()}."
        )
    valid_from = _ensure_utc(auth_record.valid_from)
    valid_to = _ensure_utc(auth_record.valid_to)
    if valid_from and now < valid_from:
        raise ReconJobAuthorizationInvalidError(
            f"Cannot resume scan: authorization is not yet valid "
            f"(valid_from: {valid_from.isoformat()})."
        )
    if valid_to and now > valid_to:
        raise ReconJobAuthorizationInvalidError(
            f"Cannot resume scan: authorization expired on {valid_to.isoformat()}."
        )

    # Revalidate pinned scope version exists
    scope_version = db.scalar(
        select(ScopeVersion).where(
            ScopeVersion.id == scan.scope_version_id,
            ScopeVersion.project_id == project_id,
        )
    )
    if scope_version is None:
        raise ReconJobScopeInvalidError("Pinned scope version for this scan was not found.")

    return transition_scan(
        db=db,
        project_id=project_id,
        scan_id=scan_id,
        new_status=STATUS_RUNNING,
        actor_id=actor_id,
        actor_type=actor_type,
        reason="Resumed by operator after authorization revalidation",
        ip_address=ip_address,
        request_id=request_id,
        evaluation_time=now,
    )
