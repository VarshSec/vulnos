"""Authorization record management and evaluation service for VulnOS.

Provides project-isolated creation, retrieval, listing, revocation, and
deterministic policy evaluation of legal authorization records with append-only
audit logging.

CRITICAL ARCHITECTURAL INVARIANT:
An authorization record is a legal/contractual prerequisite.
It does NOT independently authorize network execution without matching,
active scope rules and an active scope version.
No PATCH or modification operations are permitted on authorization records;
terms are immutable and must be revoked and re-issued if changes occur.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import AuthorizationRecord
from backend.app.db.types import utc_now, uuid7
from backend.app.scope.exceptions import (
    AuthorizationNotFoundError,
    DuplicateAuthorizationError,
)
from backend.app.scope.schemas import (
    AuthorizationCreateRequest,
    AuthorizationEvaluationResult,
    AuthorizationReasonCode,
)


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware UTC for safe comparisons."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def create_authorization(
    db: Session,
    project_id: UUID,
    user_id: UUID,
    data: AuthorizationCreateRequest,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> AuthorizationRecord:
    """Create and persist a new immutable authorization record within the specified project.

    Raises:
        DuplicateAuthorizationError: If an active authorization with the same reference
            already exists in this project.
    """
    # Check for active duplicate reference within the same project
    existing = db.scalar(
        select(AuthorizationRecord).where(
            AuthorizationRecord.project_id == project_id,
            AuthorizationRecord.reference == data.reference,
            AuthorizationRecord.revoked_at.is_(None),
        )
    )
    if existing is not None:
        raise DuplicateAuthorizationError(
            f"An active authorization with reference '{data.reference}' "
            "already exists in this project."
        )

    record = AuthorizationRecord(
        id=uuid7(),
        project_id=project_id,
        reference=data.reference,
        document_evidence_id=data.document_evidence_id,
        authorized_by_name=data.authorized_by_name,
        authorized_by_contact=data.authorized_by_contact,
        valid_from=data.valid_from,
        valid_to=data.valid_to,
        allowed_actions=data.allowed_actions,
        destructive_allowed=data.destructive_allowed,
        allow_private_ranges=data.allow_private_ranges,
        max_requests_per_scan=data.max_requests_per_scan,
        notes=data.notes,
        created_by=user_id,
        created_at=utc_now(),
        revoked_at=None,
    )
    db.add(record)
    db.flush()

    audit_entry = AuditLog(
        action="authorization.create",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="authorization_record",
        entity_id=str(record.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "reference": record.reference,
            "authorized_by_name": record.authorized_by_name,
            "valid_from": record.valid_from.isoformat(),
            "valid_to": record.valid_to.isoformat(),
            "allowed_actions": record.allowed_actions,
            "destructive_allowed": record.destructive_allowed,
            "allow_private_ranges": record.allow_private_ranges,
            "max_requests_per_scan": record.max_requests_per_scan,
        },
    )
    db.add(audit_entry)

    return record


def get_authorization(
    db: Session,
    project_id: UUID,
    authorization_id: UUID,
) -> AuthorizationRecord:
    """Retrieve a single authorization record within a project.

    Raises:
        AuthorizationNotFoundError: If the record does not exist or belongs to another project.
    """
    stmt = select(AuthorizationRecord).where(
        AuthorizationRecord.id == authorization_id,
        AuthorizationRecord.project_id == project_id,
    )
    record = db.scalar(stmt)
    if record is None:
        raise AuthorizationNotFoundError(
            f"Authorization record '{authorization_id}' not found in project."
        )
    return record


def list_authorizations(
    db: Session,
    project_id: UUID,
    active_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    now: datetime | None = None,
) -> tuple[list[AuthorizationRecord], int]:
    """Retrieve a paginated collection of authorization records within a project."""
    base_query = select(AuthorizationRecord).where(AuthorizationRecord.project_id == project_id)

    if active_only:
        ts = _ensure_utc(now) if now is not None else utc_now()
        base_query = base_query.where(
            AuthorizationRecord.revoked_at.is_(None),
            AuthorizationRecord.valid_from <= ts,
            AuthorizationRecord.valid_to >= ts,
        )

    count_query = select(func.count()).select_from(base_query.subquery())
    total = db.scalar(count_query) or 0

    paged_query = (
        base_query.order_by(AuthorizationRecord.created_at.desc()).limit(limit).offset(offset)
    )
    items = list(db.scalars(paged_query).all())
    return items, total


def revoke_authorization(
    db: Session,
    project_id: UUID,
    authorization_id: UUID,
    user_id: UUID,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
    revocation_time: datetime | None = None,
) -> AuthorizationRecord:
    """Revoke an authorization record.

    Revocation is idempotent. If the record is already revoked, its existing
    revocation timestamp is preserved and the record is returned without modification.

    Raises:
        AuthorizationNotFoundError: If the record does not exist or belongs to another project.
    """
    record = get_authorization(db=db, project_id=project_id, authorization_id=authorization_id)

    if record.revoked_at is not None:
        # Idempotent: already revoked
        return record

    ts = _ensure_utc(revocation_time) if revocation_time is not None else utc_now()
    record.revoked_at = ts
    db.flush()

    audit_entry = AuditLog(
        action="authorization.revoke",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="authorization_record",
        entity_id=str(record.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "reference": record.reference,
            "revoked_at": record.revoked_at.isoformat(),
        },
    )
    db.add(audit_entry)

    return record


def evaluate_authorization_record(
    record: AuthorizationRecord | None,
    project_id: UUID,
    action: str,
    *,
    is_destructive: bool = False,
    is_private_range: bool = False,
    now: datetime | None = None,
) -> AuthorizationEvaluationResult:
    """Deterministically evaluate whether an authorization record permits an action.

    Precedence order:
    1. Record Existence (NOT_FOUND)
    2. Project Matching (PROJECT_MISMATCH)
    3. Revocation Check (REVOKED)
    4. Time Window Check (NOT_YET_VALID, EXPIRED)
    5. Action Allowlist (ACTION_NOT_ALLOWED)
    6. Destructive Permission (DESTRUCTIVE_NOT_ALLOWED)
    7. Private Range Permission (PRIVATE_RANGE_NOT_ALLOWED)
    8. Valid (VALID)
    """
    clean_action = action.strip().lower()

    if record is None:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.NOT_FOUND,
            authorization_id=None,
            project_id=project_id,
            action=clean_action,
        )

    if record.project_id != project_id:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.PROJECT_MISMATCH,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Revocation takes top precedence
    if record.revoked_at is not None:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.REVOKED,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Time window evaluation
    eval_time = _ensure_utc(now) if now is not None else utc_now()
    valid_from_utc = _ensure_utc(record.valid_from)
    valid_to_utc = _ensure_utc(record.valid_to)

    if eval_time < valid_from_utc:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.NOT_YET_VALID,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Boundary rule: eval_time == valid_to is valid; strictly greater is expired
    if eval_time > valid_to_utc:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.EXPIRED,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Action allowlist check
    if clean_action not in record.allowed_actions:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.ACTION_NOT_ALLOWED,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Destructive testing check
    if is_destructive and not record.destructive_allowed:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.DESTRUCTIVE_NOT_ALLOWED,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    # Private IP range check
    if is_private_range and not record.allow_private_ranges:
        return AuthorizationEvaluationResult(
            allowed=False,
            reason_code=AuthorizationReasonCode.PRIVATE_RANGE_NOT_ALLOWED,
            authorization_id=record.id,
            project_id=project_id,
            action=clean_action,
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            revoked_at=record.revoked_at,
            max_requests_per_scan=record.max_requests_per_scan,
            destructive_allowed=record.destructive_allowed,
            allow_private_ranges=record.allow_private_ranges,
        )

    return AuthorizationEvaluationResult(
        allowed=True,
        reason_code=AuthorizationReasonCode.VALID,
        authorization_id=record.id,
        project_id=project_id,
        action=clean_action,
        valid_from=record.valid_from,
        valid_to=record.valid_to,
        revoked_at=record.revoked_at,
        max_requests_per_scan=record.max_requests_per_scan,
        destructive_allowed=record.destructive_allowed,
        allow_private_ranges=record.allow_private_ranges,
    )


def evaluate_authorization(
    db: Session,
    project_id: UUID,
    authorization_id: UUID,
    action: str,
    *,
    is_destructive: bool = False,
    is_private_range: bool = False,
    now: datetime | None = None,
) -> AuthorizationEvaluationResult:
    """Retrieve and evaluate an authorization record by ID."""
    stmt = select(AuthorizationRecord).where(AuthorizationRecord.id == authorization_id)
    record = db.scalar(stmt)
    return evaluate_authorization_record(
        record=record,
        project_id=project_id,
        action=action,
        is_destructive=is_destructive,
        is_private_range=is_private_range,
        now=now,
    )
