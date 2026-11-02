"""Scope versioning, rule set management, and deterministic scope validation for VulnOS.

Enforces the strict security lifecycle of ScopeVersion and ScopeRule:
- Versions progress through: 'draft' -> 'active' -> 'superseded'.
- Rules are editable ONLY while in 'draft' status.
- Once activated, rules and content hash are completely immutable.
- Exactly ONE version can be active per project at any given time.
- Activation requires an active, valid, non-revoked AuthorizationRecord.
- Every scope decision evaluates legal authorization + active scope rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.parse
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import (
    AuthorizationRecord,
    ScopeDecision,
    ScopeRule,
    ScopeVersion,
)
from backend.app.db.types import utc_now, uuid7
from backend.app.scope.authorizations import evaluate_authorization_record
from backend.app.scope.exceptions import (
    AuthorizationNotFoundError,
    AuthorizationNotValidForActivationError,
    ScopeVersionImmutableError,
    ScopeVersionInvalidStateError,
    ScopeVersionNotFoundError,
)
from backend.app.scope.matching import match_scope_rules
from backend.app.scope.normalization import (
    IPAddressCategory,
    classify_ip_address,
)
from backend.app.scope.schemas import (
    ScopeRuleCreateRequest,
    ScopeRuleData,
    ScopeValidationDecision,
    ScopeValidationRequest,
)


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware UTC for safe comparisons."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def compute_scope_content_hash(
    rules: Sequence[ScopeRule | ScopeRuleCreateRequest | ScopeRuleData | dict[str, Any]],
) -> bytes:
    """Compute deterministic SHA-256 digest of canonicalized scope rules.

    Rules are extracted into canonical dicts and sorted deterministically
    before JSON serialization and hashing.
    """
    serialized: list[dict[str, Any]] = []

    for rule in rules:
        if isinstance(rule, dict):
            effect = rule.get("effect", "")
            match_type = rule.get("match_type", "")
            value = rule.get("value", "")
            priority = int(rule.get("priority", 100))
            ports = rule.get("ports")
            protocols = rule.get("protocols")
            note = rule.get("note") or ""
        else:
            effect = getattr(rule, "effect", "")
            match_type = getattr(rule, "match_type", "")
            value = getattr(rule, "value", "")
            priority = int(getattr(rule, "priority", 100))
            ports = getattr(rule, "ports", None)
            protocols = getattr(rule, "protocols", None)
            note = getattr(rule, "note", None) or ""

        # Normalize ports representation
        norm_ports: Any
        if ports is None:
            norm_ports = None
        elif isinstance(ports, (list, tuple)):
            norm_ports = [int(p) for p in ports]
        elif hasattr(ports, "lower") and hasattr(ports, "upper"):
            norm_ports = [getattr(ports, "lower", None), getattr(ports, "upper", None)]
        else:
            norm_ports = str(ports)

        # Normalize protocols
        norm_protocols: list[str] = sorted(protocols) if protocols else []

        serialized.append(
            {
                "effect": str(effect),
                "match_type": str(match_type),
                "note": str(note),
                "ports": norm_ports,
                "priority": priority,
                "protocols": norm_protocols,
                "value": str(value),
            }
        )

    # Sort deterministically
    sorted_rules = sorted(
        serialized,
        key=lambda r: (
            r["effect"],
            -r["priority"],
            r["match_type"],
            r["value"],
            tuple(r["protocols"]),
            str(r["ports"]),
        ),
    )

    canonical_json = json.dumps(sorted_rules, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).digest()


def create_scope_version(
    db: Session,
    project_id: UUID,
    authorization_id: UUID,
    user_id: UUID,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> ScopeVersion:
    """Create a new draft scope version bound to an authorization record.

    Raises:
        AuthorizationNotFoundError: If the authorization record does not exist in the project.
    """
    # 1. Verify authorization record belongs to project
    auth_record = db.scalar(
        select(AuthorizationRecord).where(
            AuthorizationRecord.id == authorization_id,
            AuthorizationRecord.project_id == project_id,
        )
    )
    if auth_record is None:
        raise AuthorizationNotFoundError(
            f"Authorization record {authorization_id} not found in project {project_id}."
        )

    # 2. Compute next sequential version number
    max_ver = db.scalar(
        select(func.max(ScopeVersion.version)).where(ScopeVersion.project_id == project_id)
    )
    next_ver = (max_ver or 0) + 1

    # 3. Create draft scope version with initial empty hash
    initial_hash = compute_scope_content_hash([])
    scope_version = ScopeVersion(
        id=uuid7(),
        project_id=project_id,
        authorization_id=authorization_id,
        version=next_ver,
        status="draft",
        content_hash=initial_hash,
        created_by=user_id,
        created_at=utc_now(),
    )
    db.add(scope_version)
    db.flush()

    # 4. Record audit event
    audit_entry = AuditLog(
        action="scope_version.create",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="scope_version",
        entity_id=str(scope_version.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "version": scope_version.version,
            "authorization_id": str(authorization_id),
            "status": "draft",
        },
    )
    db.add(audit_entry)
    db.flush()

    return scope_version


def get_scope_version(
    db: Session,
    project_id: UUID,
    version_id: UUID,
) -> ScopeVersion:
    """Retrieve a single scope version with rules eagerly loaded.

    Raises:
        ScopeVersionNotFoundError: If not found or belongs to another project.
    """
    version = db.scalar(
        select(ScopeVersion)
        .options(joinedload(ScopeVersion.rules))
        .where(
            ScopeVersion.id == version_id,
            ScopeVersion.project_id == project_id,
        )
    )
    if version is None:
        raise ScopeVersionNotFoundError(
            f"Scope version {version_id} not found in project {project_id}."
        )
    return version


def list_scope_versions(
    db: Session,
    project_id: UUID,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ScopeVersion], int]:
    """Return paginated scope versions for a project ordered by version descending."""
    total = (
        db.scalar(select(func.count(ScopeVersion.id)).where(ScopeVersion.project_id == project_id))
        or 0
    )

    stmt = (
        select(ScopeVersion)
        .options(joinedload(ScopeVersion.rules))
        .where(ScopeVersion.project_id == project_id)
        .order_by(ScopeVersion.version.desc())
        .limit(limit)
        .offset(offset)
    )
    versions = list(db.scalars(stmt).unique().all())
    return versions, total


def get_active_scope_version(
    db: Session,
    project_id: UUID,
) -> ScopeVersion | None:
    """Return the currently active scope version for a project, or None."""
    return db.scalar(
        select(ScopeVersion)
        .options(joinedload(ScopeVersion.rules))
        .where(
            ScopeVersion.project_id == project_id,
            ScopeVersion.status == "active",
        )
    )


def replace_scope_rules(
    db: Session,
    project_id: UUID,
    version_id: UUID,
    rules_data: list[ScopeRuleCreateRequest],
    user_id: UUID,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> ScopeVersion:
    """Replace all rules in a draft scope version.

    CRITICAL INVARIANT:
    Rules can ONLY be edited while status is 'draft'.
    Active or superseded versions are completely immutable.

    Raises:
        ScopeVersionNotFoundError: If scope version does not exist.
        ScopeVersionImmutableError: If scope version is active or superseded.
    """
    version = get_scope_version(db, project_id, version_id)

    if version.status != "draft":
        raise ScopeVersionImmutableError(
            f"Cannot modify rules of scope version {version.version} in '{version.status}' status. "
            "Scope versions become immutable once activated."
        )

    # 1. Remove existing rules for this version
    db.query(ScopeRule).filter(ScopeRule.scope_version_id == version_id).delete()
    db.flush()

    # 2. Add new rules
    new_rules: list[ScopeRule] = []
    for r in rules_data:
        rule_obj = ScopeRule(
            id=uuid7(),
            scope_version_id=version_id,
            effect=r.effect,
            match_type=r.match_type,
            value=r.value,
            ports=r.ports,
            protocols=r.protocols,
            priority=r.priority,
            note=r.note,
            created_at=utc_now(),
        )
        db.add(rule_obj)
        new_rules.append(rule_obj)

    db.flush()

    # 3. Update version content hash
    version.content_hash = compute_scope_content_hash(rules_data)
    db.flush()

    # 4. Record audit entry
    audit_entry = AuditLog(
        action="scope_rules.replace",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="scope_version",
        entity_id=str(version.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "version": version.version,
            "rule_count": len(new_rules),
            "content_hash": version.content_hash.hex(),
        },
    )
    db.add(audit_entry)
    db.flush()

    # Refresh relationship
    return get_scope_version(db, project_id, version_id)


def activate_scope_version(
    db: Session,
    project_id: UUID,
    version_id: UUID,
    user_id: UUID,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> ScopeVersion:
    """Activate a draft scope version with legal consent enforcement.

    CRITICAL INVARIANTS:
    1. Scope version must be in 'draft' status.
    2. Version must contain at least one rule.
    3. Associated AuthorizationRecord must exist, be valid, and not revoked.
    4. Current active version is atomically superseded.
    5. Exactly ONE active version can exist per project.

    Raises:
        ScopeVersionNotFoundError: If version does not exist.
        ScopeVersionInvalidStateError: If version is not draft or has no rules.
        AuthorizationNotValidForActivationError: If authorization is invalid/expired/revoked.
    """
    version = get_scope_version(db, project_id, version_id)

    # Invariant 1: Must be in draft status
    if version.status != "draft":
        raise ScopeVersionInvalidStateError(
            f"Cannot activate scope version {version.version} with status '{version.status}'. "
            "Only 'draft' versions can be activated."
        )

    # Invariant 2: Must contain at least one rule
    if not version.rules:
        raise ScopeVersionInvalidStateError(
            "Cannot activate an empty scope version. Define at least one rule before activation."
        )

    # Invariant 3: Associated AuthorizationRecord must be active and valid
    auth_record = db.scalar(
        select(AuthorizationRecord).where(
            AuthorizationRecord.id == version.authorization_id,
            AuthorizationRecord.project_id == project_id,
        )
    )
    if auth_record is None:
        raise AuthorizationNotValidForActivationError(
            "Authorization record associated with this scope version not found."
        )

    now = utc_now()
    if auth_record.revoked_at is not None:
        raise AuthorizationNotValidForActivationError(
            f"Authorization record '{auth_record.reference}' was revoked on "
            f"{auth_record.revoked_at.isoformat()}."
        )
    valid_from = _ensure_utc(auth_record.valid_from)
    valid_to = _ensure_utc(auth_record.valid_to)
    if now < valid_from:
        raise AuthorizationNotValidForActivationError(
            f"Authorization record '{auth_record.reference}' is not yet valid "
            f"(valid_from: {valid_from.isoformat()})."
        )
    if now > valid_to:
        raise AuthorizationNotValidForActivationError(
            f"Authorization record '{auth_record.reference}' expired on {valid_to.isoformat()}."
        )

    # Lock content hash
    version.content_hash = compute_scope_content_hash(version.rules)

    # Invariant 4: Atomically supersede current active version
    current_active = db.scalar(
        select(ScopeVersion).where(
            ScopeVersion.project_id == project_id,
            ScopeVersion.status == "active",
        )
    )
    if current_active is not None and current_active.id != version.id:
        current_active.status = "superseded"
        current_active.superseded_at = now
        db.flush()

    # Transition to active
    version.status = "active"
    version.activated_at = now
    db.flush()

    # Record audit log
    audit_entry = AuditLog(
        action="scope_version.activate",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="scope_version",
        entity_id=str(version.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "version": version.version,
            "authorization_id": str(auth_record.id),
            "content_hash": version.content_hash.hex(),
            "rule_count": len(version.rules),
            "superseded_version_id": str(current_active.id) if current_active else None,
        },
    )
    db.add(audit_entry)
    db.flush()

    return version


def evaluate_scope_validation(
    db: Session,
    project_id: UUID,
    request: ScopeValidationRequest,
    scan_id: UUID | None = None,
    evaluation_time: datetime | None = None,
) -> ScopeValidationDecision:
    """Perform deterministic scope validation combining authorization record and scope rules.

    Evaluation Pipeline:
    1. Verify active, valid AuthorizationRecord exists for the project.
    2. Check action allowlist and destructive operation flag.
    3. Verify active ScopeVersion exists with at least one rule.
    4. Run deterministic match_scope_rules against active scope rules.
    5. Run SSRF / cloud IMDS protection (hard fail-closed).
    6. Run private network check against AuthorizationRecord.allow_private_ranges.
    7. If not dry_run, write an append-only ScopeDecision audit row.

    A matching allow rule is NOT permission to test without a valid AuthorizationRecord.
    """
    now = evaluation_time or utc_now()

    # 1. Retrieve project's active authorization record
    auth_stmt = (
        select(AuthorizationRecord)
        .where(
            AuthorizationRecord.project_id == project_id,
            AuthorizationRecord.revoked_at.is_(None),
            AuthorizationRecord.valid_from <= now,
            AuthorizationRecord.valid_to >= now,
        )
        .order_by(AuthorizationRecord.valid_to.desc())
        .limit(1)
    )
    auth_record = db.scalar(auth_stmt)

    if auth_record is None:
        return ScopeValidationDecision(
            allowed=False,
            reason_code="authorization_not_found",
            project_id=project_id,
            decided_at=now,
            context={"action": request.action, "dry_run": request.dry_run},
        )

    # 2. Evaluate authorization action and destructive flags
    auth_eval = evaluate_authorization_record(
        record=auth_record,
        project_id=project_id,
        action=request.action,
        is_destructive=request.destructive,
        now=now,
    )
    if not auth_eval.allowed:
        return ScopeValidationDecision(
            allowed=False,
            reason_code=auth_eval.reason_code.value,
            project_id=project_id,
            authorization_id=auth_record.id,
            decided_at=now,
            context={"action": request.action, "dry_run": request.dry_run},
        )

    # 3. Retrieve project's active scope version
    active_version = get_active_scope_version(db, project_id)
    if active_version is None or not active_version.rules:
        return ScopeValidationDecision(
            allowed=False,
            reason_code="no_active_scope_version",
            project_id=project_id,
            authorization_id=auth_record.id,
            decided_at=now,
            context={"action": request.action, "dry_run": request.dry_run},
        )

    # 4. Deterministic rule matching
    match_result = match_scope_rules(
        active_version.rules,
        destination=request.target,
        port=request.port,
        protocol=request.protocol,
    )

    allowed = match_result.matched and (match_result.effect == "allow")
    reason_code = match_result.reason_code.value
    matched_rule_id = match_result.matched_rule_id
    normalized_dest = match_result.normalized_destination or request.target

    # 5. SSRF / Cloud metadata / Private range checks
    ip_candidate: str | None = None
    if "://" in normalized_dest:
        try:
            split_url = urllib.parse.urlsplit(normalized_dest)
            ip_candidate = split_url.hostname
        except Exception:
            ip_candidate = None
    else:
        ip_candidate = normalized_dest.split(":")[0].strip()

    if ip_candidate:
        try:
            ip_obj = ipaddress.ip_address(ip_candidate)
            classification = classify_ip_address(ip_obj)

            if classification.is_non_overridable:
                allowed = False
                reason_code = "cloud_metadata_blocked"
            elif not auth_record.allow_private_ranges and classification.category in (
                IPAddressCategory.PRIVATE_RFC1918,
                IPAddressCategory.LINK_LOCAL,
                IPAddressCategory.LOOPBACK,
            ):
                allowed = False
                reason_code = "private_range_blocked"
        except ValueError:
            # Not an IP literal (hostname/domain)
            pass

    decision = ScopeValidationDecision(
        allowed=allowed,
        reason_code=reason_code,
        project_id=project_id,
        scope_version_id=active_version.id,
        authorization_id=auth_record.id,
        matched_rule_id=matched_rule_id,
        normalized_target=normalized_dest,
        resolved_ips=[],
        policy_hash=active_version.content_hash.hex(),
        decided_at=now,
        context={
            "action": request.action,
            "destructive": request.destructive,
            "port": request.port,
            "protocol": request.protocol,
            "dry_run": request.dry_run,
        },
    )

    # 6. If not dry_run, write authoritative append-only audit record
    if not request.dry_run:
        scope_decision_row = ScopeDecision(
            project_id=project_id,
            scan_id=scan_id,
            scope_version_id=active_version.id,
            authorization_id=auth_record.id,
            subject=normalized_dest,
            method=request.action,
            allowed=allowed,
            reason_code=reason_code,
            matched_rule_id=matched_rule_id,
            resolved_ips=[],
            policy_hash=active_version.content_hash,
            decided_at=now,
            context=decision.context,
        )
        db.add(scope_decision_row)
        db.flush()

    return decision
