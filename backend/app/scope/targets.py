"""Target management service for VulnOS.

Provides project-isolated creation, retrieval, listing, metadata updates,
and archiving of target seeds with mandatory normalization and append-only audit logging.

CRITICAL ARCHITECTURAL INVARIANT:
A target is a discovery seed, not an authorization permit.
Creating or updating a target must NEVER:
- Create an authorization record.
- Create an allow rule.
- Activate a scope version.
- Grant permission to scan.
- Bypass the scope validator.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import Target
from backend.app.db.types import utc_now, uuid7
from backend.app.scope.exceptions import DuplicateTargetError, TargetNotFoundError
from backend.app.scope.normalization import normalize_target
from backend.app.scope.schemas import TargetCreateRequest, TargetUpdateRequest


def create_target(
    db: Session,
    project_id: UUID,
    user_id: UUID,
    data: TargetCreateRequest,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> Target:
    """Normalize and persist a new target seed within the specified project.

    Raises:
        TargetNormalizationError: If the seed value fails RFC syntax checks or security rules.
        DuplicateTargetError: If a target with identical (project_id, seed_type, seed_value) exists.
    """
    # 1. Deterministic normalization and classification
    norm_result = normalize_target(data.seed_type, data.seed_value)
    canonical_value = norm_result.canonical_value

    # 2. Check for duplicate target seeds within project
    existing = db.scalar(
        select(Target).where(
            Target.project_id == project_id,
            Target.seed_type == data.seed_type.value,
            Target.seed_value == canonical_value,
        )
    )
    if existing is not None:
        raise DuplicateTargetError(
            f"Target of type '{data.seed_type.value}' with value '{canonical_value}' "
            f"already exists in this project (status: {existing.status})."
        )

    # 3. Create target record
    target = Target(
        id=uuid7(),
        project_id=project_id,
        name=data.name.strip(),
        seed_type=data.seed_type.value,
        seed_value=canonical_value,
        description=data.description.strip() if data.description else None,
        status="active",
        created_by=user_id,
        created_at=utc_now(),
        archived_at=None,
    )
    db.add(target)
    db.flush()

    # 4. Record immutable audit log entry
    audit_entry = AuditLog(
        action="target.create",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="target",
        entity_id=str(target.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={
            "name": target.name,
            "seed_type": target.seed_type,
            "seed_value": target.seed_value,
            "raw_input": data.seed_value,
        },
    )
    db.add(audit_entry)

    # Invariant assertion: Never create authorization records, scope rules, or scope versions
    return target


def get_target(
    db: Session,
    project_id: UUID,
    target_id: UUID,
) -> Target:
    """Retrieve a single target seed within a project.

    Raises:
        TargetNotFoundError: If the target does not exist or belongs to another project.
    """
    stmt = select(Target).where(
        Target.id == target_id,
        Target.project_id == project_id,
    )
    target = db.scalar(stmt)
    if target is None:
        raise TargetNotFoundError(f"Target '{target_id}' not found in project.")
    return target


def list_targets(
    db: Session,
    project_id: UUID,
    status: str | None = None,
    seed_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Target], int]:
    """Retrieve a paginated collection of target seeds within a project."""
    base_query = select(Target).where(Target.project_id == project_id)
    if status is not None:
        base_query = base_query.where(Target.status == status)
    if seed_type is not None:
        base_query = base_query.where(Target.seed_type == seed_type)

    count_query = select(func.count()).select_from(base_query.subquery())
    total = db.scalar(count_query) or 0

    paged_query = base_query.order_by(Target.created_at.desc()).limit(limit).offset(offset)
    items = list(db.scalars(paged_query).all())
    return items, total


def update_target(
    db: Session,
    project_id: UUID,
    target_id: UUID,
    user_id: UUID,
    data: TargetUpdateRequest,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> Target:
    """Update target metadata or lifecycle status.

    seed_type and seed_value are immutable to preserve audit integrity.

    Raises:
        TargetNotFoundError: If the target does not exist in the project.
    """
    target = get_target(db=db, project_id=project_id, target_id=target_id)
    changes: dict[str, Any] = {}

    if data.name is not None:
        clean_name = data.name.strip()
        if clean_name != target.name:
            changes["name"] = {"old": target.name, "new": clean_name}
            target.name = clean_name

    if data.description is not None:
        clean_desc = data.description.strip() if data.description else None
        if clean_desc != target.description:
            changes["description"] = {"old": target.description, "new": clean_desc}
            target.description = clean_desc

    if data.status is not None and data.status != target.status:
        changes["status"] = {"old": target.status, "new": data.status}
        target.status = data.status
        if data.status == "archived":
            target.archived_at = utc_now()
        elif data.status == "active":
            target.archived_at = None

    if changes:
        db.flush()
        audit_entry = AuditLog(
            action="target.update",
            actor_type="user",
            actor_id=str(user_id),
            project_id=project_id,
            entity_type="target",
            entity_id=str(target.id),
            ip=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata_={"changes": changes},
        )
        db.add(audit_entry)

    return target


def archive_target(
    db: Session,
    project_id: UUID,
    target_id: UUID,
    user_id: UUID,
    ip_address: str | None = None,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> Target:
    """Archive (soft-delete) a target seed.

    Idempotent: Archiving an already archived target is a no-op.

    Raises:
        TargetNotFoundError: If the target does not exist in the project.
    """
    target = get_target(db=db, project_id=project_id, target_id=target_id)
    if target.status == "archived":
        return target

    target.status = "archived"
    target.archived_at = utc_now()
    db.flush()

    audit_entry = AuditLog(
        action="target.archive",
        actor_type="user",
        actor_id=str(user_id),
        project_id=project_id,
        entity_type="target",
        entity_id=str(target.id),
        ip=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_={"previous_status": "active"},
    )
    db.add(audit_entry)
    return target
