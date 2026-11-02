"""Scope versioning and deterministic validation API endpoints for VulnOS."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import require_project_context
from backend.app.db.models.identity import ProjectMember
from backend.app.scope.exceptions import (
    AuthorizationNotFoundError,
    AuthorizationNotValidForActivationError,
    ScopeVersionImmutableError,
    ScopeVersionInvalidStateError,
    ScopeVersionNotFoundError,
)
from backend.app.scope.normalization import TargetNormalizationError
from backend.app.scope.schemas import (
    ScopeRuleSetUpdateRequest,
    ScopeValidationDecision,
    ScopeValidationRequest,
    ScopeVersionCreateRequest,
    ScopeVersionListResponse,
    ScopeVersionResponse,
)
from backend.app.scope.versions import (
    activate_scope_version,
    create_scope_version,
    evaluate_scope_validation,
    get_scope_version,
    list_scope_versions,
    replace_scope_rules,
)

scope_router = APIRouter(tags=["scope"])


@scope_router.post(
    "/projects/{project_id}/scope",
    response_model=ScopeVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create draft scope version",
)
def create_version_endpoint(
    project_id: UUID,
    payload: ScopeVersionCreateRequest,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> ScopeVersionResponse:
    """Create a new draft scope version bound to an authorization record."""
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        version = create_scope_version(
            db=db,
            project_id=project_id,
            authorization_id=payload.authorization_id,
            user_id=member.user_id,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        db.commit()
        db.refresh(version)
        return ScopeVersionResponse.model_validate(version)
    except AuthorizationNotFoundError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e


@scope_router.get(
    "/projects/{project_id}/scope",
    response_model=ScopeVersionListResponse,
    summary="List scope versions for a project",
)
def list_versions_endpoint(
    project_id: UUID,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> ScopeVersionListResponse:
    """List paginated scope versions for the project ordered by version descending."""
    db, _ = context
    versions, total = list_scope_versions(db, project_id=project_id, limit=limit, offset=offset)
    return ScopeVersionListResponse(
        items=[ScopeVersionResponse.model_validate(v) for v in versions],
        total=total,
    )


@scope_router.get(
    "/projects/{project_id}/scope/{version_id}",
    response_model=ScopeVersionResponse,
    summary="Get single scope version with rules",
)
def get_version_endpoint(
    project_id: UUID,
    version_id: UUID,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> ScopeVersionResponse:
    """Retrieve details and all rules for a specific scope version."""
    db, _ = context
    try:
        version = get_scope_version(db, project_id=project_id, version_id=version_id)
        return ScopeVersionResponse.model_validate(version)
    except ScopeVersionNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e


@scope_router.put(
    "/projects/{project_id}/scope/{version_id}/rules",
    response_model=ScopeVersionResponse,
    summary="Replace rules on a draft scope version",
)
def replace_rules_endpoint(
    project_id: UUID,
    version_id: UUID,
    payload: ScopeRuleSetUpdateRequest,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> ScopeVersionResponse:
    """Set or replace all rules in a draft scope version.

    IMMUTABILITY INVARIANT:
    Rules cannot be modified once a scope version is activated.
    """
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        version = replace_scope_rules(
            db=db,
            project_id=project_id,
            version_id=version_id,
            rules_data=payload.rules,
            user_id=member.user_id,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        db.commit()
        db.refresh(version)
        return ScopeVersionResponse.model_validate(version)
    except ScopeVersionNotFoundError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except ScopeVersionImmutableError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from e
    except TargetNormalizationError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(e),
        ) from e


@scope_router.post(
    "/projects/{project_id}/scope/{version_id}/activate",
    response_model=ScopeVersionResponse,
    summary="Activate draft scope version",
)
def activate_version_endpoint(
    project_id: UUID,
    version_id: UUID,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> ScopeVersionResponse:
    """Activate a draft scope version and atomically supersede the prior active version.

    Enforces that:
    1. Scope version is currently 'draft'.
    2. Version contains at least one rule.
    3. Associated AuthorizationRecord is valid, active, and not revoked.
    """
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        version = activate_scope_version(
            db=db,
            project_id=project_id,
            version_id=version_id,
            user_id=member.user_id,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        db.commit()
        db.refresh(version)
        return ScopeVersionResponse.model_validate(version)
    except ScopeVersionNotFoundError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except ScopeVersionInvalidStateError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except AuthorizationNotValidForActivationError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(e),
        ) from e


@scope_router.post(
    "/projects/{project_id}/scope/validate",
    response_model=ScopeValidationDecision,
    summary="Validate target destination against project authorization and scope",
)
def validate_scope_endpoint(
    project_id: UUID,
    payload: ScopeValidationRequest,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="operator", required_scope="scan")
    ),
) -> ScopeValidationDecision:
    """Validate whether an operation on a destination is authorized and within scope.

    Combines:
    1. Project authorization record (legal consent, validity window, actions).
    2. Active immutable scope version.
    3. Global deny-overrides-allow rule evaluation.
    4. Cloud IMDS and private network safeguards.
    """
    db, _ = context
    try:
        decision = evaluate_scope_validation(
            db=db,
            project_id=project_id,
            request=payload,
        )
        if not payload.dry_run:
            db.commit()
        return decision
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scope validation failed: {e}",
        ) from e
