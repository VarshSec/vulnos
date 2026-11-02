"""Target management API endpoints for VulnOS."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import require_project_context
from backend.app.db.models.identity import ProjectMember
from backend.app.scope.exceptions import (
    DuplicateTargetError,
    TargetNotFoundError,
)
from backend.app.scope.normalization import TargetNormalizationError
from backend.app.scope.schemas import (
    TargetCreateRequest,
    TargetListResponse,
    TargetResponse,
    TargetUpdateRequest,
)
from backend.app.scope.targets import (
    archive_target,
    create_target,
    get_target,
    list_targets,
    update_target,
)

targets_router = APIRouter(tags=["targets"])


@targets_router.post(
    "/projects/{project_id}/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a target seed to project",
)
def create_project_target(
    project_id: UUID,
    payload: TargetCreateRequest,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> TargetResponse:
    """Create a new normalized target seed in the project.

    CRITICAL INVARIANT:
    Target creation is a discovery seed registration.
    It does NOT authorize scanning or create scope rules.
    """
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        target = create_target(
            db=db,
            project_id=project_id,
            user_id=member.user_id,
            data=payload,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        return TargetResponse.model_validate(target)
    except TargetNormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except DuplicateTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@targets_router.get(
    "/projects/{project_id}/targets",
    response_model=TargetListResponse,
    summary="List target seeds for project",
)
def list_project_targets(
    project_id: UUID,
    status_filter: str | None = Query(
        None, alias="status", description="Filter by status ('active' | 'archived')"
    ),
    seed_type: str | None = Query(None, description="Filter by seed type"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> TargetListResponse:
    """Retrieve a paginated collection of target seeds within a project."""
    db, _member = context
    items, total = list_targets(
        db=db,
        project_id=project_id,
        status=status_filter,
        seed_type=seed_type,
        limit=limit,
        offset=offset,
    )
    return TargetListResponse(
        items=[TargetResponse.model_validate(t) for t in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@targets_router.get(
    "/projects/{project_id}/targets/{target_id}",
    response_model=TargetResponse,
    summary="Get single target seed",
)
def get_project_target(
    project_id: UUID,
    target_id: UUID,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> TargetResponse:
    """Retrieve details of a single target seed."""
    db, _member = context
    try:
        target = get_target(db=db, project_id=project_id, target_id=target_id)
        return TargetResponse.model_validate(target)
    except TargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@targets_router.patch(
    "/projects/{project_id}/targets/{target_id}",
    response_model=TargetResponse,
    summary="Update target metadata or status",
)
def update_project_target(
    project_id: UUID,
    target_id: UUID,
    payload: TargetUpdateRequest,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> TargetResponse:
    """Update target name, description, or active/archived status."""
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        target = update_target(
            db=db,
            project_id=project_id,
            target_id=target_id,
            user_id=member.user_id,
            data=payload,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        return TargetResponse.model_validate(target)
    except TargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@targets_router.delete(
    "/projects/{project_id}/targets/{target_id}",
    response_model=TargetResponse,
    status_code=status.HTTP_200_OK,
    summary="Archive a target seed",
)
def archive_project_target(
    project_id: UUID,
    target_id: UUID,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> TargetResponse:
    """Archive (soft-delete) a target seed. Preserves history."""
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        target = archive_target(
            db=db,
            project_id=project_id,
            target_id=target_id,
            user_id=member.user_id,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        return TargetResponse.model_validate(target)
    except TargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
