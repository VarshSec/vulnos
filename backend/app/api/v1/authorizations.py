"""Authorization record management API endpoints for VulnOS.

Provides project-isolated creation, listing, retrieval, and revocation of legal
authorization records with RBAC role enforcement, API key scope checks, and audit logging.

CRITICAL ARCHITECTURAL INVARIANTS:
1. Legal terms are strictly immutable: NO UPDATE OR PATCH ENDPOINTS are permitted.
   Modifications require revoking the existing record and issuing a new one.
2. Authorization records establish legal consent, but do NOT independently authorize
   network execution without matching active scope rules and an active scope version.
3. Access is strictly project-isolated: non-members receive 404 Not Found to prevent
   project and authorization enumeration.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import require_project_context
from backend.app.db.models.identity import ProjectMember
from backend.app.db.types import utc_now
from backend.app.scope.authorizations import (
    create_authorization,
    get_authorization,
    list_authorizations,
    revoke_authorization,
)
from backend.app.scope.exceptions import (
    AuthorizationNotFoundError,
    DuplicateAuthorizationError,
)
from backend.app.scope.schemas import (
    AuthorizationCreateRequest,
    AuthorizationListResponse,
    AuthorizationResponse,
)

authorizations_router = APIRouter(tags=["authorizations"])


@authorizations_router.post(
    "/projects/{project_id}/authorizations",
    response_model=AuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a legal authorization record",
)
def create_project_authorization(
    project_id: UUID,
    payload: AuthorizationCreateRequest,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> AuthorizationResponse:
    """Create a new immutable authorization record for the project.

    Enforces:
    - Project role: admin
    - API key scope: admin
    - valid_to must be in the future (rejected with 422 if in the past)
    """
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    # API_CONTRACTS.md §8.5: Creating an authorization with valid_to in the past is rejected (422)
    if payload.valid_to <= utc_now():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Authorization 'valid_to' must be in the future.",
        )

    try:
        record = create_authorization(
            db=db,
            project_id=project_id,
            user_id=member.user_id,
            data=payload,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        return AuthorizationResponse.model_validate(record)
    except DuplicateAuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@authorizations_router.get(
    "/projects/{project_id}/authorizations",
    response_model=AuthorizationListResponse,
    summary="List authorization records for project",
)
def list_project_authorizations(
    project_id: UUID,
    active_only: bool = Query(
        False, alias="active_only", description="Filter for currently active authorizations"
    ),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> AuthorizationListResponse:
    """Retrieve a paginated collection of authorization records within a project."""
    db, _member = context
    items, total = list_authorizations(
        db=db,
        project_id=project_id,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    return AuthorizationListResponse(
        items=[AuthorizationResponse.model_validate(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@authorizations_router.get(
    "/projects/{project_id}/authorizations/{authorization_id}",
    response_model=AuthorizationResponse,
    summary="Get single authorization record",
)
def get_project_authorization(
    project_id: UUID,
    authorization_id: UUID,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="viewer", required_scope="read")
    ),
) -> AuthorizationResponse:
    """Retrieve details of a single authorization record within the project."""
    db, _member = context
    try:
        record = get_authorization(
            db=db,
            project_id=project_id,
            authorization_id=authorization_id,
        )
        return AuthorizationResponse.model_validate(record)
    except AuthorizationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@authorizations_router.post(
    "/projects/{project_id}/authorizations/{authorization_id}/revoke",
    response_model=AuthorizationResponse,
    summary="Revoke an authorization record",
)
def revoke_project_authorization(
    project_id: UUID,
    authorization_id: UUID,
    request: Request,
    context: tuple[Session, ProjectMember] = Depends(
        require_project_context(required_role="admin", required_scope="admin")
    ),
) -> AuthorizationResponse:
    """Revoke an existing authorization record.

    Revocation is idempotent. Once revoked, the authorization can no longer permit
    active scope rule validation or scanning operations.
    """
    db, member = context
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    user_agent = request.headers.get("User-Agent")

    try:
        record = revoke_authorization(
            db=db,
            project_id=project_id,
            authorization_id=authorization_id,
            user_id=member.user_id,
            ip_address=client_ip,
            request_id=request_id,
            user_agent=user_agent,
        )
        return AuthorizationResponse.model_validate(record)
    except AuthorizationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
