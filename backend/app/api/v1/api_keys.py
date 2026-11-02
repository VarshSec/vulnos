"""API Key management endpoints for VulnOS."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.api_keys import create_user_api_key, revoke_api_key
from backend.app.auth.dependencies import get_current_user
from backend.app.auth.exceptions import APIKeyError
from backend.app.auth.rate_limits import record_auth_audit_event
from backend.app.auth.schemas import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyResponse,
)
from backend.app.db.models.identity import APIKey, User
from backend.app.db.session import get_db

api_keys_router = APIRouter(prefix="/api-keys", tags=["api_keys"])


@api_keys_router.get(
    "",
    response_model=list[APIKeyResponse],
    summary="List API keys belonging to authenticated user",
)
def list_api_keys(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[APIKeyResponse]:
    """Return all active and revoked API keys issued to the authenticated user."""
    stmt = select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
    keys = db.scalars(stmt).all()
    return [APIKeyResponse.model_validate(k) for k in keys]


@api_keys_router.post(
    "",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new API key",
)
def create_api_key(
    payload: APIKeyCreateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> APIKeyCreateResponse:
    """Issue a new API key. Plaintext key is displayed strictly once upon creation."""
    key_record, plaintext_key = create_user_api_key(
        db=db,
        user_id=user.id,
        name=payload.name,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
    )
    record_auth_audit_event(
        db=db,
        action="api_key.created",
        actor_id=str(user.id),
        actor_type="user",
        details={"name": payload.name, "scopes": payload.scopes},
    )

    return APIKeyCreateResponse(
        id=key_record.id,
        name=key_record.name,
        key_prefix=key_record.key_prefix,
        api_key=plaintext_key,
        scopes=key_record.scopes,
        created_at=key_record.created_at,
        expires_at=key_record.expires_at,
    )


@api_keys_router.get(
    "/{key_id}",
    response_model=APIKeyResponse,
    summary="Retrieve API key metadata",
)
def get_api_key(
    key_id: UUID = Path(..., description="API key identifier"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> APIKeyResponse:
    """Retrieve metadata for a specific API key belonging to the user."""
    stmt = select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    key_record = db.scalar(stmt)
    if not key_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    return APIKeyResponse.model_validate(key_record)


@api_keys_router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
)
def revoke_key(
    key_id: UUID = Path(..., description="API key identifier"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Revoke an API key so it can no longer be used for authentication."""
    try:
        revoke_api_key(db=db, key_id=key_id, user_id=user.id)
        record_auth_audit_event(
            db=db,
            action="api_key.revoked",
            actor_id=str(user.id),
            actor_type="user",
            details={"key_id": str(key_id)},
        )
    except APIKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
