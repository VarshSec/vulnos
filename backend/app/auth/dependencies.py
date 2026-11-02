"""FastAPI authentication, session, and project-isolated tenant context dependencies for VulnOS.

Ensures the strict request execution pipeline:
1. Authenticate principal (Bearer token, API key, or Session cookie).
2. Validate account status.
3. Verify project membership and RBAC role.
4. Establish transaction-local tenant context in PostgreSQL.
"""

from collections.abc import Callable, Generator
from dataclasses import dataclass
from uuid import UUID

from fastapi import Cookie, Depends, Header, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from backend.app.auth.api_keys import authenticate_api_key
from backend.app.auth.exceptions import (
    APIKeyError,
    AuthError,
    PermissionDeniedError,
    ProjectAccessDeniedError,
    TokenError,
)
from backend.app.auth.sessions import SessionData, SessionManager
from backend.app.auth.tokens import decode_access_token
from backend.app.authorization.permissions import has_api_key_scope
from backend.app.authorization.project_access import verify_project_access
from backend.app.db.models.identity import APIKey, ProjectMember, User
from backend.app.db.session import get_db
from backend.app.db.tenant import clear_tenant_context, set_tenant_context

_session_manager = SessionManager()


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Represents the authenticated subject (User or API Key)."""

    user: User
    api_key: APIKey | None = None
    session_data: SessionData | None = None

    @property
    def is_api_key(self) -> bool:
        return self.api_key is not None


def get_current_principal(
    request: Request,
    authorization: str | None = Header(None, alias="Authorization"),
    session_cookie: str | None = Cookie(None, alias="vulnos_session"),
    db: Session = Depends(get_db),
) -> AuthenticatedPrincipal:
    """Resolve authenticated principal from Bearer token or session cookie."""
    # 1. Bearer Token Authentication
    if authorization and authorization.startswith("Bearer "):
        token_str = authorization[len("Bearer ") :].strip()

        # Check if the token is an API Key
        if token_str.startswith("vulnos_"):
            try:
                api_key, user = authenticate_api_key(db, token_str)
                return AuthenticatedPrincipal(user=user, api_key=api_key)
            except (APIKeyError, AuthError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                ) from exc

        # Otherwise, process as JWT Access Token
        try:
            payload = decode_access_token(token_str)
            user_id = UUID(payload["sub"])
            user_obj = db.get(User, user_id)
            if user_obj is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account not found",
                )
            if not user_obj.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is inactive",
                )
            return AuthenticatedPrincipal(user=user_obj)
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc

    # 2. Browser Session Cookie Authentication
    if session_cookie:
        session_data = _session_manager.get_session(session_cookie)
        if session_data is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid",
            )

        # Enforce CSRF protection for cookie-based state-changing requests
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            csrf_header = request.headers.get("X-CSRF-Token")
            if not csrf_header or csrf_header != session_data.csrf_token:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token validation failed",
                )

        session_user = db.get(User, session_data.user_id)
        if session_user is None or not session_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or not found",
            )
        return AuthenticatedPrincipal(user=session_user, session_data=session_data)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication credentials",
    )


def get_current_user(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> User:
    """Dependency extracting the authenticated User model."""
    return principal.user


def require_project_context(
    required_role: str = "viewer",
    required_scope: str | None = None,
) -> Callable[..., Generator[tuple[Session, ProjectMember]]]:
    """Dependency factory enforcing project authorization and setting RLS tenant context.

    Pipeline:
    1. Authenticate user.
    2. Check project membership (returns 404 for non-members).
    3. Verify minimum role (returns 403 for insufficient privileges).
    4. If API key, verify granted scope.
    5. Set transaction-local PostgreSQL tenant context.
    6. Yield (db, project_member).
    7. Clean up tenant context on exit.
    """

    def _project_dependency(
        project_id: UUID = Path(..., description="Project identifier"),
        x_request_id: str | None = Header(None, alias="X-Request-ID"),
        principal: AuthenticatedPrincipal = Depends(get_current_principal),
        db: Session = Depends(get_db),
    ) -> Generator[tuple[Session, ProjectMember]]:
        try:
            # Check project membership and RBAC role
            member = verify_project_access(
                db=db,
                project_id=project_id,
                user_id=principal.user.id,
                required_role=required_role,
            )

            # Check API key scope if authenticated via API key
            if principal.api_key and required_scope:
                if not has_api_key_scope(principal.api_key.scopes, required_scope):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"API key missing required scope {required_scope!r}",
                    )

            # Establish trusted transaction-local tenant context
            set_tenant_context(
                session=db,
                project_id=project_id,
                user_id=principal.user.id,
                request_id=x_request_id,
            )

            yield db, member

        except ProjectAccessDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            ) from exc
        except PermissionDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        finally:
            clear_tenant_context(db)

    return _project_dependency
