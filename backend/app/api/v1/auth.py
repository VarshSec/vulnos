"""Authentication API endpoints for VulnOS.

Provides user registration, credential login, atomic refresh token rotation,
logout, logout-all, password change, and current user profile inspection.
"""

from typing import Literal, cast

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import (
    AuthenticatedPrincipal,
    get_current_principal,
    get_current_user,
)
from backend.app.auth.exceptions import (
    AuthError,
    InvalidCredentialsError,
    PasswordPolicyError,
    TokenError,
)
from backend.app.auth.rate_limits import check_rate_limit, record_auth_audit_event
from backend.app.auth.schemas import (
    PasswordChangeRequest,
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from backend.app.auth.service import authenticate_user, change_password, register_user
from backend.app.auth.sessions import SessionManager
from backend.app.auth.tokens import create_access_token
from backend.app.core.config import get_settings
from backend.app.db.models.identity import User
from backend.app.db.session import get_db

auth_router = APIRouter(prefix="/auth", tags=["auth"])
_session_manager = SessionManager()


@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new human user",
)
def register(
    payload: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Register a new user account with Argon2id hashed password."""
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"register:{client_ip}", max_requests=10, window_seconds=3600)

    try:
        user = register_user(
            db=db,
            email=payload.email,
            password=payload.password,
            display_name=payload.display_name,
        )
        record_auth_audit_event(
            db=db,
            action="auth.register",
            actor_id=str(user.id),
            actor_type="user",
            ip_address=client_ip,
        )
        return UserResponse.model_validate(user)
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and create session",
)
def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate email/password, set HttpOnly session cookie and return access token."""
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{client_ip}:{payload.email}", max_requests=5, window_seconds=60)

    try:
        user = authenticate_user(db=db, email=payload.email, password=payload.password)
    except InvalidCredentialsError as exc:
        record_auth_audit_event(
            db=db,
            action="auth.login.failed",
            actor_id=None,
            actor_type="user",
            ip_address=client_ip,
            details={"email": payload.email},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        ) from exc
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    settings = get_settings()
    user_agent = request.headers.get("User-Agent")

    # Create stateful Redis session and cryptographic refresh token
    session_data, raw_refresh = _session_manager.create_session(
        user_id=user.id,
        user_agent=user_agent,
        ip_address=client_ip,
    )

    # Set secure HttpOnly session cookie
    response.set_cookie(
        key="vulnos_session",
        value=session_data.session_id,
        max_age=settings.REFRESH_TOKEN_TTL_DAYS * 86400,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=cast(Literal["lax", "strict", "none"], settings.SESSION_COOKIE_SAMESITE.lower()),
        path="/",
    )
    # Set CSRF synchronizer token header for SPA clients
    response.headers["X-CSRF-Token"] = session_data.csrf_token

    access_token = create_access_token(user.id)
    record_auth_audit_event(
        db=db,
        action="auth.login.success",
        actor_id=str(user.id),
        actor_type="user",
        ip_address=client_ip,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_seconds=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
        refresh_token=raw_refresh,
    )


@auth_router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Atomically rotate refresh token",
)
def refresh(
    payload: TokenRefreshRequest | None = None,
    session_cookie: str | None = Cookie(None, alias="vulnos_session"),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Rotate an active refresh token with replay detection."""
    settings = get_settings()
    refresh_token = payload.refresh_token if payload else None

    if not refresh_token and session_cookie:
        # Check active session in redis
        sess = _session_manager.get_session(session_cookie)
        if sess is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid",
            )
        new_token = create_access_token(sess.user_id)
        return TokenResponse(
            access_token=new_token,
            token_type="bearer",
            expires_in_seconds=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
            refresh_token=None,
        )

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing refresh token",
        )

    try:
        user_id, _sess_data, new_access_token, new_raw_refresh = (
            _session_manager.rotate_refresh_token(refresh_token)
        )
        record_auth_audit_event(
            db=db,
            action="auth.refresh_token.rotated",
            actor_id=str(user_id),
            actor_type="user",
        )
        return TokenResponse(
            access_token=new_access_token,
            token_type="bearer",
            expires_in_seconds=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
            refresh_token=new_raw_refresh,
        )
    except TokenError as exc:
        record_auth_audit_event(
            db=db,
            action="auth.refresh_token.replay_detected",
            actor_id=None,
            actor_type="system",
            details={"error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


@auth_router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke active session and delete cookie",
)
def logout(
    response: Response,
    session_cookie: str | None = Cookie(None, alias="vulnos_session"),
    db: Session = Depends(get_db),
) -> None:
    """Terminate the active session."""
    if session_cookie:
        _session_manager.revoke_session(session_cookie)
        response.delete_cookie(key="vulnos_session", path="/")
        record_auth_audit_event(
            db=db,
            action="auth.logout",
            actor_id=None,
            actor_type="user",
        )


@auth_router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all active sessions for current user",
)
def logout_all(
    response: Response,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> None:
    """Invalidate all sessions across all devices for the authenticated user."""
    _session_manager.revoke_all_user_sessions(principal.user.id)
    response.delete_cookie(key="vulnos_session", path="/")
    record_auth_audit_event(
        db=db,
        action="auth.logout_all",
        actor_id=str(principal.user.id),
        actor_type="user",
    )


@auth_router.post(
    "/change-password",
    summary="Change user password and invalidate sessions",
)
def user_change_password(
    payload: PasswordChangeRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Change user password, verifying current password and revoking all device sessions."""
    try:
        change_password(
            db=db,
            user_id=principal.user.id,
            current_password=payload.current_password,
            new_password=payload.new_password,
            session_manager=_session_manager,
        )
        record_auth_audit_event(
            db=db,
            action="auth.password_changed",
            actor_id=str(principal.user.id),
            actor_type="user",
        )
        return {"status": "password_changed"}
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@auth_router.get(
    "/me",
    response_model=UserResponse,
    summary="Retrieve current authenticated user",
)
def get_me(user: User = Depends(get_current_user)) -> UserResponse:
    """Return identity and status of currently authenticated user."""
    return UserResponse.model_validate(user)
