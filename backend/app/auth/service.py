"""User authentication service, registration, and credential management for VulnOS."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.exceptions import (
    InvalidCredentialsError,
    PasswordPolicyError,
    UserInactiveError,
    UserNotFoundError,
)
from backend.app.auth.passwords import (
    hash_password,
    validate_password_policy,
    verify_password,
)
from backend.app.auth.sessions import SessionManager
from backend.app.db.models.identity import User
from backend.app.db.types import utc_now


def register_user(
    db: Session,
    email: str,
    password: str,
    display_name: str,
) -> User:
    """Register a new human user with validated Argon2id hashed password."""
    clean_email = email.strip().lower()
    clean_name = display_name.strip()

    # Check for existing email address
    existing = db.scalar(select(User).where(User.email == clean_email))
    if existing is not None:
        raise PasswordPolicyError("An account with this email already exists")

    # Validate and hash password
    validate_password_policy(password)
    pw_hash = hash_password(password)

    user = User(
        email=clean_email,
        display_name=clean_name,
        password_hash=pw_hash,
        auth_provider="local",
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User:
    """Authenticate user credentials using constant-time verification.

    Executes a dummy verification path when the user is not found to prevent
    username enumeration through execution timing differences.
    """
    clean_email = email.strip().lower()
    user = db.scalar(select(User).where(User.email == clean_email))

    if user is None:
        # Neutralize timing differences by running against pre-computed dummy hash
        verify_password(None, password)
        raise InvalidCredentialsError("Invalid email or password")

    if not verify_password(user.password_hash, password):
        raise InvalidCredentialsError("Invalid email or password")

    if not user.is_active:
        raise UserInactiveError("Account is inactive or disabled")

    # Update last login timestamp
    user.last_login_at = utc_now()
    db.flush()
    return user


def change_password(
    db: Session,
    user_id: UUID,
    current_password: str,
    new_password: str,
    session_manager: SessionManager | None = None,
) -> None:
    """Change user password, verify current password, and invalidate existing sessions."""
    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise UserNotFoundError("User not found")

    if not verify_password(user.password_hash, current_password):
        raise InvalidCredentialsError("Current password is incorrect")

    validate_password_policy(new_password)
    new_hash = hash_password(new_password)

    user.password_hash = new_hash
    db.flush()

    # Invalidate all active sessions across all devices for this user
    if session_manager is not None:
        session_manager.revoke_all_user_sessions(user_id)
