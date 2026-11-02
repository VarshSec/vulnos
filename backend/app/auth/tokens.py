"""JWT access token and cryptographic refresh token operations for VulnOS.

Enforces strict algorithm pinning (HS256), claim validation (issuer, audience,
expiration, token type), and SHA-256 digest hashing for refresh tokens.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import UUID

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from backend.app.auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
)
from backend.app.core.config import get_settings
from backend.app.db.types import uuid7

JWT_ALGORITHM: Final[str] = "HS256"
JWT_ISSUER: Final[str] = "vulnos"
JWT_AUDIENCE: Final[str] = "vulnos-api"
TOKEN_TYPE_ACCESS: Final[str] = "access"  # noqa: S105


def create_access_token(
    user_id: UUID | str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a cryptographically signed JWT access token.

    Claims:
    - sub: User UUID
    - iss: vulnos
    - aud: vulnos-api
    - exp: expiration timestamp
    - iat: issued-at timestamp
    - jti: unique token identifier
    - typ: access
    """
    settings = get_settings()
    now = datetime.now(UTC)

    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)

    claims: dict[str, Any] = {
        "sub": str(user_id),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid7()),
        "typ": TOKEN_TYPE_ACCESS,
    }

    token = jwt.encode(
        payload=claims,
        key=settings.SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return token


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT access token.

    Enforces algorithm pinning, signature verification, issuer, audience,
    and token type validation.
    """
    if not token or not isinstance(token, str):
        raise TokenInvalidError("Token must be a non-empty string")

    settings = get_settings()

    try:
        payload: dict[str, Any] = jwt.decode(
            jwt=token,
            key=settings.SECRET_KEY,
            algorithms=[JWT_ALGORITHM],  # Explicitly pin allowed algorithm
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["sub", "iss", "aud", "exp", "iat", "jti", "typ"],
            },
        )
    except ExpiredSignatureError as exc:
        raise TokenExpiredError("Access token has expired") from exc
    except InvalidTokenError as exc:
        raise TokenInvalidError(f"Invalid access token: {exc}") from exc

    # Validate token type isolation
    if payload.get("typ") != TOKEN_TYPE_ACCESS:
        raise TokenInvalidError(f"Invalid token type: expected {TOKEN_TYPE_ACCESS!r}")

    # Validate subject UUID format
    try:
        UUID(payload["sub"])
    except (ValueError, TypeError) as exc:
        raise TokenInvalidError("Invalid subject UUID in token") from exc

    return payload


def generate_refresh_token() -> tuple[str, str]:
    """Generate a cryptographic refresh token and its SHA-256 digest.

    Returns:
        tuple[raw_token, token_hash]: The raw token is returned to the client once;
        only token_hash is ever stored in Redis.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_refresh_token(raw_token)
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Compute the SHA-256 hex digest of a refresh token for storage and lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
