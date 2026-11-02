"""API Key lifecycle, HMAC-SHA-256 peppered hashing, and scope verification for VulnOS.

Adheres strictly to the APIKey model from P2.2:
- Generates keys formatted as `vulnos_<prefix>_<secret>`.
- Plaintext key is returned strictly once upon creation; never logged, never stored.
- Computes HMAC-SHA-256 digest using server-side API_KEY_PEPPER.
- Enforces revocation and expiration checks on every use.
"""

import hmac
import re
import secrets
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidCredentialsError,
)
from backend.app.core.config import get_settings
from backend.app.db.models.identity import APIKey, User
from backend.app.db.types import utc_now

API_KEY_PATTERN = re.compile(r"^vulnos_([a-zA-Z0-9]{8})_([a-zA-Z0-9]{32,64})$")


def compute_key_hash(secret: str, pepper: str | None = None) -> bytes:
    """Compute HMAC-SHA-256 digest of secret using server-side API_KEY_PEPPER."""
    if pepper is None:
        pepper = get_settings().API_KEY_PEPPER
    return hmac.new(
        key=pepper.encode("utf-8"),
        msg=secret.encode("utf-8"),
        digestmod="sha256",
    ).digest()


def generate_api_key() -> tuple[str, str, str, bytes]:
    """Generate a new secure API key with prefix, secret, and keyed hash.

    Returns:
        tuple[full_key, prefix, secret, key_hash]
    """
    prefix = secrets.token_hex(4)  # 8 alphanumeric characters
    secret = secrets.token_hex(16)  # 32 alphanumeric characters
    full_key = f"vulnos_{prefix}_{secret}"
    key_hash = compute_key_hash(secret)
    return full_key, prefix, secret, key_hash


def create_user_api_key(
    db: Session,
    user_id: UUID,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
) -> tuple[APIKey, str]:
    """Create a new API key record for a user.

    Returns:
        tuple[APIKey, full_key]: Model record and plaintext key shown only once.
    """
    full_key, prefix, _, key_hash = generate_api_key()

    api_key_record = APIKey(
        user_id=user_id,
        name=name.strip(),
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(api_key_record)
    db.flush()
    return api_key_record, full_key


def authenticate_api_key(db: Session, raw_key: str) -> tuple[APIKey, User]:
    """Authenticate an incoming raw API key string against database records.

    Verifies prefix, revocation, expiration, and constant-time HMAC-SHA-256 digest.
    Updates `last_used_at` timestamp upon success.
    """
    match = API_KEY_PATTERN.match(raw_key.strip())
    if not match:
        raise InvalidCredentialsError("Malformed API key format")

    prefix, secret = match.groups()

    # Look up by public prefix
    stmt = (
        select(APIKey, User)
        .join(User, APIKey.user_id == User.id)
        .where(APIKey.key_prefix == prefix)
    )
    result = db.execute(stmt).first()
    if not result:
        raise APIKeyNotFoundError("API key not found")

    api_key, user = result

    # Check revocation
    if api_key.revoked_at is not None:
        raise APIKeyRevokedError("API key has been revoked")

    # Check expiration
    if api_key.expires_at is not None:
        now = datetime.now(UTC)
        expires_at = (
            api_key.expires_at
            if api_key.expires_at.tzinfo is not None
            else api_key.expires_at.replace(tzinfo=UTC)
        )
        if expires_at <= now:
            raise APIKeyExpiredError("API key has expired")

    # Verify HMAC digest in constant time
    expected_hash = compute_key_hash(secret)
    if not hmac.compare_digest(expected_hash, bytes(api_key.key_hash)):
        raise InvalidCredentialsError("Invalid API key credentials")

    # Verify user account is active
    if not user.is_active:
        raise InvalidCredentialsError("Owning user account is inactive")

    # Update last_used_at
    api_key.last_used_at = utc_now()
    db.flush()

    return api_key, user


def revoke_api_key(db: Session, key_id: UUID, user_id: UUID) -> APIKey:
    """Revoke an API key belonging to a user."""
    stmt = select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user_id)
    api_key = db.scalar(stmt)
    if not api_key:
        raise APIKeyNotFoundError("API key not found")

    if api_key.revoked_at is None:
        api_key.revoked_at = utc_now()
        db.flush()

    return api_key
