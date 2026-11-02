"""Unit tests for API key generation, HMAC-SHA-256 peppered verification, and revocation."""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.auth.api_keys import (
    authenticate_api_key,
    compute_key_hash,
    create_user_api_key,
    generate_api_key,
    revoke_api_key,
)
from backend.app.auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidCredentialsError,
)
from backend.app.db.base import Base
from backend.app.db.models.identity import User


@pytest.fixture
def auth_db() -> Generator[Session]:
    """In-memory SQLite session with users and api_keys tables."""
    engine = create_engine("sqlite:///:memory:")
    # Only create User and APIKey tables
    tables = [User.__table__, Base.metadata.tables["api_keys"]]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_api_key_format_and_hashing() -> None:
    """Verify API key formatting and HMAC-SHA-256 peppered hashing."""
    full_key, prefix, secret, key_hash = generate_api_key()

    assert full_key.startswith(f"vulnos_{prefix}_{secret}")
    assert len(prefix) == 8
    assert len(secret) == 32
    assert len(key_hash) == 32  # 256 bits

    # Verifying with matching secret and pepper
    assert compute_key_hash(secret) == key_hash


def test_api_key_authentication_success(auth_db: Session) -> None:
    """Verify issuing and successfully authenticating an API key."""
    user = User(id=uuid4(), email="apikey@example.com", display_name="API User")
    auth_db.add(user)
    auth_db.commit()

    key_record, plaintext_key = create_user_api_key(
        db=auth_db,
        user_id=user.id,
        name="CI Key",
        scopes=["read", "scan"],
    )
    auth_db.commit()

    assert key_record.last_used_at is None

    # Authenticate with the plaintext key
    auth_key, auth_user = authenticate_api_key(auth_db, plaintext_key)
    assert auth_key.id == key_record.id
    assert auth_user.id == user.id
    assert auth_key.last_used_at is not None


def test_api_key_invalid_format_and_tampered_secret(auth_db: Session) -> None:
    """Verify that malformed or tampered keys are rejected."""
    user = User(id=uuid4(), email="tamper@example.com", display_name="Tamper User")
    auth_db.add(user)
    auth_db.commit()

    key_record, plaintext_key = create_user_api_key(
        db=auth_db,
        user_id=user.id,
        name="Test Key",
        scopes=["read"],
    )
    auth_db.commit()

    # Malformed key format
    with pytest.raises(InvalidCredentialsError, match="Malformed API key format"):
        authenticate_api_key(auth_db, "not_an_api_key")

    # Non-existent prefix
    fake_key = f"vulnos_ffffffff_{plaintext_key.split('_')[2]}"
    with pytest.raises(APIKeyNotFoundError, match="not found"):
        authenticate_api_key(auth_db, fake_key)

    # Valid prefix, wrong secret
    tampered_key = f"vulnos_{key_record.key_prefix}_00000000000000000000000000000000"
    with pytest.raises(InvalidCredentialsError, match="Invalid API key credentials"):
        authenticate_api_key(auth_db, tampered_key)


def test_api_key_revocation_rejection(auth_db: Session) -> None:
    """Verify that revoked keys cannot authenticate."""
    user = User(id=uuid4(), email="revoke@example.com", display_name="Revoke User")
    auth_db.add(user)
    auth_db.commit()

    key_record, plaintext_key = create_user_api_key(
        db=auth_db,
        user_id=user.id,
        name="Revoke Me",
        scopes=["read"],
    )
    auth_db.commit()

    # Revoke key
    revoke_api_key(auth_db, key_record.id, user.id)
    auth_db.commit()

    with pytest.raises(APIKeyRevokedError, match="revoked"):
        authenticate_api_key(auth_db, plaintext_key)


def test_api_key_expiration_rejection(auth_db: Session) -> None:
    """Verify that expired keys cannot authenticate."""
    user = User(id=uuid4(), email="expire@example.com", display_name="Expire User")
    auth_db.add(user)
    auth_db.commit()

    past_time = datetime.now(UTC) - timedelta(minutes=5)
    _key_record, plaintext_key = create_user_api_key(
        db=auth_db,
        user_id=user.id,
        name="Expired Key",
        scopes=["read"],
        expires_at=past_time,
    )
    auth_db.commit()

    with pytest.raises(APIKeyExpiredError, match="expired"):
        authenticate_api_key(auth_db, plaintext_key)
