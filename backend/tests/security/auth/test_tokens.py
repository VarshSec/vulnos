"""Unit tests for JWT access tokens and cryptographic refresh tokens."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from backend.app.auth.exceptions import TokenExpiredError, TokenInvalidError
from backend.app.auth.tokens import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from backend.app.core.config import get_settings


def test_create_and_decode_access_token() -> None:
    """Verify standard access token round-trip."""
    user_id = uuid4()
    token = create_access_token(user_id)

    payload = decode_access_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_AUDIENCE
    assert payload["typ"] == "access"
    assert "jti" in payload
    assert payload["exp"] > payload["iat"]


def test_expired_token_rejection() -> None:
    """Verify that expired access tokens raise TokenExpiredError."""
    user_id = uuid4()
    # Create token that expired 10 seconds ago
    expired_token = create_access_token(user_id, expires_delta=timedelta(seconds=-10))

    with pytest.raises(TokenExpiredError, match="expired"):
        decode_access_token(expired_token)


def test_invalid_signature_rejection() -> None:
    """Verify that tampering with token payload or signature is rejected."""
    user_id = uuid4()
    valid_token = create_access_token(user_id)

    # Tamper with the signature portion
    parts = valid_token.split(".")
    tampered_token = f"{parts[0]}.{parts[1]}.bad_signature_here"

    with pytest.raises(TokenInvalidError, match="Invalid access token"):
        decode_access_token(tampered_token)


def test_wrong_issuer_and_audience() -> None:
    """Verify that tokens with untrusted issuer or audience are rejected."""
    settings = get_settings()
    user_id = uuid4()
    now = datetime.now(UTC)

    # Wrong issuer
    bad_iss_claims = {
        "sub": str(user_id),
        "iss": "untrusted-issuer",
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": str(uuid4()),
        "typ": "access",
    }
    bad_iss_token = jwt.encode(bad_iss_claims, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    with pytest.raises(TokenInvalidError, match="Invalid access token"):
        decode_access_token(bad_iss_token)

    # Wrong audience
    bad_aud_claims = {
        "sub": str(user_id),
        "iss": JWT_ISSUER,
        "aud": "wrong-audience",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": str(uuid4()),
        "typ": "access",
    }
    bad_aud_token = jwt.encode(bad_aud_claims, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    with pytest.raises(TokenInvalidError, match="Invalid access token"):
        decode_access_token(bad_aud_token)


def test_token_type_confusion_rejection() -> None:
    """Verify that tokens claiming typ != 'access' (e.g. 'refresh') are rejected."""
    settings = get_settings()
    user_id = uuid4()
    now = datetime.now(UTC)

    refresh_claims = {
        "sub": str(user_id),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": str(uuid4()),
        "typ": "refresh",
    }
    refresh_token_as_jwt = jwt.encode(refresh_claims, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)

    with pytest.raises(TokenInvalidError, match="Invalid token type"):
        decode_access_token(refresh_token_as_jwt)


def test_refresh_token_generation_and_hashing() -> None:
    """Verify generation of cryptographically unguessable refresh tokens."""
    raw1, hash1 = generate_refresh_token()
    raw2, hash2 = generate_refresh_token()

    assert raw1 != raw2
    assert hash1 != hash2
    assert hash_refresh_token(raw1) == hash1
    assert len(hash1) == 64  # SHA-256 hex string
