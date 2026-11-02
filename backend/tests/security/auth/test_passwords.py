"""Unit tests for Argon2id password hashing, policy validation, and timing attack mitigation."""

import pytest

from backend.app.auth.exceptions import PasswordPolicyError
from backend.app.auth.passwords import (
    hash_password,
    needs_rehash,
    validate_password_policy,
    verify_password,
)


def test_password_policy_validation() -> None:
    """Verify password policy length and null-byte constraints."""
    # Too short (< 12 characters)
    with pytest.raises(PasswordPolicyError, match="at least 12 characters"):
        validate_password_policy("short_pass")

    # Too long (> 128 characters)
    with pytest.raises(PasswordPolicyError, match="cannot exceed 128"):
        validate_password_policy("A" * 129)

    # Null byte injection
    with pytest.raises(PasswordPolicyError, match="null bytes"):
        validate_password_policy("valid_length\x00password")

    # Valid passwords
    validate_password_policy("correct_horse_battery_staple")
    validate_password_policy("A" * 12)
    validate_password_policy("A" * 128)


def test_password_hashing_and_verification() -> None:
    """Verify Argon2id hashing and verification."""
    password = "SuperSecurePassword123!"
    pw_hash = hash_password(password)

    # Must be an Argon2id hash format
    assert pw_hash.startswith("$argon2id$")
    assert "m=65536,t=3,p=4" in pw_hash

    # Verification with correct password
    assert verify_password(pw_hash, password) is True

    # Verification with incorrect password
    assert verify_password(pw_hash, "WrongPassword123!") is False

    # Does not need rehash when using matching parameters
    assert needs_rehash(pw_hash) is False


def test_hash_salt_uniqueness() -> None:
    """Verify that identical passwords produce distinct hashes due to random salts."""
    password = "IdenticalPasswordForSaltTest123!"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2
    assert verify_password(hash1, password) is True
    assert verify_password(hash2, password) is True


def test_dummy_verification_timing_mitigation() -> None:
    """Verify that verifying None or empty hash executes safely without raising exceptions."""
    # When hash is None (e.g. user not found)
    assert verify_password(None, "some_candidate_password") is False

    # When hash is empty string
    assert verify_password("", "some_candidate_password") is False

    # When candidate is empty
    assert verify_password("$argon2id$fake", "") is False
