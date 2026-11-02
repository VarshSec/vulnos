"""Argon2id password hashing and constant-time verification for VulnOS.

Adheres strictly to RFC 9106 and OWASP password storage recommendations.
Includes dummy verification path to mitigate username enumeration via timing attacks.
"""

import contextlib
from typing import Final

import argon2
from argon2.exceptions import VerifyMismatchError

from backend.app.auth.exceptions import PasswordPolicyError

# OWASP Recommended Argon2id parameters
ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_COST: Final[int] = 65536  # 64 MiB
ARGON2_PARALLELISM: Final[int] = 4
ARGON2_HASH_LEN: Final[int] = 32
ARGON2_SALT_LEN: Final[int] = 16

MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_PASSWORD_LENGTH: Final[int] = 128

_hasher = argon2.PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=argon2.Type.ID,
)

# Pre-computed dummy hash used to neutralize timing differences when a user is not found
_DUMMY_HASH: Final[str] = _hasher.hash("dummy_constant_password_timing_mitigation_123")


def validate_password_policy(password: str) -> None:
    """Validate password against complexity and length constraints.

    Rejects passwords shorter than 12 characters, longer than 128 characters,
    or containing null bytes.
    """
    if not isinstance(password, str):
        raise PasswordPolicyError("Password must be a string")
    if "\x00" in password:
        raise PasswordPolicyError("Password cannot contain null bytes")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password cannot exceed {MAX_PASSWORD_LENGTH} characters in length"
        )


def hash_password(password: str) -> str:
    """Hash password using Argon2id with validated OWASP parameters."""
    validate_password_policy(password)
    return _hasher.hash(password)


def verify_password(password_hash: str | None, candidate_password: str) -> bool:
    """Verify candidate password against hash in constant time.

    If password_hash is None or empty, runs verification against a pre-computed
    dummy hash to equalize execution timing and prevent timing-based user enumeration.
    """
    if not candidate_password or not isinstance(candidate_password, str):
        return False

    if not password_hash or not isinstance(password_hash, str) or not password_hash.strip():
        # Execute dummy verification to preserve execution time
        with contextlib.suppress(Exception):
            _hasher.verify(_DUMMY_HASH, candidate_password)
        return False

    try:
        return _hasher.verify(password_hash, candidate_password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    """Determine whether stored password hash should be upgraded to current parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return True
