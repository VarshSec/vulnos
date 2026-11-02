"""Tests for recursive sensitive-value redaction and sanitization."""

from typing import Any

from backend.app.core.redaction import (
    MAX_REDACTION_DEPTH,
    REDACTED_PLACEHOLDER,
    is_sensitive_key,
    redact_sensitive_data,
)


def test_is_sensitive_key() -> None:
    """Verify sensitive key detection for various formats and cases."""
    assert is_sensitive_key("password")
    assert is_sensitive_key("PASSWORD")
    assert is_sensitive_key("user_password")
    assert is_sensitive_key("secret_key")
    assert is_sensitive_key("api_key")
    assert is_sensitive_key("cookie")
    assert is_sensitive_key("set-cookie")
    assert is_sensitive_key("authorization")
    assert is_sensitive_key("auth_token")
    assert is_sensitive_key("session_id")

    assert not is_sensitive_key("username")
    assert not is_sensitive_key("email")
    assert not is_sensitive_key("created_at")
    assert not is_sensitive_key("project_id")


def test_redact_primitive_types() -> None:
    """Primitives should remain intact unless matching standalone bearer pattern."""
    assert redact_sensitive_data(123) == 123
    assert redact_sensitive_data(45.67) == 45.67
    assert redact_sensitive_data(True) is True
    assert redact_sensitive_data(None) is None
    assert redact_sensitive_data("regular_string") == "regular_string"
    assert redact_sensitive_data("Bearer eyJhbGciOi...") == "Bearer [REDACTED]"


def test_redact_shallow_dictionary() -> None:
    """Direct sensitive dictionary keys must be redacted."""
    data = {
        "username": "alice",
        "password": "SuperSecretPassword123!",
        "api_key": "vln_live_abcdef123456",
        "status": "active",
    }
    redacted = redact_sensitive_data(data)
    assert redacted["username"] == "alice"
    assert redacted["password"] == REDACTED_PLACEHOLDER
    assert redacted["api_key"] == REDACTED_PLACEHOLDER
    assert redacted["status"] == "active"
    # Verify original dictionary was not mutated
    assert data["password"] == "SuperSecretPassword123!"


def test_redact_nested_structures() -> None:
    """Nested dicts, lists, and tuples must be recursively redacted."""
    data = {
        "user": {
            "name": "bob",
            "credentials": {
                "hash": "argon2id$...",
                "pepper": "super-secret-pepper",
            },
        },
        "accounts": [
            {"token": "tok_1", "role": "admin"},
            {"token": "tok_2", "role": "viewer"},
        ],
        "headers": ("User-Agent: test", "Authorization: Bearer secret_token_123"),
    }
    redacted = redact_sensitive_data(data)

    assert redacted["user"]["credentials"] == REDACTED_PLACEHOLDER
    assert redacted["accounts"][0]["token"] == REDACTED_PLACEHOLDER
    assert redacted["accounts"][0]["role"] == "admin"
    assert redacted["accounts"][1]["token"] == REDACTED_PLACEHOLDER
    assert redacted["headers"][0] == "User-Agent: test"
    assert redacted["headers"][1] == "Authorization: Bearer secret_token_123"


def test_redaction_cycle_protection() -> None:
    """Circular references must be caught without causing RecursionError."""
    cyclic_dict: dict[str, Any] = {"name": "cyclic"}
    cyclic_dict["self"] = cyclic_dict

    redacted = redact_sensitive_data(cyclic_dict)
    assert redacted["name"] == "cyclic"
    assert redacted["self"] == "[CIRCULAR_REFERENCE]"


def test_redaction_max_depth_limit() -> None:
    """Excessive nesting beyond limit must truncate safely."""
    nested: dict[str, Any] = {"val": "bottom"}
    for _ in range(MAX_REDACTION_DEPTH + 5):
        nested = {"level": nested}

    redacted = redact_sensitive_data(nested)
    # Drill down to max depth
    current = redacted
    while isinstance(current, dict) and "level" in current:
        current = current["level"]
    assert current == "[MAX_DEPTH_EXCEEDED]"
