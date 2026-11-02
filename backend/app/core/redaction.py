"""Recursive sensitive-value redaction module for VulnOS.

Ensures secrets, passwords, cookies, authorization tokens, and API keys are never
accidentally leaked into structured logs, exception details, or error envelopes.
"""

from collections.abc import Mapping
from typing import Any

# Default set of sensitive keys (lowercase for case-insensitive matching)
DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "authorization",
        "cookie",
        "cookies",
        "set-cookie",
        "session",
        "session_id",
        "pepper",
        "api_key_pepper",
        "credential",
        "credentials",
        "private_key",
        "client_secret",
    }
)

REDACTED_PLACEHOLDER: str = "[REDACTED]"
MAX_REDACTION_DEPTH: int = 15


def is_sensitive_key(key: Any) -> bool:
    """Check if a dictionary key or field name matches sensitive patterns."""
    if not isinstance(key, str):
        key = str(key)
    key_lower = key.strip().lower()

    if key_lower in DEFAULT_SENSITIVE_KEYS:
        return True

    # Check for substring matches on key names
    return any(sensitive in key_lower for sensitive in DEFAULT_SENSITIVE_KEYS)


def redact_sensitive_data(
    data: Any,
    max_depth: int = MAX_REDACTION_DEPTH,
    _current_depth: int = 0,
    _seen_ids: set[int] | None = None,
) -> Any:
    """Recursively redact sensitive key-values from dicts, lists, tuples, and sets.

    Returns a deep, sanitized copy without modifying the original input.
    Guards against cyclic references and excessive nesting depth.
    """
    if _current_depth > max_depth:
        return "[MAX_DEPTH_EXCEEDED]"

    if _seen_ids is None:
        _seen_ids = set()

    # Primitive types (immutable, non-container)
    if data is None or isinstance(data, (bool, int, float)):
        return data

    if isinstance(data, str):
        # Redact obvious Authorization headers if passed as string directly
        if data.lower().startswith("bearer ") and len(data) > 7:
            return "Bearer [REDACTED]"
        return data

    obj_id = id(data)
    if obj_id in _seen_ids:
        return "[CIRCULAR_REFERENCE]"

    _seen_ids.add(obj_id)
    try:
        if isinstance(data, Mapping):
            redacted_dict: dict[str, Any] = {}
            for k, v in data.items():
                str_k = str(k)
                if is_sensitive_key(str_k):
                    redacted_dict[str_k] = REDACTED_PLACEHOLDER
                else:
                    redacted_dict[str_k] = redact_sensitive_data(
                        v,
                        max_depth=max_depth,
                        _current_depth=_current_depth + 1,
                        _seen_ids=_seen_ids,
                    )
            return redacted_dict

        if isinstance(data, (list, tuple, set)):
            redacted_items = [
                redact_sensitive_data(
                    item,
                    max_depth=max_depth,
                    _current_depth=_current_depth + 1,
                    _seen_ids=_seen_ids,
                )
                for item in data
            ]
            if isinstance(data, tuple):
                return tuple(redacted_items)
            if isinstance(data, set):
                # Sets might have unhashable elements after redaction if dicts were inside
                try:
                    return set(redacted_items)
                except TypeError:
                    return redacted_items
            return redacted_items

        # Fallback for object instances with __dict__
        if hasattr(data, "__dict__"):
            return redact_sensitive_data(
                vars(data),
                max_depth=max_depth,
                _current_depth=_current_depth + 1,
                _seen_ids=_seen_ids,
            )

        return str(data)
    finally:
        _seen_ids.remove(obj_id)
