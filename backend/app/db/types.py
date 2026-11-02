"""Centralized database types and UUIDv7 generation for VulnOS.

Ensures application-generated UUIDv7 (RFC 9562 / RFC 4122 derivative) is used
consistently across all primary keys and entity identifiers.
"""

import uuid
from datetime import UTC, datetime

import uuid6


def uuid7() -> uuid.UUID:
    """Generate a time-ordered UUIDv7 (RFC 9562).

    Guarantees version=7 and variant=RFC 4122 with millisecond precision
    timestamp in the high 48 bits, providing natural time-ordering for indexes.
    """
    return uuid6.uuid7()


def utc_now() -> datetime:
    """Return current UTC timezone-aware timestamp."""
    return datetime.now(UTC)
