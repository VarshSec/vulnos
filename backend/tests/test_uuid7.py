"""Tests for UUIDv7 generation — RFC 9562 compliance.

Verifies version bits, variant bits, timestamp ordering, uniqueness,
and round-trip serialization of application-generated UUIDs.
"""

from __future__ import annotations

import time
import uuid

from backend.app.db.types import uuid7


class TestUUID7Generation:
    """Validate UUIDv7 properties per RFC 9562."""

    def test_returns_uuid_instance(self) -> None:
        result = uuid7()
        assert isinstance(result, uuid.UUID)

    def test_version_is_7(self) -> None:
        result = uuid7()
        assert result.version == 7

    def test_variant_is_rfc4122(self) -> None:
        result = uuid7()
        assert result.variant == uuid.RFC_4122

    def test_version_bits_in_raw(self) -> None:
        """Version nibble (bits 48-51) should be 0b0111 = 7."""
        u = uuid7()
        version_nibble = (u.int >> 76) & 0xF
        assert version_nibble == 7

    def test_variant_bits_in_raw(self) -> None:
        """Variant bits (bits 64-65) should be 0b10."""
        u = uuid7()
        variant_bits = (u.int >> 62) & 0x3
        assert variant_bits == 0b10

    def test_uniqueness(self) -> None:
        uuids = {uuid7() for _ in range(1000)}
        assert len(uuids) == 1000

    def test_temporal_ordering(self) -> None:
        """UUIDs generated sequentially should be lexicographically ordered."""
        first = uuid7()
        time.sleep(0.002)  # Ensure at least 1ms separation
        second = uuid7()
        assert str(first) < str(second)

    def test_string_roundtrip(self) -> None:
        original = uuid7()
        roundtrip = uuid.UUID(str(original))
        assert roundtrip == original
        assert roundtrip.version == 7

    def test_bytes_roundtrip(self) -> None:
        original = uuid7()
        roundtrip = uuid.UUID(bytes=original.bytes)
        assert roundtrip == original

    def test_hex_roundtrip(self) -> None:
        original = uuid7()
        roundtrip = uuid.UUID(hex=original.hex)
        assert roundtrip == original

    def test_int_roundtrip(self) -> None:
        original = uuid7()
        roundtrip = uuid.UUID(int=original.int)
        assert roundtrip == original

    def test_not_uuid4(self) -> None:
        """Must not silently substitute UUIDv4."""
        results = [uuid7() for _ in range(100)]
        for u in results:
            assert u.version != 4
            assert u.version == 7

    def test_batch_uniqueness_large(self) -> None:
        """Verify uniqueness across a larger batch."""
        uuids = [uuid7() for _ in range(10_000)]
        assert len(set(uuids)) == 10_000
