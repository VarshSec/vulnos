"""Unit tests for Redis session management, atomic refresh token rotation, and replay detection."""

from __future__ import annotations

import builtins
from typing import Any
from uuid import uuid4

import pytest

from backend.app.auth.exceptions import (
    SessionNotFoundError,
    TokenInvalidError,
    TokenReplayError,
)
from backend.app.auth.sessions import SessionManager


class FakeRedisPipeline:
    """Mock Redis pipeline for simulating atomic commands in test environments."""

    def __init__(self, store: dict[str, Any], sets: dict[str, set[str]], ttls: dict[str, int]):
        self.store = store
        self.sets = sets
        self.ttls = ttls
        self.commands: list[tuple[str, tuple[Any, ...]]] = []

    def set(self, key: str, value: str, ex: int | None = None) -> FakeRedisPipeline:
        self.commands.append(("set", (key, value, ex)))
        return self

    def delete(self, key: str) -> FakeRedisPipeline:
        self.commands.append(("delete", (key,)))
        return self

    def sadd(self, key: str, member: str) -> FakeRedisPipeline:
        self.commands.append(("sadd", (key, member)))
        return self

    def srem(self, key: str, member: str) -> FakeRedisPipeline:
        self.commands.append(("srem", (key, member)))
        return self

    def expire(self, key: str, ttl: int) -> FakeRedisPipeline:
        self.commands.append(("expire", (key, ttl)))
        return self

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for cmd, args in self.commands:
            if cmd == "set":
                self.store[args[0]] = args[1]
                if args[2] is not None:
                    self.ttls[args[0]] = args[2]
                results.append(True)
            elif cmd == "delete":
                self.store.pop(args[0], None)
                self.sets.pop(args[0], None)
                self.ttls.pop(args[0], None)
                results.append(1)
            elif cmd == "sadd":
                if args[0] not in self.sets:
                    self.sets[args[0]] = set()
                self.sets[args[0]].add(str(args[1]))
                results.append(1)
            elif cmd == "srem":
                if args[0] in self.sets:
                    self.sets[args[0]].discard(str(args[1]))
                results.append(1)
            elif cmd == "expire":
                self.ttls[args[0]] = args[1]
                results.append(True)
        self.commands.clear()
        return results


class FakeRedisClient:
    """In-memory Redis client mock simulating key-value and set operations."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.sets: dict[str, builtins.set[str]] = {}
        self.ttls: dict[str, int] = {}

    def pipeline(self) -> FakeRedisPipeline:
        return FakeRedisPipeline(self.store, self.sets, self.ttls)

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    def delete(self, key: str) -> int:
        self.store.pop(key, None)
        self.sets.pop(key, None)
        self.ttls.pop(key, None)
        return 1

    def smembers(self, key: str) -> builtins.set[str]:
        return builtins.set(self.sets.get(key, builtins.set()))

    def srem(self, key: str, member: str) -> int:
        if key in self.sets:
            self.sets[key].discard(str(member))
        return 1

    def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)


@pytest.fixture
def fake_session_manager() -> SessionManager:
    """Fixture returning a SessionManager using an in-memory FakeRedisClient."""
    client = FakeRedisClient()
    return SessionManager(client=client)


def test_session_creation_and_retrieval(fake_session_manager: SessionManager) -> None:
    """Verify session creation and lookup."""
    user_id = uuid4()
    sess, raw_refresh = fake_session_manager.create_session(
        user_id=user_id,
        user_agent="TestAgent/1.0",
        ip_address="192.0.2.1",
    )

    assert sess.user_id == user_id
    assert sess.session_id is not None
    assert sess.csrf_token is not None
    assert sess.family_id is not None
    assert raw_refresh is not None

    retrieved = fake_session_manager.get_session(sess.session_id)
    assert retrieved is not None
    assert retrieved.user_id == user_id
    assert retrieved.session_id == sess.session_id
    assert retrieved.csrf_token == sess.csrf_token


def test_session_revocation(fake_session_manager: SessionManager) -> None:
    """Verify revoking a single session removes it from Redis."""
    user_id = uuid4()
    sess, _ = fake_session_manager.create_session(user_id=user_id)

    assert fake_session_manager.get_session(sess.session_id) is not None

    fake_session_manager.revoke_session(sess.session_id)
    assert fake_session_manager.get_session(sess.session_id) is None


def test_revoke_all_user_sessions(fake_session_manager: SessionManager) -> None:
    """Verify revoke_all_user_sessions terminates all sessions for that user."""
    user_id = uuid4()
    s1, _ = fake_session_manager.create_session(user_id=user_id)
    s2, _ = fake_session_manager.create_session(user_id=user_id)
    s3, _ = fake_session_manager.create_session(user_id=user_id)

    # All 3 active
    assert fake_session_manager.get_session(s1.session_id) is not None
    assert fake_session_manager.get_session(s2.session_id) is not None
    assert fake_session_manager.get_session(s3.session_id) is not None

    revoked_count = fake_session_manager.revoke_all_user_sessions(user_id)
    assert revoked_count == 3

    # All 3 revoked
    assert fake_session_manager.get_session(s1.session_id) is None
    assert fake_session_manager.get_session(s2.session_id) is None
    assert fake_session_manager.get_session(s3.session_id) is None


def test_atomic_refresh_token_rotation_success(fake_session_manager: SessionManager) -> None:
    """Verify normal refresh token rotation."""
    user_id = uuid4()
    sess, raw_refresh = fake_session_manager.create_session(user_id=user_id)

    # First rotation
    uid, sess_data, new_access, next_refresh = fake_session_manager.rotate_refresh_token(
        raw_refresh
    )
    assert uid == user_id
    assert sess_data.session_id == sess.session_id
    assert new_access is not None
    assert next_refresh is not None
    assert next_refresh != raw_refresh

    # Second rotation using next_refresh
    uid2, _sess_data2, _new_access2, next_refresh2 = fake_session_manager.rotate_refresh_token(
        next_refresh
    )
    assert uid2 == user_id
    assert next_refresh2 != next_refresh


def test_refresh_token_replay_attack_detection(fake_session_manager: SessionManager) -> None:
    """Verify replay detection: reusing an already-rotated token revokes the entire family."""
    user_id = uuid4()
    sess, raw_refresh = fake_session_manager.create_session(user_id=user_id)

    # Legitimate client rotates token
    _, _, _, next_refresh = fake_session_manager.rotate_refresh_token(raw_refresh)

    # Attacker tries to reuse the OLD raw_refresh token!
    with pytest.raises(TokenReplayError, match="replay detected"):
        fake_session_manager.rotate_refresh_token(raw_refresh)

    # The session itself must now be revoked due to replay attack!
    assert fake_session_manager.get_session(sess.session_id) is None

    # Even the newer token cannot be used because the whole family is revoked
    with pytest.raises((SessionNotFoundError, TokenInvalidError)):
        fake_session_manager.rotate_refresh_token(next_refresh)
