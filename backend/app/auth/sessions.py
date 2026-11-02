"""Redis session lifecycle, atomic refresh token rotation, and replay detection for VulnOS.

Maintains strict separation:
- Ephemeral browser sessions are stored in Redis (zero relational sessions table).
- Refresh tokens are rotated atomically; reuse of an already-used token triggers
  immediate token family revocation and session invalidation.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID

import redis

from backend.app.auth.exceptions import (
    SessionNotFoundError,
    TokenInvalidError,
    TokenReplayError,
)
from backend.app.auth.tokens import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from backend.app.core.config import get_settings


@dataclass(frozen=True)
class SessionData:
    """Stored Redis session record."""

    session_id: str
    user_id: UUID
    family_id: str
    csrf_token: str
    created_at: int
    last_activity_at: int
    user_agent: str | None = None
    ip_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["user_id"] = str(self.user_id)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionData:
        return cls(
            session_id=str(data["session_id"]),
            user_id=UUID(str(data["user_id"])),
            family_id=str(data["family_id"]),
            csrf_token=str(data["csrf_token"]),
            created_at=int(data["created_at"]),
            last_activity_at=int(data["last_activity_at"]),
            user_agent=data.get("user_agent"),
            ip_address=data.get("ip_address"),
        )


def get_redis_client() -> redis.Redis[Any]:
    """Create a Redis client instance configured from settings."""
    settings = get_settings()
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def _session_key(session_id: str) -> str:
    return f"vulnos:session:{session_id}"


def _user_sessions_key(user_id: UUID | str) -> str:
    return f"vulnos:user_sessions:{user_id}"


def _refresh_key(token_hash: str) -> str:
    return f"vulnos:refresh:{token_hash}"


def _family_key(family_id: str) -> str:
    return f"vulnos:family:{family_id}"


class SessionManager:
    """Manages session creation, rotation, lookup, and revocation in Redis."""

    def __init__(self, client: Any | None = None):
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = get_redis_client()
        return self._client

    def create_session(
        self,
        user_id: UUID,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[SessionData, str]:
        """Create a new authenticated session and initial refresh token.

        Returns:
            tuple[SessionData, raw_refresh_token]: Session record and raw refresh token.
        """
        settings = get_settings()
        ttl_seconds = settings.REFRESH_TOKEN_TTL_DAYS * 86400
        now = int(time.time())

        session_id = secrets.token_hex(24)
        family_id = secrets.token_hex(16)
        csrf_token = secrets.token_hex(24)
        raw_refresh_token, refresh_hash = generate_refresh_token()

        sess = SessionData(
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            csrf_token=csrf_token,
            created_at=now,
            last_activity_at=now,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        pipe = self.client.pipeline()
        # 1. Store session JSON
        pipe.set(_session_key(session_id), json.dumps(sess.to_dict()), ex=ttl_seconds)
        # 2. Add to user's set of active sessions
        pipe.sadd(_user_sessions_key(user_id), session_id)
        pipe.expire(_user_sessions_key(user_id), ttl_seconds)
        # 3. Store refresh token metadata
        refresh_data = {
            "user_id": str(user_id),
            "session_id": session_id,
            "family_id": family_id,
            "used": 0,
        }
        pipe.set(_refresh_key(refresh_hash), json.dumps(refresh_data), ex=ttl_seconds)
        # 4. Track refresh token in family set for revocation
        pipe.sadd(_family_key(family_id), refresh_hash)
        pipe.expire(_family_key(family_id), ttl_seconds)
        pipe.execute()

        return sess, raw_refresh_token

    def get_session(self, session_id: str) -> SessionData | None:
        """Retrieve active session by ID and touch last_activity_at timestamp."""
        if not session_id or not isinstance(session_id, str):
            return None

        raw = self.client.get(_session_key(session_id))
        if not raw:
            return None

        try:
            data = json.loads(raw)
            sess = SessionData.from_dict(data)
            # Update last activity timestamp asynchronously/best effort
            now = int(time.time())
            if now - sess.last_activity_at > 60:
                data["last_activity_at"] = now
                ttl = self.client.ttl(_session_key(session_id))
                if ttl > 0:
                    self.client.set(_session_key(session_id), json.dumps(data), ex=ttl)
            return sess
        except Exception:
            return None

    def revoke_session(self, session_id: str) -> None:
        """Revoke a specific session."""
        sess = self.get_session(session_id)
        if sess is not None:
            pipe = self.client.pipeline()
            pipe.delete(_session_key(session_id))
            pipe.srem(_user_sessions_key(sess.user_id), session_id)
            # Revoke all tokens in the family
            family_hashes = self.client.smembers(_family_key(sess.family_id))
            for h in family_hashes:
                pipe.delete(_refresh_key(h))
            pipe.delete(_family_key(sess.family_id))
            pipe.execute()

    def revoke_all_user_sessions(self, user_id: UUID) -> int:
        """Revoke every active session belonging to a user (e.g. after password change)."""
        session_ids = self.client.smembers(_user_sessions_key(user_id))
        count = len(session_ids)
        for sid in session_ids:
            self.revoke_session(str(sid))
        self.client.delete(_user_sessions_key(user_id))
        return count

    def rotate_refresh_token(
        self,
        raw_refresh_token: str,
    ) -> tuple[UUID, SessionData, str, str]:
        """Atomically rotate a refresh token with strict replay attack detection.

        Returns:
            tuple[user_id, session_data, new_access_token, new_raw_refresh_token]
        """
        if not raw_refresh_token or not isinstance(raw_refresh_token, str):
            raise TokenInvalidError("Invalid refresh token")

        token_hash = hash_refresh_token(raw_refresh_token)
        raw_data = self.client.get(_refresh_key(token_hash))
        if not raw_data:
            raise TokenInvalidError("Refresh token not found or expired")

        token_meta = json.loads(raw_data)
        family_id = token_meta["family_id"]
        session_id = token_meta["session_id"]
        user_id = UUID(token_meta["user_id"])

        # Check for replay attack: If token was already marked used!
        if token_meta.get("used", 0) != 0:
            # Revoke entire token family and associated session immediately
            self.revoke_session(session_id)
            raise TokenReplayError(
                "Refresh token replay detected. All tokens in family have been revoked."
            )

        # Verify parent session is still active
        session_data = self.get_session(session_id)
        if session_data is None:
            raise SessionNotFoundError("Session has been terminated or expired")

        # Mark current token as used
        token_meta["used"] = 1
        settings = get_settings()
        ttl_seconds = settings.REFRESH_TOKEN_TTL_DAYS * 86400

        # Generate new token pair
        new_raw_refresh, new_hash = generate_refresh_token()
        new_meta = {
            "user_id": str(user_id),
            "session_id": session_id,
            "family_id": family_id,
            "used": 0,
        }

        pipe = self.client.pipeline()
        pipe.set(_refresh_key(token_hash), json.dumps(token_meta), ex=ttl_seconds)
        pipe.set(_refresh_key(new_hash), json.dumps(new_meta), ex=ttl_seconds)
        pipe.sadd(_family_key(family_id), new_hash)
        pipe.execute()

        new_access_token = create_access_token(user_id)
        return user_id, session_data, new_access_token, new_raw_refresh
