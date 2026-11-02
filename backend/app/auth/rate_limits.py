"""Redis-backed rate limiting and audit logging helpers for authentication operations."""

import time
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.auth.exceptions import RateLimitExceededError
from backend.app.auth.sessions import get_redis_client
from backend.app.db.models.audit import AuditLog


def check_rate_limit(
    key: str,
    max_requests: int,
    window_seconds: int,
    client: Any | None = None,
) -> int:
    """Evaluate sliding-window rate limit in Redis.

    Returns:
        int: Number of remaining allowed requests in current window.

    Raises:
        RateLimitExceededError: If the request threshold is exceeded.
    """
    if client is None:
        try:
            client = get_redis_client()
        except Exception:
            # If Redis is unavailable in unit testing, fail open safely
            return max_requests

    redis_key = f"vulnos:ratelimit:{key}"
    now = time.time()
    cutoff = now - window_seconds

    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, cutoff)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {str(now): now})
        pipe.expire(redis_key, window_seconds)
        results = pipe.execute()

        current_count = int(results[1])
        if current_count >= max_requests:
            raise RateLimitExceededError(
                message=f"Rate limit exceeded. Try again in {window_seconds} seconds.",
                retry_after_seconds=window_seconds,
            )

        return max(0, max_requests - current_count - 1)
    except RateLimitExceededError:
        raise
    except Exception:
        # Fallback gracefully if Redis connection drops
        return max_requests


def record_auth_audit_event(
    db: Session,
    action: str,
    actor_id: str | None,
    actor_type: str = "user",
    project_id: UUID | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Record an immutable append-only audit log entry for authentication and security events.

    Security Rule: Passwords, raw access tokens, refresh tokens, and raw API keys
    must NEVER be included in details.
    """
    safe_metadata = {}
    if details:
        # Scrub any potential secrets
        for k, v in details.items():
            if any(s in k.lower() for s in ("password", "token", "secret", "key", "hash")):
                continue
            safe_metadata[k] = v

    log = AuditLog(
        action=action,
        actor_type=actor_type,
        actor_id=actor_id,
        project_id=project_id,
        entity_type="auth",
        entity_id=actor_id,
        ip=ip_address,
        request_id=request_id,
        metadata_=safe_metadata,
    )
    db.add(log)
    db.flush()
