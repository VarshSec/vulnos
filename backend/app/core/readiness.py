"""Bounded dependency readiness checks for VulnOS.

Performs bounded TCP connectivity checks against PostgreSQL, Redis, and S3-compatible
object storage endpoints.

Note on readiness level:
These checks verify network-layer TCP port reachability only. They do NOT assert full
application-level protocol health, authentication validity, schema migration status,
or bucket existence.
"""

import asyncio

from pydantic import BaseModel, Field

from backend.app.core.config import Settings
from backend.app.core.logging import get_logger

logger = get_logger("backend.readiness")


class ServiceCheckResult(BaseModel):
    """Result of a single dependency check."""

    status: str = Field(..., description="'reachable' | 'unreachable' | 'timeout' | 'error'")
    check_type: str = Field(
        default="tcp_socket_connect",
        description="Explicitly documents that this check is TCP reachability only",
    )
    latency_ms: float | None = Field(default=None, description="Check duration in milliseconds")
    error: str | None = Field(
        default=None,
        description="Sanitized error description; never includes credentials",
    )


class ReadinessResponse(BaseModel):
    """Overall readiness probe response."""

    status: str = Field(..., description="'ready' | 'not_ready'")
    check_level: str = Field(
        default="tcp_reachability_only",
        description=(
            "Explicit declaration that checks do not verify application-level auth or state"
        ),
    )
    services: dict[str, ServiceCheckResult]


async def check_tcp_reachability(
    host: str, port: int, timeout_seconds: float
) -> ServiceCheckResult:
    """Attempt a bounded TCP socket connection to host:port."""
    start_time = asyncio.get_event_loop().time()
    try:
        conn = asyncio.open_connection(host, port)
        _reader, writer = await asyncio.wait_for(conn, timeout=timeout_seconds)
        latency = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        writer.close()
        await writer.wait_closed()
        return ServiceCheckResult(
            status="reachable",
            latency_ms=latency,
        )
    except TimeoutError:
        latency = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        return ServiceCheckResult(
            status="timeout",
            latency_ms=latency,
            error=f"Connection timed out after {timeout_seconds}s",
        )
    except OSError as err:
        latency = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        return ServiceCheckResult(
            status="unreachable",
            latency_ms=latency,
            error=f"TCP connection failed: {err.strerror or 'Connection refused'}",
        )
    except Exception as exc:
        latency = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        return ServiceCheckResult(
            status="error",
            latency_ms=latency,
            error=f"Unexpected connectivity error: {exc.__class__.__name__}",
        )


async def check_all_services(settings: Settings) -> tuple[bool, dict[str, ServiceCheckResult]]:
    """Run concurrent bounded reachability checks across Postgres, Redis, and S3."""
    timeout = settings.READINESS_CHECK_TIMEOUT_SECONDS

    pg_host, pg_port = settings.parsed_db_host_port
    redis_host, redis_port = settings.parsed_redis_host_port
    s3_host, s3_port = settings.parsed_s3_host_port

    pg_task = check_tcp_reachability(pg_host, pg_port, timeout)
    redis_task = check_tcp_reachability(redis_host, redis_port, timeout)
    s3_task = check_tcp_reachability(s3_host, s3_port, timeout)

    results = await asyncio.gather(pg_task, redis_task, s3_task, return_exceptions=False)

    service_results: dict[str, ServiceCheckResult] = {
        "postgres": results[0],
        "redis": results[1],
        "s3_storage": results[2],
    }

    all_ready = all(r.status == "reachable" for r in service_results.values())
    return all_ready, service_results
