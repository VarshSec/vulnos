"""Tests for bounded TCP readiness probes and level disclosure."""

import asyncio
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import Settings
from backend.app.core.readiness import check_all_services, check_tcp_reachability
from backend.app.main import create_app


@pytest.fixture
async def tcp_echo_server() -> AsyncGenerator[tuple[str, int]]:
    """Spins up a lightweight local TCP listener for testing reachability."""

    def handle_client(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()
    yield host, port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_reachability_success(tcp_echo_server: tuple[str, int]) -> None:
    """Verifies reachable TCP port returns status='reachable' with latency."""
    host, port = tcp_echo_server
    result = await check_tcp_reachability(host, port, timeout_seconds=1.0)
    assert result.status == "reachable"
    assert result.check_type == "tcp_socket_connect"
    assert result.latency_ms is not None
    assert result.latency_ms >= 0
    assert result.error is None


@pytest.mark.asyncio
async def test_tcp_reachability_unreachable() -> None:
    """Verifies closed port returns status='unreachable' with sanitized error message."""
    # Port 1 is rarely/never bound on loopback
    result = await check_tcp_reachability("127.0.0.1", 1, timeout_seconds=0.5)
    assert result.status in {"unreachable", "error", "timeout"}
    assert result.error is not None
    # Ensure error does not expose any connection strings or passwords
    assert "password" not in result.error.lower()
    assert "vulnos" not in result.error.lower()


@pytest.mark.asyncio
async def test_tcp_reachability_timeout() -> None:
    """Verifies non-routable address times out predictably."""
    # 192.0.2.1 is TEST-NET-1 (RFC 5737), packets dropped
    result = await check_tcp_reachability("192.0.2.1", 80, timeout_seconds=0.1)
    assert result.status in {"timeout", "unreachable"}
    assert result.latency_ms is not None


@pytest.mark.asyncio
async def test_check_all_services_honesty(tcp_echo_server: tuple[str, int]) -> None:
    """Verifies readiness level is explicitly declared and truthful."""
    host, port = tcp_echo_server
    # Configure mock settings pointing to our test echo server
    mock_settings = Settings(
        DATABASE_URL=f"postgresql+psycopg://vulnos:fake-pass@{host}:{port}/vulnos",
        REDIS_URL=f"redis://{host}:{port}/0",
        S3_ENDPOINT_URL=f"http://{host}:{port}",
        READINESS_CHECK_TIMEOUT_SECONDS=1.0,
    )

    all_ready, services = await check_all_services(mock_settings)
    assert all_ready is True
    assert services["postgres"].status == "reachable"
    assert services["redis"].status == "reachable"
    assert services["s3_storage"].status == "reachable"


@pytest.mark.asyncio
async def test_ready_endpoint_http_status_when_unready() -> None:
    """GET /ready must return 503 Service Unavailable when any dependency is unreachable."""
    unreachable_settings = Settings(
        DATABASE_URL="postgresql+psycopg://vulnos:pass@127.0.0.1:1/vulnos",
        REDIS_URL="redis://127.0.0.1:1/0",
        S3_ENDPOINT_URL="http://127.0.0.1:1",
        READINESS_CHECK_TIMEOUT_SECONDS=0.2,
        ALLOWED_HOSTS=["testserver"],
    )
    app = create_app(settings=unreachable_settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        response = await ac.get("/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["check_level"] == "tcp_reachability_only"
        assert "postgres" in data["services"]
        assert "redis" in data["services"]
        assert "s3_storage" in data["services"]
