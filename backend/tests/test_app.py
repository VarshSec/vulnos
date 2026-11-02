"""Integration tests for FastAPI application, probes, middleware, and errors."""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import Settings
from backend.app.core.errors import APIError
from backend.app.main import create_app


@pytest.fixture
def test_settings() -> Settings:
    """Provides isolated test settings."""
    return Settings(
        APP_ENV="test",
        APP_DEBUG=False,
        SECRET_KEY="test-secret-key-for-unit-testing-32bytes",
        ALLOWED_HOSTS=["testserver", "localhost"],
        CORS_ORIGINS=["http://localhost:5173"],
    )


@pytest.fixture
async def client(test_settings: Settings) -> AsyncGenerator[AsyncClient]:
    """Provides an authenticated test client with app lifespan executed."""
    app = create_app(settings=test_settings)

    # Attach a route to test custom APIError
    @app.get("/test/custom-error")
    async def trigger_custom_error() -> None:
        raise APIError(
            status_code=400,
            code="test_bad_request",
            message="Custom error message",
            details={"reason": "test_failure"},
        )

    # Attach a route to test unhandled internal error (500)
    @app.get("/test/unhandled-500")
    async def trigger_unhandled_500() -> None:
        raise RuntimeError("Database connection string password leaked!")

    # Attach a route with query validation to test 422 schema error
    @app.get("/test/validation")
    async def trigger_validation(count: int) -> dict[str, int]:
        return {"count": count}

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """GET /health must return 200 OK with app and version metadata."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "VulnOS"
    assert data["version"] == "0.1.0"
    assert data["environment"] == "test"


@pytest.mark.asyncio
async def test_api_v1_root_endpoint(client: AsyncClient) -> None:
    """GET /api/v1 must return v1 operational information."""
    response = await client.get("/api/v1")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "v1"
    assert data["service"] == "VulnOS API"
    assert data["milestone"] == "P2.1"


@pytest.mark.asyncio
async def test_openapi_schema_endpoint(client: AsyncClient) -> None:
    """GET /openapi.json must return valid OpenAPI 3.x document."""
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["openapi"].startswith("3.")
    assert schema["info"]["title"] == "VulnOS API"
    assert "/health" in schema["paths"]
    assert "/ready" in schema["paths"]
    assert "/api/v1" in schema["paths"]


@pytest.mark.asyncio
async def test_request_id_generation_and_propagation(client: AsyncClient) -> None:
    """App must generate req_... when none supplied and echo it in response headers."""
    # 1. No incoming request ID
    res1 = await client.get("/health")
    req_id1 = res1.headers.get("X-Request-ID")
    assert req_id1 is not None
    assert req_id1.startswith("req_")

    # 2. Existing valid incoming request ID
    incoming_id = "test-custom-id-998877"
    res2 = await client.get("/health", headers={"X-Request-ID": incoming_id})
    assert res2.headers.get("X-Request-ID") == incoming_id


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient) -> None:
    """All responses must carry baseline defense-in-depth security headers."""
    response = await client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "0"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "geolocation=()" in response.headers["Permissions-Policy"]


@pytest.mark.asyncio
async def test_cors_preflight_and_headers(client: AsyncClient) -> None:
    """Preflight OPTIONS and actual requests must return correct CORS headers."""
    # Preflight OPTIONS
    preflight = await client.options(
        "/api/v1",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "GET" in preflight.headers["access-control-allow-methods"]

    # Actual request with Origin
    actual = await client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert actual.status_code == 200
    assert actual.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "X-Request-ID" in actual.headers.get("access-control-expose-headers", "")


@pytest.mark.asyncio
async def test_404_not_found_standard_error_envelope(client: AsyncClient) -> None:
    """Non-existent route must return 404 inside standard error envelope."""
    response = await client.get("/non-existent-endpoint")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    err = body["error"]
    assert err["code"] == "not_found"
    assert err["message"] == "Not Found"
    assert err["request_id"] is not None


@pytest.mark.asyncio
async def test_validation_error_envelope_with_field_paths(client: AsyncClient) -> None:
    """Malformed request parameter must return 422 with field paths."""
    response = await client.get("/test/validation?count=invalid_not_an_int")
    assert response.status_code == 422
    body = response.json()
    assert "error" in body
    err = body["error"]
    assert err["code"] == "validation_error"
    assert err["message"] == "Request validation failed."
    assert "fields" in err["details"]
    assert any(f["path"].endswith("count") for f in err["details"]["fields"])


@pytest.mark.asyncio
async def test_custom_api_error_envelope(client: AsyncClient) -> None:
    """Application APIError exceptions must return custom status, code, and details."""
    response = await client.get("/test/custom-error")
    assert response.status_code == 400
    body = response.json()
    err = body["error"]
    assert err["code"] == "test_bad_request"
    assert err["message"] == "Custom error message"
    assert err["details"]["reason"] == "test_failure"


@pytest.mark.asyncio
async def test_unhandled_500_masks_internal_details(client: AsyncClient) -> None:
    """Unhandled server exceptions must return sanitized 500 without leaking stack traces."""
    response = await client.get("/test/unhandled-500")
    assert response.status_code == 500
    body = response.json()
    err = body["error"]
    assert err["code"] == "internal_error"
    # Verify sensitive leak was NOT returned in error response
    assert "password leaked" not in str(body)
    assert err["request_id"] is not None
