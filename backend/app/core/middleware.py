"""Security and telemetry middleware for VulnOS FastAPI service.

Includes:
- RequestIDMiddleware: Generates or propagates X-Request-ID header and contextvars.
- SecurityHeadersMiddleware: Applies defense-in-depth HTTP response headers.
- AccessLoggingMiddleware: Structured access logging without sensitive query strings.
"""

import time
import uuid
from collections.abc import Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from backend.app.core.config import Settings
from backend.app.core.logging import get_logger, set_request_id

logger = get_logger("backend.access")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Propagates incoming X-Request-ID or generates a new UUIDv4 request ID."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        incoming_id = request.headers.get("X-Request-ID")
        if incoming_id and len(incoming_id) <= 128 and incoming_id.replace("-", "").isalnum():
            request_id = incoming_id
        else:
            request_id = f"req_{uuid.uuid4().hex}"

        request.state.request_id = request_id
        set_request_id(request_id)

        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces standard HTTP security response headers."""

    def __init__(self, app: Any, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        response: Response = await call_next(request)

        # Baseline security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # CSP: Relaxed slightly for OpenAPI /docs UI if necessary, strict otherwise
        if request.url.path in {"/docs", "/redoc", "/openapi.json"}:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none';"
            )

        # HSTS in production or when secure cookies are required
        if self.settings.is_production or self.settings.SESSION_COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


class AccessLoggingMiddleware(BaseHTTPMiddleware):
    """Logs incoming HTTP requests and responses as structured JSON events.

    Security rule: Path only is logged; raw query strings are omitted to prevent
    accidental credential or token exposure in access logs.
    """

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        start_time = time.perf_counter()
        req_id = getattr(request.state, "request_id", None)
        path = request.url.path
        method = request.method
        client_ip = request.client.host if request.client else "unknown"

        try:
            response: Response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.exception(
                "Unhandled error during request processing",
                method=method,
                path=path,
                duration_ms=duration_ms,
                client_ip=client_ip,
                request_id=req_id,
                error=str(exc),
            )
            from backend.app.core.errors import create_error_response

            return create_error_response(
                status_code=500,
                code="internal_error",
                message="An unexpected server error occurred. Please contact administrator.",
                request_id=req_id,
            )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.status_code

        log_method = (
            logger.info
            if status_code < 400
            else (logger.warning if status_code < 500 else logger.error)
        )

        log_method(
            "HTTP request completed",
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
            request_id=req_id,
        )

        return response
