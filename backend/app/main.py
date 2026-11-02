"""VulnOS FastAPI application factory and entry point.

Implements startup/shutdown lifecycle, structured logging, middleware pipeline,
standardized error envelopes, /health, /ready probes, and OpenAPI documentation.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.api.v1.router import api_v1_router
from backend.app.core.config import Settings, get_settings
from backend.app.core.errors import (
    APIError,
    api_error_handler,
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from backend.app.core.logging import get_logger, setup_logging
from backend.app.core.middleware import (
    AccessLoggingMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)
from backend.app.core.readiness import ReadinessResponse, check_all_services

logger = get_logger("backend.lifecycle")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifecycle management for startup and shutdown."""
    settings: Settings = app.state.settings
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)

    logger.info(
        "VulnOS backend starting up",
        app_name=settings.APP_NAME,
        app_env=settings.APP_ENV,
        debug=settings.APP_DEBUG,
        version="0.1.0",
    )

    yield

    logger.info("VulnOS backend shutting down")


def create_app(settings: Settings | None = None) -> FastAPI:
    """FastAPI application factory."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title=f"{settings.APP_NAME} API",
        description="AI-assisted, evidence-based web and API vulnerability discovery engine.",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = settings

    # --- Exception Handlers ---------------------------------------------------
    app.add_exception_handler(APIError, api_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # --- Middleware Pipeline (outer to inner execution) -----------------------
    # 1. Access Logging (records full request-response lifecycle)
    app.add_middleware(AccessLoggingMiddleware)

    # 2. Security Headers (nosniff, frame-ancestors, CSP, HSTS)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)

    # 3. Request ID Middleware (attaches X-Request-ID and populates contextvars)
    app.add_middleware(RequestIDMiddleware)

    # 4. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # 5. Trusted Host Middleware (when allowed hosts configured)
    if settings.ALLOWED_HOSTS and "*" not in settings.ALLOWED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS,
        )

    # --- Root & Probe Endpoints -----------------------------------------------
    @app.get("/health", tags=["system"], summary="Liveness probe")
    async def health() -> dict[str, Any]:
        """Simple, unauthenticated liveness probe."""
        return {
            "status": "ok",
            "app": settings.APP_NAME,
            "version": "0.1.0",
            "environment": settings.APP_ENV,
        }

    @app.get(
        "/ready",
        tags=["system"],
        summary="Readiness probe",
        response_model=ReadinessResponse,
        responses={
            status.HTTP_200_OK: {
                "description": "All infrastructure dependencies are TCP reachable"
            },
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "description": "One or more infrastructure dependencies are unreachable"
            },
        },
    )
    async def ready() -> JSONResponse:
        """Bounded readiness probe checking TCP connectivity to Postgres, Redis, and S3.

        Returns 200 OK if all dependencies are reachable, or 503 Service Unavailable if any
        dependency fails the bounded TCP check.
        """
        all_ready, service_results = await check_all_services(settings)
        payload = ReadinessResponse(
            status="ready" if all_ready else "not_ready",
            services=service_results,
        )
        http_status = status.HTTP_200_OK if all_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=http_status, content=payload.model_dump())

    # --- Routers --------------------------------------------------------------
    app.include_router(api_v1_router)

    return app


# Default ASGI application instance for Uvicorn
app = create_app()
