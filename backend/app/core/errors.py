"""Structured error taxonomy and exception handlers per API_CONTRACTS.md.

Ensures a consistent error envelope across all HTTP errors, request validation failures,
and unhandled internal errors, including request ID correlation and safe exception masking.
"""

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.logging import get_logger, get_request_id

logger = get_logger("backend.errors")


class ErrorBody(BaseModel):
    """Inner error payload."""

    code: str = Field(..., description="Stable error code string")
    message: str = Field(..., description="Human-readable error explanation")
    details: dict[str, Any] = Field(default_factory=dict, description="Structured error context")
    request_id: str | None = Field(default=None, description="Request correlation identifier")


class ErrorEnvelope(BaseModel):
    """Top-level standard error envelope."""

    error: ErrorBody


class APIError(Exception):
    """Base application exception for anticipated API errors."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


# Standard HTTP status code to default error code mapping
HTTP_STATUS_CODE_MAP: dict[int, str] = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "dependency_unavailable",
    504: "gateway_timeout",
}


def create_error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Construct a standardized JSONResponse with the VulnOS error envelope."""
    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=code,
            message=message,
            details=details or {},
            request_id=request_id or get_request_id(),
        )
    )
    return JSONResponse(status_code=status_code, content=envelope.model_dump())


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle custom application APIError exceptions."""
    req_id = getattr(request.state, "request_id", None) or get_request_id()
    logger.warning(
        "API error occurred",
        code=exc.code,
        status_code=exc.status_code,
        message=exc.message,
        request_id=req_id,
        path=request.url.path,
    )
    return create_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
        request_id=req_id,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle standard Starlette / FastAPI HTTPExceptions."""
    req_id = getattr(request.state, "request_id", None) or get_request_id()
    code = HTTP_STATUS_CODE_MAP.get(exc.status_code, "http_error")
    message = str(exc.detail) if exc.detail else "An HTTP error occurred."

    logger.warning(
        "HTTP exception occurred",
        status_code=exc.status_code,
        code=code,
        message=message,
        request_id=req_id,
        path=request.url.path,
    )
    return create_error_response(
        status_code=exc.status_code,
        code=code,
        message=message,
        request_id=req_id,
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle request schema validation errors, extracting field paths."""
    req_id = getattr(request.state, "request_id", None) or get_request_id()
    formatted_fields: list[dict[str, str]] = []

    for err in exc.errors():
        loc = ".".join(str(elem) for elem in err.get("loc", []) if elem != "body")
        formatted_fields.append(
            {
                "path": loc or "root",
                "issue": err.get("msg", "Invalid value"),
            }
        )

    logger.info(
        "Request validation error",
        fields=formatted_fields,
        request_id=req_id,
        path=request.url.path,
    )

    return create_error_response(
        status_code=422,
        code="validation_error",
        message="Request validation failed.",
        details={"fields": formatted_fields},
        request_id=req_id,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unhandled exceptions (500 Internal Server Error).

    Logs the exception with stack trace securely, but returns a sanitized error envelope.
    """
    req_id = getattr(request.state, "request_id", None) or get_request_id()
    logger.exception(
        "Unhandled internal server error",
        error=str(exc),
        request_id=req_id,
        path=request.url.path,
    )

    return create_error_response(
        status_code=500,
        code="internal_error",
        message="An unexpected server error occurred. Please contact administrator.",
        request_id=req_id,
    )
