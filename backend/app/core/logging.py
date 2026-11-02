"""Structured JSON logging configuration for VulnOS.

Configures structlog with UTC ISO timestamps, contextvars (for request correlation IDs),
and automatic recursive redaction of sensitive fields.
"""

import contextvars
import logging
import sys
from typing import Any

import structlog

from backend.app.core.redaction import redact_sensitive_data

# Context variable for request correlation ID across async execution contexts
current_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_request_id", default=None
)


def get_request_id() -> str | None:
    """Retrieve current request ID from contextvar."""
    return current_request_id.get()


def set_request_id(request_id: str | None) -> None:
    """Set the current request ID in contextvar."""
    current_request_id.set(request_id)


def redaction_processor(
    _logger: Any,
    _method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Structlog processor that recursively redacts sensitive information."""
    return redact_sensitive_data(event_dict)  # type: ignore[no-any-return]


def correlation_id_processor(
    _logger: Any,
    _method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Attach active request_id from contextvars if not already present in event."""
    req_id = get_request_id()
    if req_id and "request_id" not in event_dict:
        event_dict["request_id"] = req_id
    return event_dict


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure standard library and structlog loggers."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        correlation_id_processor,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redaction_processor,
    ]

    if log_format.lower() == "console":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(numeric_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Obtain a structured logger instance."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]
