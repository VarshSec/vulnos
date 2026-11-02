"""Tests for structured logging, correlation IDs, and processor redaction."""

from backend.app.core.logging import (
    correlation_id_processor,
    get_request_id,
    redaction_processor,
    set_request_id,
    setup_logging,
)
from backend.app.core.redaction import REDACTED_PLACEHOLDER


def test_contextvar_request_id_binding() -> None:
    """Request ID must bind to and read from contextvars cleanly."""
    set_request_id("req_test_12345")
    assert get_request_id() == "req_test_12345"

    set_request_id(None)
    assert get_request_id() is None


def test_correlation_id_processor() -> None:
    """Processor must inject active request_id from contextvar into event dict."""
    set_request_id("req_abc_789")
    try:
        event_dict = {"event": "test event"}
        processed = correlation_id_processor(None, "info", event_dict)
        assert processed["request_id"] == "req_abc_789"

        # Explicitly passed request_id should not be overwritten
        event_with_custom = {"event": "custom", "request_id": "req_explicit"}
        processed_custom = correlation_id_processor(None, "info", event_with_custom)
        assert processed_custom["request_id"] == "req_explicit"
    finally:
        set_request_id(None)


def test_redaction_processor() -> None:
    """Redaction processor must sanitize sensitive keys in logging event dict."""
    raw_event = {
        "event": "user authenticated",
        "user": "admin",
        "password": "ClearTextPassword!",
        "token": "secret_session_token",
        "api_key": "vln_live_xyz",
    }
    sanitized = redaction_processor(None, "info", raw_event)
    assert sanitized["user"] == "admin"
    assert sanitized["password"] == REDACTED_PLACEHOLDER
    assert sanitized["token"] == REDACTED_PLACEHOLDER
    assert sanitized["api_key"] == REDACTED_PLACEHOLDER


def test_setup_logging_runs_without_error() -> None:
    """Verify setup_logging configures root and structlog loggers safely."""
    setup_logging(log_level="DEBUG", log_format="json")
    setup_logging(log_level="INFO", log_format="console")
