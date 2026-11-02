"""Unit tests for VulnOS Authorization Schemas and Validation (P2.5.4.2).

Validates:
- Strict field validation on AuthorizationCreateRequest.
- Timezone awareness enforcement and UTC normalization.
- Invariant: valid_to must be strictly greater than valid_from.
- Action vocabulary validation, case folding, and deterministic deduplication.
- Secure boolean defaults (destructive_allowed=False, allow_private_ranges=False).
- Request ceiling bounds (positive integer, max 10,000,000, explicit nullable semantics).
- UUID format validation for document_evidence_id.
- Serialization and reason code verification on evaluation models.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.app.db.types import uuid7
from backend.app.scope.schemas import (
    AuthorizationCreateRequest,
    AuthorizationEvaluationResult,
    AuthorizationReasonCode,
    AuthorizationResponse,
)

# -----------------------------------------------------------------------------
# Creation Request Validations
# -----------------------------------------------------------------------------


def test_valid_authorization_create_request() -> None:
    """Valid request with ISO strings creates parsed, UTC-normalized model."""
    req = AuthorizationCreateRequest(
        reference="ENG-2026-041",
        authorized_by_name="Jane Doe",
        authorized_by_contact="security@example.com",
        valid_from=datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC),
        valid_to=datetime(2026, 12, 1, 0, 0, 0, tzinfo=UTC),
        allowed_actions=["scan", "validate"],
        destructive_allowed=False,
        allow_private_ranges=False,
        max_requests_per_scan=50000,
        notes="External testing only",
    )
    assert req.reference == "ENG-2026-041"
    assert req.authorized_by_name == "Jane Doe"
    assert req.authorized_by_contact == "security@example.com"
    assert req.valid_from.tzinfo == UTC
    assert req.valid_to.tzinfo == UTC
    assert req.allowed_actions == ["scan", "validate"]
    assert req.destructive_allowed is False
    assert req.allow_private_ranges is False
    assert req.max_requests_per_scan == 50000
    assert req.notes == "External testing only"


def test_missing_required_fields_raises() -> None:
    """Omission of required fields raises ValidationError."""
    with pytest.raises(ValidationError) as exc:
        AuthorizationCreateRequest.model_validate({})
    errors = {e["loc"][0] for e in exc.value.errors()}
    expected = {
        "reference",
        "authorized_by_name",
        "authorized_by_contact",
        "valid_from",
        "valid_to",
        "allowed_actions",
    }
    assert expected.issubset(errors)


def test_empty_and_whitespace_only_strings_rejected() -> None:
    """Empty or whitespace-only reference and contact strings are rejected."""
    base_data = {
        "reference": "   ",
        "authorized_by_name": "Valid Name",
        "authorized_by_contact": "contact@example.com",
        "valid_from": "2026-11-01T00:00:00Z",
        "valid_to": "2026-12-01T00:00:00Z",
        "allowed_actions": ["scan"],
    }
    with pytest.raises(ValidationError, match="reference"):
        AuthorizationCreateRequest.model_validate(base_data)

    base_data["reference"] = "REF-100"
    base_data["authorized_by_name"] = "\t  \n"
    with pytest.raises(ValidationError, match="authorized_by_name"):
        AuthorizationCreateRequest.model_validate(base_data)

    base_data["authorized_by_name"] = "Alice"
    base_data["authorized_by_contact"] = "   "
    with pytest.raises(ValidationError, match="authorized_by_contact"):
        AuthorizationCreateRequest.model_validate(base_data)


def test_naive_timestamp_rejection() -> None:
    """Timestamps without explicit timezone offset are strictly rejected."""
    # String naive
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuthorizationCreateRequest(
            reference="REF-1",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=datetime.fromisoformat("2026-11-01T00:00:00"),  # Naive string
            valid_to=datetime(2026, 12, 1, 0, 0, 0, tzinfo=UTC),
            allowed_actions=["scan"],
        )

    # Datetime naive
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuthorizationCreateRequest(
            reference="REF-1",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC),
            valid_to=datetime(2026, 12, 1, 0, 0, 0),  # Naive datetime object
            allowed_actions=["scan"],
        )


def test_utc_normalization() -> None:
    """Non-UTC timestamps with offsets are correctly normalized to UTC."""
    req = AuthorizationCreateRequest.model_validate(
        {
            "reference": "REF-TZ",
            "authorized_by_name": "Alice",
            "authorized_by_contact": "alice@example.com",
            "valid_from": "2026-11-01T05:30:00+05:30",  # Equivalent to 2026-11-01T00:00:00Z
            "valid_to": "2026-12-01T00:00:00Z",
            "allowed_actions": ["scan"],
        }
    )
    assert req.valid_from == datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
    assert req.valid_from.tzinfo == UTC


def test_valid_to_must_be_strictly_after_valid_from() -> None:
    """valid_to <= valid_from is rejected."""
    t1 = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)  # Equal
    t0 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)  # Before

    with pytest.raises(ValidationError, match="strictly after"):
        AuthorizationCreateRequest(
            reference="REF-EQ",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=t1,
            valid_to=t2,
            allowed_actions=["scan"],
        )

    with pytest.raises(ValidationError, match="strictly after"):
        AuthorizationCreateRequest(
            reference="REF-REV",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=t1,
            valid_to=t0,
            allowed_actions=["scan"],
        )


# -----------------------------------------------------------------------------
# Action Vocabulary & Permissions Tests
# -----------------------------------------------------------------------------

T_FROM = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
T_TO = datetime(2026, 12, 1, 0, 0, 0, tzinfo=UTC)


def test_allowed_actions_case_folding_and_deduplication() -> None:
    """Actions are folded to lowercase and deduplicated deterministically."""
    req = AuthorizationCreateRequest(
        reference="REF-ACT",
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=T_FROM,
        valid_to=T_TO,
        allowed_actions=["SCAN", "validate", "Scan", "AGENT_RUN"],
    )
    assert req.allowed_actions == ["agent_run", "scan", "validate"]


def test_unknown_action_rejected() -> None:
    """Unrecognized action names outside VALID_AUTHORIZATION_ACTIONS are rejected."""
    with pytest.raises(ValidationError, match="Unknown action 'arbitrary_exploit'"):
        AuthorizationCreateRequest(
            reference="REF-BAD",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=["scan", "arbitrary_exploit"],
        )


def test_empty_actions_list_rejected() -> None:
    """Empty allowed_actions list raises ValidationError."""
    with pytest.raises(ValidationError):
        AuthorizationCreateRequest(
            reference="REF-EMPTY",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=[],
        )


def test_boolean_permissions_secure_defaults() -> None:
    """destructive_allowed and allow_private_ranges default to False."""
    req = AuthorizationCreateRequest(
        reference="REF-DEF",
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=T_FROM,
        valid_to=T_TO,
        allowed_actions=["scan"],
    )
    assert req.destructive_allowed is False
    assert req.allow_private_ranges is False


# -----------------------------------------------------------------------------
# Request Ceiling & Evidence Reference Tests
# -----------------------------------------------------------------------------


def test_max_requests_per_scan_positive_and_nullable() -> None:
    """max_requests_per_scan must be positive; zero and negative values are rejected."""
    # Positive passes
    req = AuthorizationCreateRequest(
        reference="REF-LIM",
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=T_FROM,
        valid_to=T_TO,
        allowed_actions=["scan"],
        max_requests_per_scan=1000,
    )
    assert req.max_requests_per_scan == 1000

    # Nullable passes
    req_null = AuthorizationCreateRequest(
        reference="REF-LIM-NULL",
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=T_FROM,
        valid_to=T_TO,
        allowed_actions=["scan"],
        max_requests_per_scan=None,
    )
    assert req_null.max_requests_per_scan is None

    # Zero rejected
    with pytest.raises(ValidationError, match="positive integer"):
        AuthorizationCreateRequest(
            reference="REF-ZERO",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=["scan"],
            max_requests_per_scan=0,
        )

    # Negative rejected
    with pytest.raises(ValidationError, match="positive integer"):
        AuthorizationCreateRequest(
            reference="REF-NEG",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=["scan"],
            max_requests_per_scan=-500,
        )

    # Excessive ceiling rejected
    with pytest.raises(ValidationError, match="cannot exceed architecture ceiling"):
        AuthorizationCreateRequest(
            reference="REF-OVER",
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=["scan"],
            max_requests_per_scan=100_000_000,
        )


def test_document_evidence_id_validation() -> None:
    """document_evidence_id accepts valid UUID and rejects malformed strings."""
    ev_id = uuid7()
    req = AuthorizationCreateRequest(
        reference="REF-EV",
        document_evidence_id=ev_id,
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=T_FROM,
        valid_to=T_TO,
        allowed_actions=["scan"],
    )
    assert req.document_evidence_id == ev_id

    with pytest.raises(ValidationError):
        AuthorizationCreateRequest(
            reference="REF-BAD-EV",
            document_evidence_id="not-a-uuid",  # type: ignore[arg-type]
            authorized_by_name="Alice",
            authorized_by_contact="alice@example.com",
            valid_from=T_FROM,
            valid_to=T_TO,
            allowed_actions=["scan"],
        )


# -----------------------------------------------------------------------------
# Response & Evaluation Model Tests
# -----------------------------------------------------------------------------


def test_authorization_response_model() -> None:
    """AuthorizationResponse serializes expected fields without leaking internal secrets."""
    auth_id = uuid7()
    proj_id = uuid7()
    user_id = uuid7()
    now = datetime.now(UTC)

    res = AuthorizationResponse(
        id=auth_id,
        project_id=proj_id,
        reference="ENG-2026-041",
        document_evidence_id=None,
        authorized_by_name="Jane Doe",
        authorized_by_contact="security@example.com",
        valid_from=now,
        valid_to=datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
        allowed_actions=["scan", "validate"],
        destructive_allowed=False,
        allow_private_ranges=False,
        max_requests_per_scan=10000,
        notes="Standard pentest",
        created_by=user_id,
        created_at=now,
        revoked_at=None,
    )
    data = res.model_dump()
    assert data["id"] == auth_id
    assert data["project_id"] == proj_id
    assert data["reference"] == "ENG-2026-041"
    assert data["destructive_allowed"] is False
    assert data["revoked_at"] is None


def test_authorization_evaluation_result_model() -> None:
    """AuthorizationEvaluationResult formats structured decision outcomes."""
    auth_id = uuid7()
    proj_id = uuid7()

    eval_result = AuthorizationEvaluationResult(
        allowed=True,
        reason_code=AuthorizationReasonCode.VALID,
        authorization_id=auth_id,
        project_id=proj_id,
        action="scan",
        max_requests_per_scan=5000,
        destructive_allowed=False,
        allow_private_ranges=False,
    )
    assert eval_result.allowed is True
    assert eval_result.reason_code == "AUTHORIZATION_VALID"
    assert eval_result.action == "scan"

    eval_denied = AuthorizationEvaluationResult(
        allowed=False,
        reason_code=AuthorizationReasonCode.EXPIRED,
        authorization_id=auth_id,
        project_id=proj_id,
        action="scan",
    )
    assert eval_denied.allowed is False
    assert eval_denied.reason_code == "AUTHORIZATION_EXPIRED"
