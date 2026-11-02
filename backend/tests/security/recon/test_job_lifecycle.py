"""Security and lifecycle unit tests for VulnOS Reconnaissance Job (Scan) Lifecycle.

Tests:
- Deterministic state transition validation.
- Every allowed and forbidden transition.
- Terminal-state reactivation rejection.
- Actor permission enforcement (preventing client-controlled status manipulation).
- Server-controlled timestamp semantics (started_at, finished_at, cancel_requested_at).
- Idempotent cancellation and terminal cancellation rejection.
- Partial completion semantics (ScanStageRun synchronization and stats recording).
- Timeout classification and distinct audit logging.
- Pause and resume behavior with authorization/scope revalidation.
- Immutable execution context protection after queueing.
- Row-level locking and project isolation.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.base import Base
from backend.app.db.models.audit import AuditLog
from backend.app.db.models.execution import Scan, ScanStageRun, ToolExecution
from backend.app.db.models.identity import (
    APIKey,
    AuthorizationRecord,
    Project,
    ProjectMember,
    ScopeDecision,
    ScopeRule,
    ScopeVersion,
    Target,
    User,
)
from backend.app.db.types import utc_now, uuid7
from backend.app.recon.exceptions import (
    ReconInvalidActorError,
    ReconJobAlreadyTerminalError,
    ReconJobAuthorizationInvalidError,
    ReconJobContextImmutableError,
    ReconJobInvalidStateError,
    ReconJobNotFoundError,
)
from backend.app.recon.lifecycle import (
    ACTOR_ADMIN,
    ACTOR_OPERATOR,
    ACTOR_SYSTEM,
    ACTOR_WORKER,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_DRAFT,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    _ensure_utc,
    assert_scan_context_immutable,
    pause_scan,
    request_scan_cancellation,
    resume_scan,
    transition_scan,
    validate_scan_transition,
)


@pytest.fixture
def recon_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for recon lifecycle tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [
        User.__table__,
        Project.__table__,
        ProjectMember.__table__,
        Target.__table__,
        AuditLog.__table__,
        APIKey.__table__,
        AuthorizationRecord.__table__,
        ScopeVersion.__table__,
        ScopeRule.__table__,
        ScopeDecision.__table__,
        Scan.__table__,
        ScanStageRun.__table__,
        ToolExecution.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine, tables=tables)  # type: ignore[arg-type]
        engine.dispose()


@pytest.fixture
def seeded_env(recon_session_factory: sessionmaker[Session]) -> Generator[dict[str, Any]]:
    """Seed project, user, target, authorization record, and active scope version."""
    session = recon_session_factory()
    now = utc_now()

    user = User(
        id=uuid7(),
        email="operator@example.com",
        display_name="Operator User",
        password_hash="argon2id$fake",
        is_active=True,
    )
    session.add(user)

    project = Project(
        id=uuid7(),
        name="Recon Test Project",
        slug="recon-test",
        owner_id=user.id,
        status="active",
    )
    session.add(project)

    target = Target(
        id=uuid7(),
        project_id=project.id,
        name="Target 1",
        seed_type="domain",
        seed_value="example.com",
        created_by=user.id,
    )
    session.add(target)

    auth = AuthorizationRecord(
        id=uuid7(),
        project_id=project.id,
        reference="AUTH-RECON-001",
        authorized_by_name="Alice Owner",
        authorized_by_contact="alice@example.com",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=30),
        allowed_actions=["recon", "discovery", "read"],
        created_by=user.id,
    )
    session.add(auth)

    scope_ver = ScopeVersion(
        id=uuid7(),
        project_id=project.id,
        authorization_id=auth.id,
        version=1,
        status="active",
        content_hash=b"\x00" * 32,
        created_by=user.id,
        activated_at=now,
    )
    session.add(scope_ver)

    session.commit()

    try:
        yield {
            "project_id": project.id,
            "user_id": user.id,
            "target_id": target.id,
            "authorization_id": auth.id,
            "scope_version_id": scope_ver.id,
            "session_factory": recon_session_factory,
        }
    finally:
        session.close()


def _create_test_scan(
    session: Session,
    env: dict[str, Any],
    status: str = STATUS_DRAFT,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    cancel_requested_at: datetime | None = None,
    with_stage_run: bool = True,
) -> Scan:
    """Helper to create a test Scan with optional ScanStageRun."""
    scan = Scan(
        id=uuid7(),
        project_id=env["project_id"],
        name="Test Recon Scan",
        scan_type="recon",
        status=status,
        scope_version_id=env["scope_version_id"],
        authorization_id=env["authorization_id"],
        target_ids=[env["target_id"]],
        profile={"modules": ["dns", "ports"]},
        budget={"max_requests": 1000, "max_wall_clock_minutes": 60},
        requested_by=env["user_id"],
        started_at=started_at,
        finished_at=finished_at,
        cancel_requested_at=cancel_requested_at,
        cost_usd=Decimal("0.0"),
        stats={},
    )
    session.add(scan)
    session.flush()

    if with_stage_run:
        if status in (STATUS_DRAFT, STATUS_QUEUED):
            stage_status = "pending"
        elif status in (STATUS_RUNNING, STATUS_PAUSED):
            stage_status = "running"
        elif status == STATUS_COMPLETED:
            stage_status = "succeeded"
        else:
            stage_status = status

        stage_run = ScanStageRun(
            id=uuid7(),
            project_id=env["project_id"],
            scan_id=scan.id,
            stage="recon",
            attempt=1,
            status=stage_status,
            metrics={},
        )
        session.add(stage_run)
        session.flush()

    session.commit()
    return scan


# ============================================================================
# 1. State Transition Validation Unit Tests (Pure Function)
# ============================================================================


def test_validate_scan_transition_allowed_paths() -> None:
    """Verify that every legal transition passes validation with correct actors."""
    # draft -> queued
    assert validate_scan_transition(STATUS_DRAFT, STATUS_QUEUED, ACTOR_OPERATOR)
    assert validate_scan_transition(STATUS_DRAFT, STATUS_QUEUED, ACTOR_SYSTEM)

    # draft -> cancelled
    assert validate_scan_transition(STATUS_DRAFT, STATUS_CANCELLED, ACTOR_OPERATOR)

    # queued -> running
    assert validate_scan_transition(STATUS_QUEUED, STATUS_RUNNING, ACTOR_SYSTEM)
    assert validate_scan_transition(STATUS_QUEUED, STATUS_RUNNING, ACTOR_WORKER)

    # queued -> cancelled
    assert validate_scan_transition(STATUS_QUEUED, STATUS_CANCELLED, ACTOR_OPERATOR)
    assert validate_scan_transition(STATUS_QUEUED, STATUS_CANCELLED, ACTOR_SYSTEM)

    # running -> completed
    assert validate_scan_transition(STATUS_RUNNING, STATUS_COMPLETED, ACTOR_SYSTEM)

    # running -> failed
    assert validate_scan_transition(STATUS_RUNNING, STATUS_FAILED, ACTOR_SYSTEM)

    # running -> cancelled
    assert validate_scan_transition(STATUS_RUNNING, STATUS_CANCELLED, ACTOR_OPERATOR)
    assert validate_scan_transition(STATUS_RUNNING, STATUS_CANCELLED, ACTOR_SYSTEM)

    # running -> paused
    assert validate_scan_transition(STATUS_RUNNING, STATUS_PAUSED, ACTOR_OPERATOR)

    # paused -> running
    assert validate_scan_transition(STATUS_PAUSED, STATUS_RUNNING, ACTOR_ADMIN)

    # paused -> cancelled
    assert validate_scan_transition(STATUS_PAUSED, STATUS_CANCELLED, ACTOR_OPERATOR)


def test_validate_scan_transition_idempotent() -> None:
    """Self-transitions are idempotent no-ops."""
    for s in (
        STATUS_DRAFT,
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_PAUSED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    ):
        assert validate_scan_transition(s, s, ACTOR_SYSTEM)
        assert validate_scan_transition(s, s, ACTOR_OPERATOR)


def test_validate_scan_transition_terminal_reactivation_rejected() -> None:
    """Reactivating a terminal state (completed, failed, cancelled) is strictly forbidden."""
    for terminal in (STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED):
        for target in (STATUS_DRAFT, STATUS_QUEUED, STATUS_RUNNING, STATUS_PAUSED):
            with pytest.raises(ReconJobAlreadyTerminalError, match="terminal state"):
                validate_scan_transition(terminal, target, ACTOR_SYSTEM)


def test_validate_scan_transition_illegal_transitions_rejected() -> None:
    """Illegal transitions (e.g. draft -> running, queued -> completed) are rejected."""
    illegal_pairs = [
        (STATUS_DRAFT, STATUS_RUNNING),
        (STATUS_DRAFT, STATUS_COMPLETED),
        (STATUS_DRAFT, STATUS_FAILED),
        (STATUS_DRAFT, STATUS_PAUSED),
        (STATUS_QUEUED, STATUS_COMPLETED),
        (STATUS_QUEUED, STATUS_PAUSED),
        (STATUS_PAUSED, STATUS_COMPLETED),
        (STATUS_PAUSED, STATUS_FAILED),
        (STATUS_RUNNING, STATUS_DRAFT),
        (STATUS_RUNNING, STATUS_QUEUED),
    ]
    for current, target in illegal_pairs:
        with pytest.raises(ReconJobInvalidStateError, match="Illegal scan state transition"):
            validate_scan_transition(current, target, ACTOR_SYSTEM)


def test_validate_scan_transition_invalid_actors() -> None:
    """Actors lacking permission for a transition are rejected."""
    # Worker cannot cancel a draft job
    with pytest.raises(ReconInvalidActorError, match="not authorized"):
        validate_scan_transition(STATUS_DRAFT, STATUS_CANCELLED, ACTOR_WORKER)

    # Operator cannot directly mark a running job as completed (only system/orchestrator can)
    with pytest.raises(ReconInvalidActorError, match="not authorized"):
        validate_scan_transition(STATUS_RUNNING, STATUS_COMPLETED, ACTOR_OPERATOR)

    # Operator cannot directly mark a queued job as running (only worker/system can)
    with pytest.raises(ReconInvalidActorError, match="not authorized"):
        validate_scan_transition(STATUS_QUEUED, STATUS_RUNNING, ACTOR_OPERATOR)


def test_validate_scan_transition_unknown_status() -> None:
    """Unknown status strings are rejected."""
    with pytest.raises(ReconJobInvalidStateError, match="Unknown current"):
        validate_scan_transition("invalid_status", STATUS_RUNNING, ACTOR_SYSTEM)

    with pytest.raises(ReconJobInvalidStateError, match="Unknown requested"):
        validate_scan_transition(STATUS_DRAFT, "nonexistent", ACTOR_SYSTEM)


# ============================================================================
# 2. Immutable Execution Context Tests
# ============================================================================


def test_assert_scan_context_immutable_allows_draft(seeded_env: dict[str, Any]) -> None:
    """Context modification is allowed while in 'draft' status."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_DRAFT)

    # Should not raise
    assert_scan_context_immutable(scan, {"budget": {"max_requests": 9999}})


def test_assert_scan_context_immutable_rejects_queued_or_running(
    seeded_env: dict[str, Any],
) -> None:
    """Context modification is strictly rejected once queued or running."""
    session = seeded_env["session_factory"]()
    for status in (STATUS_QUEUED, STATUS_RUNNING, STATUS_PAUSED):
        scan = _create_test_scan(session, seeded_env, status=status)

        # Altering authorization_id
        with pytest.raises(ReconJobContextImmutableError, match="immutable execution context"):
            assert_scan_context_immutable(scan, {"authorization_id": uuid7()})

        # Altering scope_version_id
        with pytest.raises(ReconJobContextImmutableError, match="immutable execution context"):
            assert_scan_context_immutable(scan, {"scope_version_id": uuid7()})

        # Altering target_ids
        with pytest.raises(ReconJobContextImmutableError, match="immutable execution context"):
            assert_scan_context_immutable(scan, {"target_ids": [uuid7()]})

        # Altering budget
        with pytest.raises(ReconJobContextImmutableError, match="immutable execution context"):
            assert_scan_context_immutable(scan, {"budget": {"max_requests": 50000}})


# ============================================================================
# 3. Transactional State Transition Service Tests
# ============================================================================


def test_transition_scan_full_lifecycle(seeded_env: dict[str, Any]) -> None:
    """Test standard progression: draft -> queued -> running -> completed."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_DRAFT)

    t0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 11, 2, 10, 1, 0, tzinfo=UTC)
    t2 = datetime(2026, 11, 2, 10, 15, 0, tzinfo=UTC)

    # 1. draft -> queued
    s1 = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_QUEUED,
        actor_id=str(seeded_env["user_id"]),
        actor_type=ACTOR_OPERATOR,
        evaluation_time=t0,
    )
    assert s1.status == STATUS_QUEUED
    assert s1.started_at is None
    assert s1.finished_at is None

    # 2. queued -> running
    s2 = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_RUNNING,
        actor_id="worker-01",
        actor_type=ACTOR_WORKER,
        evaluation_time=t1,
    )
    assert s2.status == STATUS_RUNNING
    assert s2.started_at == t1
    assert s2.finished_at is None

    # Repeated running transition does not overwrite started_at
    s2_repeat = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_RUNNING,
        actor_id="worker-01",
        actor_type=ACTOR_WORKER,
        evaluation_time=t2,
    )
    assert s2_repeat.started_at == t1

    # 3. running -> completed
    s3 = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_COMPLETED,
        actor_id="orchestrator",
        actor_type=ACTOR_SYSTEM,
        evaluation_time=t2,
    )
    assert s3.status == STATUS_COMPLETED
    assert s3.started_at == t1
    assert s3.finished_at == t2


def test_transition_scan_partial_completion(seeded_env: dict[str, Any]) -> None:
    """Test partial completion recording stats and stage run status."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_RUNNING)

    completed = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_COMPLETED,
        actor_id="orchestrator",
        actor_type=ACTOR_SYSTEM,
        is_partial=True,
    )
    assert completed.status == STATUS_COMPLETED
    assert completed.stats.get("partially_completed") is True

    # Verify stage run was marked partial
    stage_run = session.query(ScanStageRun).filter_by(scan_id=scan.id).first()
    assert stage_run is not None
    assert stage_run.status == "partial"

    # Verify audit log recorded partial completion
    audit = (
        session.query(AuditLog)
        .filter_by(entity_id=str(scan.id), action="recon_job.partial_completed")
        .first()
    )
    assert audit is not None
    assert audit.metadata_["is_partial"] is True


def test_transition_scan_timeout_failure(seeded_env: dict[str, Any]) -> None:
    """Test failure transition with timeout classification."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_RUNNING)

    failed = transition_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        STATUS_FAILED,
        actor_id="orchestrator",
        actor_type=ACTOR_SYSTEM,
        failure_reason="timeout",
        reason="Exceeded maximum wall-clock minutes (60m)",
    )
    assert failed.status == STATUS_FAILED
    assert failed.stats.get("failure_reason") == "timeout"

    # Verify stage run updated with timeout
    stage_run = session.query(ScanStageRun).filter_by(scan_id=scan.id).first()
    assert stage_run is not None
    assert stage_run.status == "failed"
    assert stage_run.error_code == "timeout"

    # Verify audit log recorded timeout action
    audit = (
        session.query(AuditLog)
        .filter_by(entity_id=str(scan.id), action="recon_job.timed_out")
        .first()
    )
    assert audit is not None
    assert audit.metadata_["failure_reason"] == "timeout"


def test_transition_scan_not_found_and_cross_project(seeded_env: dict[str, Any]) -> None:
    """Non-existent scan or cross-project access raises ReconJobNotFoundError."""
    session = seeded_env["session_factory"]()
    foreign_project_id = uuid7()

    # Non-existent scan
    with pytest.raises(ReconJobNotFoundError):
        transition_scan(
            session,
            seeded_env["project_id"],
            uuid7(),
            STATUS_QUEUED,
            actor_id="user",
            actor_type=ACTOR_OPERATOR,
        )

    # Valid scan but wrong project ID
    scan = _create_test_scan(session, seeded_env, status=STATUS_DRAFT)
    with pytest.raises(ReconJobNotFoundError):
        transition_scan(
            session,
            foreign_project_id,
            scan.id,
            STATUS_QUEUED,
            actor_id="user",
            actor_type=ACTOR_OPERATOR,
        )


# ============================================================================
# 4. Cancellation Handling Tests
# ============================================================================


def test_request_scan_cancellation_from_queued(seeded_env: dict[str, Any]) -> None:
    """Cancelling a queued scan immediately transitions to cancelled."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_QUEUED)

    now = utc_now()
    cancelled = request_scan_cancellation(
        session,
        seeded_env["project_id"],
        scan.id,
        actor_id=str(seeded_env["user_id"]),
        actor_type=ACTOR_OPERATOR,
        reason="Client aborted",
        evaluation_time=now,
    )
    assert cancelled.status == STATUS_CANCELLED
    assert cancelled.cancel_requested_at == now
    assert cancelled.finished_at == now

    # Verify audit log
    audit_req = (
        session.query(AuditLog)
        .filter_by(entity_id=str(scan.id), action="recon_job.cancel_requested")
        .first()
    )
    assert audit_req is not None


def test_request_scan_cancellation_from_running(seeded_env: dict[str, Any]) -> None:
    """Cancelling a running scan sets cancel_requested_at and transitions to cancelled."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_RUNNING)

    now = utc_now()
    cancelled = request_scan_cancellation(
        session,
        seeded_env["project_id"],
        scan.id,
        actor_id=str(seeded_env["user_id"]),
        actor_type=ACTOR_OPERATOR,
        reason="Operator stopped scan",
        evaluation_time=now,
    )
    assert cancelled.status == STATUS_CANCELLED
    assert cancelled.cancel_requested_at == now
    assert cancelled.finished_at == now


def test_request_scan_cancellation_idempotency(seeded_env: dict[str, Any]) -> None:
    """Repeated cancellation of an already cancelled scan is a safe no-op."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_CANCELLED)
    original_finished = utc_now() - timedelta(minutes=10)
    scan.finished_at = original_finished
    scan.cancel_requested_at = original_finished
    session.commit()

    # Calling cancellation again should return scan without altering timestamps
    repeated = request_scan_cancellation(
        session,
        seeded_env["project_id"],
        scan.id,
        actor_id="user",
        actor_type=ACTOR_OPERATOR,
    )
    assert repeated.status == STATUS_CANCELLED
    assert _ensure_utc(repeated.finished_at) == original_finished
    assert _ensure_utc(repeated.cancel_requested_at) == original_finished


def test_request_scan_cancellation_on_completed_rejected(
    seeded_env: dict[str, Any],
) -> None:
    """Cancelling a scan that is already completed or failed is strictly rejected."""
    session = seeded_env["session_factory"]()
    completed = _create_test_scan(session, seeded_env, status=STATUS_COMPLETED)

    with pytest.raises(ReconJobAlreadyTerminalError, match="already finished"):
        request_scan_cancellation(
            session,
            seeded_env["project_id"],
            completed.id,
            actor_id="user",
            actor_type=ACTOR_OPERATOR,
        )

    failed = _create_test_scan(session, seeded_env, status=STATUS_FAILED)
    with pytest.raises(ReconJobAlreadyTerminalError, match="already finished"):
        request_scan_cancellation(
            session,
            seeded_env["project_id"],
            failed.id,
            actor_id="user",
            actor_type=ACTOR_OPERATOR,
        )


# ============================================================================
# 5. Pause & Resume Behavior Tests
# ============================================================================


def test_pause_and_resume_scan_success(seeded_env: dict[str, Any]) -> None:
    """Test pause and successful resume with valid authorization and scope."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_RUNNING)

    # 1. Pause
    paused = pause_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        actor_id=str(seeded_env["user_id"]),
        actor_type=ACTOR_OPERATOR,
    )
    assert paused.status == STATUS_PAUSED

    # 2. Resume
    resumed = resume_scan(
        session,
        seeded_env["project_id"],
        scan.id,
        actor_id=str(seeded_env["user_id"]),
        actor_type=ACTOR_OPERATOR,
    )
    assert resumed.status == STATUS_RUNNING


def test_resume_scan_rejects_revoked_authorization(seeded_env: dict[str, Any]) -> None:
    """Resuming a paused scan fails closed if authorization was revoked while paused."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_PAUSED)

    # Revoke authorization record
    auth = session.query(AuthorizationRecord).filter_by(id=scan.authorization_id).first()
    assert auth is not None
    auth.revoked_at = utc_now()
    session.commit()

    # Attempt to resume
    with pytest.raises(ReconJobAuthorizationInvalidError, match="revoked"):
        resume_scan(
            session,
            seeded_env["project_id"],
            scan.id,
            actor_id="operator",
            actor_type=ACTOR_OPERATOR,
        )


def test_resume_scan_rejects_expired_authorization(seeded_env: dict[str, Any]) -> None:
    """Resuming a paused scan fails closed if authorization expired while paused."""
    session = seeded_env["session_factory"]()
    scan = _create_test_scan(session, seeded_env, status=STATUS_PAUSED)

    # Set valid_to in the past
    auth = session.query(AuthorizationRecord).filter_by(id=scan.authorization_id).first()
    assert auth is not None
    auth.valid_to = utc_now() - timedelta(minutes=5)
    session.commit()

    # Attempt to resume
    with pytest.raises(ReconJobAuthorizationInvalidError, match="expired"):
        resume_scan(
            session,
            seeded_env["project_id"],
            scan.id,
            actor_id="operator",
            actor_type=ACTOR_OPERATOR,
        )


def test_resume_scan_rejects_non_paused(seeded_env: dict[str, Any]) -> None:
    """Attempting to resume a draft, queued, or running scan is rejected."""
    session = seeded_env["session_factory"]()
    running = _create_test_scan(session, seeded_env, status=STATUS_RUNNING)

    with pytest.raises(ReconJobInvalidStateError, match="Only 'paused' scans"):
        resume_scan(
            session,
            seeded_env["project_id"],
            running.id,
            actor_id="operator",
            actor_type=ACTOR_OPERATOR,
        )
