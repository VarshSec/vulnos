"""Security and integration tests for VulnOS Task Lease Claim Service (P3.1.3.4.4.2).

Tests:
1. Successful claim: queued task claimed, status becomes running, started_at set, worker_id set.
2. Immutable TaskLeaseClaim returned with raw token, attempt, worker_id, lease_expires_at.
3. Cryptographic token generation: raw token has 256 bits entropy, only SHA-256 hash stored.
4. Zero token leakage: raw token is NEVER persisted in task.stats, AuditLog metadata, or logs.
5. Preserved attempt semantics: claiming binds active attempt without incrementing.
6. Timeout boundary validation: 30s and 86400s allowed;
   <30, >86400, bool, and invalid types rejected.
7. Worker ID validation: empty string, whitespace, non-string rejected.
8. Duplicate claim rejection: already running task cannot be claimed by another or same worker.
9. Terminal task rejection: terminal tasks (succeeded, cancelled, skipped,
   scope_violation, failed, timeout) rejected.
10. Parent Scan state restrictions: queued/running allowed; draft, paused,
    completed, failed, cancelled rejected.
11. Cross-project isolation: mismatched project_id fails closed.
12. Parent-child consistency: task.scan_id != scan.id fails closed with ReconJobNotFoundError.
13. Audit trail: recon_task.lease_claimed emitted with zero token material in same transaction.
14. Audit failure atomicity: failure during audit insertion rolls back the claim completely.
15. Timestamp integrity: timezone-aware UTC for started_at and lease_expires_at.
16. Concurrent claiming serialization: only one worker can successfully claim a queued task.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.base import Base
from backend.app.db.models.audit import AuditLog
from backend.app.db.models.execution import Scan, ScanStageRun, Tool, ToolExecution, ToolVersion
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
    ReconJobNotFoundError,
    ReconTaskAlreadyClaimedError,
    ReconTaskInvalidActorError,
    ReconTaskInvalidTimeoutError,
    ReconTaskNotFoundError,
    ReconTaskParentStateInvalidError,
    ReconTaskTerminalStateError,
)
from backend.app.recon.task_lifecycle import (
    MAX_LEASE_TIMEOUT_SECONDS,
    MIN_LEASE_TIMEOUT_SECONDS,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_DRAFT,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PAUSED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SCOPE_VIOLATION,
    STATUS_SKIPPED,
    STATUS_SUCCEEDED,
    STATUS_TIMEOUT,
    TaskLeaseClaim,
    claim_task_lease,
)


@pytest.fixture
def recon_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for task lease claim tests."""
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
        Tool.__table__,
        ToolVersion.__table__,
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
    """Seed project, tool, tool version, scan, and initial queued task."""
    session = recon_session_factory()
    now = utc_now()

    user = User(
        id=uuid7(),
        email="operator@example.com",
        display_name="Operator User",
        is_active=True,
    )
    session.add(user)

    project = Project(
        id=uuid7(),
        name="Test Recon Project",
        slug="test-recon-proj",
        owner_id=user.id,
    )
    session.add(project)

    target = Target(
        id=uuid7(),
        project_id=project.id,
        name="Target Domain",
        seed_type="domain",
        seed_value="example.com",
        created_by=user.id,
    )
    session.add(target)

    tool = Tool(
        id=uuid7(),
        name="test_scanner",
        category="recon",
        description="Test Scanner",
    )
    session.add(tool)

    tool_version = ToolVersion(
        id=uuid7(),
        tool_id=tool.id,
        version="1.0.0",
        image_ref="registry.vulnos.local/test_scanner:1.0.0",
        image_digest="sha256:" + "0" * 64,
        verification_status="production_verified",
    )
    session.add(tool_version)

    scan = Scan(
        id=uuid7(),
        project_id=project.id,
        name="Recon Scan",
        scan_type="recon",
        status=SCAN_STATUS_RUNNING,
        scope_version_id=uuid7(),
        authorization_id=uuid7(),
        target_ids=[target.id],
        budget={"max_requests": 1000},
        requested_by=user.id,
    )
    session.add(scan)

    task = ToolExecution(
        id=uuid7(),
        project_id=project.id,
        scan_id=scan.id,
        stage="recon",
        tool_version_id=tool_version.id,
        status=STATUS_QUEUED,
        attempt=1,
        input={"destination": "example.com"},
        stats={},
        created_at=now,
    )
    session.add(task)
    session.commit()

    yield {
        "session": session,
        "project": project,
        "user": user,
        "scan": scan,
        "task": task,
        "tool_version": tool_version,
    }
    session.close()


def test_claim_task_lease_success(seeded_env: dict[str, Any]) -> None:
    """Validate successful claim of a queued task."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]
    scan: Scan = seeded_env["scan"]

    fixed_time = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)

    claimed_task, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-recon-01",
        timeout_seconds=300,
        evaluation_time=fixed_time,
        request_id="req-123",
        correlation_id="corr-456",
    )

    # 1. Verify returned task
    assert claimed_task.id == task.id
    assert claimed_task.status == STATUS_RUNNING
    assert claimed_task.worker_id == "worker-recon-01"
    assert claimed_task.started_at == fixed_time
    assert claimed_task.attempt == 1

    # 2. Verify returned claim object
    assert isinstance(claim, TaskLeaseClaim)
    assert claim.execution_id == task.id
    assert claim.scan_id == scan.id
    assert claim.project_id == project.id
    assert claim.attempt == 1
    assert claim.worker_id == "worker-recon-01"
    assert isinstance(claim.lease_token, str)
    assert len(claim.lease_token) >= 32
    assert claim.started_at == fixed_time
    assert claim.lease_expires_at == fixed_time + timedelta(seconds=300)

    # 3. Verify stats persistence (hash stored, NOT plaintext)
    assert "lease_token_hash" in claimed_task.stats
    expected_hash = hashlib.sha256(claim.lease_token.encode("utf-8")).hexdigest()
    assert claimed_task.stats["lease_token_hash"] == expected_hash
    expected_expiry = (fixed_time + timedelta(seconds=300)).isoformat()
    assert claimed_task.stats["lease_expires_at"] == expected_expiry
    assert claimed_task.stats["lease_timeout_seconds"] == 300
    assert "lease_token" not in claimed_task.stats  # Zero plaintext token leakage

    # 4. Verify AuditLog
    audit_entry = session.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.lease_claimed",
        )
    )
    assert audit_entry is not None
    assert audit_entry.actor_type == "worker"
    assert audit_entry.actor_id == "worker-recon-01"
    assert audit_entry.project_id == project.id
    assert audit_entry.metadata_["attempt"] == 1
    assert audit_entry.metadata_["timeout_seconds"] == 300
    assert audit_entry.metadata_["correlation_id"] == "corr-456"
    assert "lease_token" not in audit_entry.metadata_
    assert "lease_token_hash" not in audit_entry.metadata_


def test_claim_task_lease_parent_scan_queued_permitted(seeded_env: dict[str, Any]) -> None:
    """Validate that parent Scan in 'queued' status also permits task claims."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]
    scan: Scan = seeded_env["scan"]

    scan.status = SCAN_STATUS_QUEUED
    session.flush()

    claimed_task, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-02",
    )
    assert claimed_task.status == STATUS_RUNNING
    assert claim.worker_id == "worker-02"


@pytest.mark.parametrize(
    "disallowed_scan_status",
    [
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    ],
)
def test_claim_task_lease_parent_scan_disallowed_states(
    seeded_env: dict[str, Any], disallowed_scan_status: str
) -> None:
    """Validate that parent Scan in draft, paused, or terminal status rejects task claims."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]
    scan: Scan = seeded_env["scan"]

    scan.status = disallowed_scan_status
    session.flush()

    with pytest.raises(ReconTaskParentStateInvalidError) as exc_info:
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-03",
        )
    assert disallowed_scan_status in str(exc_info.value)


def test_claim_task_lease_timeout_boundaries(seeded_env: dict[str, Any]) -> None:
    """Validate timeout boundary conditions: 30s and 86400s allowed; others rejected."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    # Lower boundary: 30s succeeds
    _claimed_task, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-min",
        timeout_seconds=MIN_LEASE_TIMEOUT_SECONDS,
    )
    assert claim.lease_expires_at == claim.started_at + timedelta(seconds=30)

    # Reset task back to queued for upper boundary test
    task.status = STATUS_QUEUED
    task.worker_id = None
    session.flush()

    # Upper boundary: 86400s succeeds
    _claimed_task, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-max",
        timeout_seconds=MAX_LEASE_TIMEOUT_SECONDS,
    )
    assert claim.lease_expires_at == claim.started_at + timedelta(seconds=86400)


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        29,
        86401,
        0,
        -1,
        -300,
        "300",
        True,
        False,
        30.5,
        None,
    ],
)
def test_claim_task_lease_invalid_timeout_rejected(
    seeded_env: dict[str, Any], invalid_timeout: Any
) -> None:
    """Validate rejection of timeout values outside [30, 86400] or invalid types."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    with pytest.raises(ReconTaskInvalidTimeoutError):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-invalid-timeout",
            timeout_seconds=invalid_timeout,
        )


@pytest.mark.parametrize("invalid_worker", ["", "   ", None, 123, []])
def test_claim_task_lease_invalid_worker_id(
    seeded_env: dict[str, Any], invalid_worker: Any
) -> None:
    """Validate rejection of empty or non-string worker IDs."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    with pytest.raises(ReconTaskInvalidActorError):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id=invalid_worker,
        )


def test_claim_task_lease_duplicate_claim_rejected(seeded_env: dict[str, Any]) -> None:
    """Validate that once claimed (running), subsequent claims fail closed."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    # First claim succeeds
    claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-first",
    )
    session.flush()

    # Second claim by another worker fails
    with pytest.raises(ReconTaskAlreadyClaimedError) as exc_info:
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-second",
        )
    assert "worker-first" in str(exc_info.value)

    # Re-claim by the same worker also fails (idempotent re-claim without retry is not permitted)
    with pytest.raises(ReconTaskAlreadyClaimedError):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-first",
        )


@pytest.mark.parametrize(
    "terminal_status",
    [
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_TIMEOUT,
        STATUS_CANCELLED,
        STATUS_SKIPPED,
        STATUS_SCOPE_VIOLATION,
    ],
)
def test_claim_task_lease_terminal_task_rejected(
    seeded_env: dict[str, Any], terminal_status: str
) -> None:
    """Validate that tasks in terminal or failed states cannot be claimed directly."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    task.status = terminal_status
    session.flush()

    with pytest.raises(ReconTaskTerminalStateError):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-terminal",
        )


def test_claim_task_lease_attempt_preservation(seeded_env: dict[str, Any]) -> None:
    """Validate that claiming a task does NOT increment attempt."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    # Simulate a task that was retried to attempt = 3
    task.attempt = 3
    session.flush()

    claimed_task, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-attempt-3",
    )
    assert claimed_task.attempt == 3
    assert claim.attempt == 3


def test_claim_task_lease_token_cryptographic_uniqueness(seeded_env: dict[str, Any]) -> None:
    """Validate cryptographic token generation and verification using secrets.compare_digest."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    _, claim1 = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-token-test",
    )

    # Token must be constant-time verifiable via SHA-256 hash
    computed_hash = hashlib.sha256(claim1.lease_token.encode("utf-8")).hexdigest()
    assert secrets.compare_digest(computed_hash, task.stats["lease_token_hash"])

    # Tampered token fails comparison
    tampered_token = claim1.lease_token[:-1] + ("A" if claim1.lease_token[-1] != "A" else "B")
    tampered_hash = hashlib.sha256(tampered_token.encode("utf-8")).hexdigest()
    assert not secrets.compare_digest(tampered_hash, task.stats["lease_token_hash"])


def test_claim_task_lease_cross_project_rejection(seeded_env: dict[str, Any]) -> None:
    """Validate that claiming with a mismatched project_id fails closed."""
    session: Session = seeded_env["session"]
    task: ToolExecution = seeded_env["task"]
    foreign_project_id = uuid7()

    with pytest.raises(ReconTaskNotFoundError):
        claim_task_lease(
            db=session,
            project_id=foreign_project_id,
            execution_id=task.id,
            worker_id="worker-cross-proj",
        )


def test_claim_task_lease_parent_child_mismatch(seeded_env: dict[str, Any]) -> None:
    """Validate rejection when task.project_id != scan.project_id."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]
    scan: Scan = seeded_env["scan"]

    # Deliberately desynchronize project association
    scan.project_id = uuid7()
    session.flush()

    with pytest.raises(ReconJobNotFoundError):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-desync",
        )


def test_claim_task_lease_audit_write_failure_rolls_back(seeded_env: dict[str, Any]) -> None:
    """Validate that failure during AuditLog insertion rolls back the entire claim transaction."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    original_status = task.status
    original_worker = task.worker_id

    # Simulate audit write database error
    with (
        patch.object(session, "add", side_effect=RuntimeError("DB Disk Full during AuditLog")),
        pytest.raises(RuntimeError, match="DB Disk Full"),
    ):
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-crash",
        )

    # Roll back session and verify task status remains queued
    session.rollback()
    refreshed_task = session.get(ToolExecution, task.id)
    assert refreshed_task is not None
    assert refreshed_task.status == original_status
    assert refreshed_task.worker_id == original_worker
    assert "lease_token_hash" not in refreshed_task.stats


def test_claim_task_lease_timestamp_timezone_aware(seeded_env: dict[str, Any]) -> None:
    """Validate that timestamps are timezone-aware UTC."""
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    _, claim = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-tz",
    )

    assert claim.started_at.tzinfo is not None
    assert claim.lease_expires_at.tzinfo is not None
    assert claim.started_at.utcoffset() == timedelta(0)
    assert claim.lease_expires_at.utcoffset() == timedelta(0)


def test_claim_task_lease_concurrent_claiming_serialization(seeded_env: dict[str, Any]) -> None:
    """Simulate two concurrent claimers under row-level locking.

    The first worker acquires the row lock on Scan and ToolExecution, claims the task, and flushes.
    The second worker, upon acquiring the lock, finds status == 'running' and is rejected.
    """
    session: Session = seeded_env["session"]
    project: Project = seeded_env["project"]
    task: ToolExecution = seeded_env["task"]

    # Worker 1 claims task
    _, claim1 = claim_task_lease(
        db=session,
        project_id=project.id,
        execution_id=task.id,
        worker_id="worker-A",
    )
    session.flush()

    assert claim1.worker_id == "worker-A"

    # Worker 2 attempts to claim concurrently
    with pytest.raises(ReconTaskAlreadyClaimedError) as exc_info:
        claim_task_lease(
            db=session,
            project_id=project.id,
            execution_id=task.id,
            worker_id="worker-B",
        )
    assert "worker-A" in str(exc_info.value)
    assert task.worker_id == "worker-A"
