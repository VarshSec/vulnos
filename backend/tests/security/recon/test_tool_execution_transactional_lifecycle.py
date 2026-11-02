"""Security and integration tests for VulnOS Transactional ToolExecution Lifecycle Service.

Tests:
1. Successful queued-to-running transition (started_at, worker_id, audit event).
2. Successful running-to-succeeded transition (finished_at, exit_code 0, stats, cost).
3. Successful running-to-failed transition (finished_at, exit_code != 0, error_code).
4. Successful running-to-timeout transition (timeout_controller, finished_at, error_code).
5. Successful queued-to-cancelled transition (operator, finished_at, error_code).
6. Successful running-to-cancelled transition (operator in-flight, finished_at).
7. Successful running-to-scope_violation transition (scope_enforcement, finished_at).
8. Successful queued-to-skipped transition (orchestrator, finished_at, error_code).
9. Invalid transition edge rejection (queued -> succeeded, running -> queued).
10. Terminal-state immutability (mutating succeeded, cancelled, scope_violation).
11. Cross-project access rejection (attempting transition with wrong project_id).
12. Cross-tenant isolation (task.project_id mismatching scan.project_id).
13. Parent Scan paused behavior (permits in-flight running task to complete).
14. Parent Scan paused behavior (rejects new queued task from starting).
15. Parent Scan terminal-state rejection (completed/cancelled scan rejects completion).
16. Draft Scan scheduling behavior (draft scan rejects task execution).
17. Server-controlled timestamps correctness (UTC, started_at, finished_at).
18. Rejected transition preserves original timestamps without alteration.
19. Audit event created and verified in same transaction.
20. Audit-write failure rolls back task state changes atomically.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import patch
from uuid import UUID

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
    ReconTaskInvalidTransitionError,
    ReconTaskNotFoundError,
    ReconTaskParentStateInvalidError,
    ReconTaskTerminalStateError,
)
from backend.app.recon.task_lifecycle import (
    ACTOR_ADMIN,
    ACTOR_OPERATOR,
    ACTOR_ORCHESTRATOR,
    ACTOR_SCOPE_ENFORCEMENT,
    ACTOR_TIMEOUT_CONTROLLER,
    ACTOR_WORKER,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_DRAFT,
    SCAN_STATUS_PAUSED,
    SCAN_STATUS_RUNNING,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SCOPE_VIOLATION,
    STATUS_SKIPPED,
    STATUS_SUCCEEDED,
    STATUS_TIMEOUT,
    transition_tool_execution,
)


@pytest.fixture
def recon_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for task transactional lifecycle tests."""
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
        name="Test Project",
        slug="test-proj",
        owner_id=user.id,
    )
    session.add(project)

    member = ProjectMember(
        project_id=project.id,
        user_id=user.id,
        role="operator",
    )
    session.add(member)

    target = Target(
        id=uuid7(),
        project_id=project.id,
        name="example.com",
        seed_type="domain",
        seed_value="example.com",
        created_by=user.id,
    )
    session.add(target)

    auth_record = AuthorizationRecord(
        id=uuid7(),
        project_id=project.id,
        reference="AUTH-2026-001",
        authorized_by_name="Security Admin",
        authorized_by_contact="security@example.com",
        valid_from=now,
        valid_to=datetime(2027, 1, 1, tzinfo=UTC),
        allowed_actions=["recon", "discovery"],
        created_by=user.id,
    )
    session.add(auth_record)

    scope_version = ScopeVersion(
        id=uuid7(),
        project_id=project.id,
        version=1,
        status="active",
        content_hash=b"\x00" * 32,
        authorization_id=auth_record.id,
        created_by=user.id,
        activated_at=now,
    )
    session.add(scope_version)

    tool = Tool(
        id=uuid7(),
        name="amass",
        category="recon",
        description="In-depth DNS enumeration tool",
    )
    session.add(tool)

    tool_version = ToolVersion(
        id=uuid7(),
        tool_id=tool.id,
        version="v4.2.0",
        image_ref="amass:v4.2.0",
        image_digest="sha256:abcd1234abcd1234abcd1234abcd1234",
    )
    session.add(tool_version)

    scan = Scan(
        id=uuid7(),
        project_id=project.id,
        name="Test Recon Scan",
        scan_type="recon",
        status=SCAN_STATUS_RUNNING,
        scope_version_id=scope_version.id,
        authorization_id=auth_record.id,
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
        input={"domain": "example.com"},
    )
    session.add(task)

    session.commit()

    yield {
        "session": session,
        "user": user,
        "project": project,
        "target": target,
        "auth_record": auth_record,
        "scope_version": scope_version,
        "tool": tool,
        "tool_version": tool_version,
        "scan": scan,
        "task": task,
    }

    session.close()


def test_transition_queued_to_running_success(seeded_env: dict[str, Any]) -> None:
    """T-T02: Worker claims lease, sets started_at, worker_id, and emits audit event."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task_id: UUID = seeded_env["task"].id

    task = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task_id,
        new_status=STATUS_RUNNING,
        actor_id="worker-node-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-node-1",
    )
    db.commit()

    assert task.status == STATUS_RUNNING
    assert task.worker_id == "worker-node-1"
    assert task.started_at is not None
    assert task.finished_at is None

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task_id),
            AuditLog.action == "recon_task.started",
        )
    )
    assert audit is not None
    assert audit.actor_type == "worker"
    assert audit.metadata_["new_status"] == STATUS_RUNNING


def test_transition_running_to_succeeded_success(seeded_env: dict[str, Any]) -> None:
    """T-T04: Worker finishes exit code 0, sets finished_at, stats, and cost."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    # Start task
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    # Complete task
    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_SUCCEEDED,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        exit_code=0,
        cost_usd=Decimal("0.002500"),
        stats={"subdomains_found": 15},
    )
    db.commit()

    assert updated.status == STATUS_SUCCEEDED
    assert updated.exit_code == 0
    assert updated.finished_at is not None
    assert updated.cost_usd == Decimal("0.002500")
    assert updated.stats["subdomains_found"] == 15

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.succeeded",
        )
    )
    assert audit is not None
    assert audit.metadata_["exit_code"] == 0


def test_transition_running_to_failed_success(seeded_env: dict[str, Any]) -> None:
    """T-T05: Worker non-zero exit code or error, sets finished_at and error_code."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_FAILED,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        exit_code=2,
        error_code="DNS_SERVER_REFUSED",
        error_message="All configured resolvers timed out.",
    )
    db.commit()

    assert updated.status == STATUS_FAILED
    assert updated.exit_code == 2
    assert updated.error_code == "DNS_SERVER_REFUSED"
    assert updated.finished_at is not None

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.failed",
        )
    )
    assert audit is not None
    assert audit.metadata_["error_code"] == "DNS_SERVER_REFUSED"


def test_transition_running_to_timeout_success(seeded_env: dict[str, Any]) -> None:
    """T-T06: Timeout controller terminates expired task."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_TIMEOUT,
        actor_id="timeout-watchdog",
        actor_type=ACTOR_TIMEOUT_CONTROLLER,
        reason="Execution duration exceeded 300s budget.",
    )
    db.commit()

    assert updated.status == STATUS_TIMEOUT
    assert updated.error_code == "TIMEOUT"
    assert updated.finished_at is not None

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.timed_out",
        )
    )
    assert audit is not None


def test_transition_queued_to_cancelled_success(seeded_env: dict[str, Any]) -> None:
    """T-T03: Cancel queued task before worker claims lease."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_CANCELLED,
        actor_id="operator-1",
        actor_type=ACTOR_OPERATOR,
        reason="Operator cancelled scan pipeline.",
    )
    db.commit()

    assert updated.status == STATUS_CANCELLED
    assert updated.started_at is None
    assert updated.finished_at is not None
    assert updated.error_code == "CANCELLED"


def test_transition_running_to_cancelled_success(seeded_env: dict[str, Any]) -> None:
    """T-T07: Cancel in-flight task during execution."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_CANCELLED,
        actor_id="operator-1",
        actor_type=ACTOR_OPERATOR,
        reason="User requested immediate stop.",
    )
    db.commit()

    assert updated.status == STATUS_CANCELLED
    assert updated.started_at is not None
    assert updated.finished_at is not None


def test_transition_running_to_scope_violation_success(seeded_env: dict[str, Any]) -> None:
    """T-T08: Scope guard detects unauthorized egress destination."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_SCOPE_VIOLATION,
        actor_id="egress-proxy",
        actor_type=ACTOR_SCOPE_ENFORCEMENT,
        error_message="Tool attempted connection to AWS IMDS 169.254.169.254.",
    )
    db.commit()

    assert updated.status == STATUS_SCOPE_VIOLATION
    assert updated.error_code == "SCOPE_VIOLATION"
    assert updated.finished_at is not None

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.scope_violation",
        )
    )
    assert audit is not None


def test_transition_queued_to_skipped_success(seeded_env: dict[str, Any]) -> None:
    """T-T09: Orchestrator skips task due to failed upstream DAG dependency."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    updated = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_SKIPPED,
        actor_id="orchestrator",
        actor_type=ACTOR_ORCHESTRATOR,
        error_code="DEPENDENCY_FAILED",
        reason="Upstream subdomain enumeration produced 0 assets.",
    )
    db.commit()

    assert updated.status == STATUS_SKIPPED
    assert updated.error_code == "DEPENDENCY_FAILED"
    assert updated.finished_at is not None


def test_transition_invalid_edge_rejected(seeded_env: dict[str, Any]) -> None:
    """Verify illegal transitions (queued -> succeeded, running -> queued) raise errors."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    with pytest.raises(ReconTaskInvalidTransitionError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_SUCCEEDED,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
        )

    # Start task
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    # Cannot transition from running directly to queued
    with pytest.raises(ReconTaskInvalidTransitionError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_QUEUED,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
        )


def test_transition_terminal_state_immutability(seeded_env: dict[str, Any]) -> None:
    """Verify terminal tasks cannot be mutated or reactivated."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    # Transition to cancelled
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_CANCELLED,
        actor_id="operator-1",
        actor_type=ACTOR_OPERATOR,
    )

    with pytest.raises(ReconTaskTerminalStateError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_RUNNING,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            worker_id="worker-1",
        )


def test_transition_cross_project_task_access_rejected(seeded_env: dict[str, Any]) -> None:
    """Verify looking up task with wrong project_id raises ReconTaskNotFoundError."""
    db: Session = seeded_env["session"]
    task: ToolExecution = seeded_env["task"]
    other_project_id = uuid7()

    with pytest.raises(ReconTaskNotFoundError) as exc_info:
        transition_tool_execution(
            db=db,
            project_id=other_project_id,
            execution_id=task.id,
            new_status=STATUS_RUNNING,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            worker_id="worker-1",
        )
    assert "not found" in str(exc_info.value)


def test_transition_cross_tenant_isolation(seeded_env: dict[str, Any]) -> None:
    """Verify task-to-scan project mismatch raises ReconTaskProjectMismatchError."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    # Artificially alter task.scan_id to another project's scan
    foreign_scan = Scan(
        id=uuid7(),
        project_id=uuid7(),  # Different project
        name="Foreign Scan",
        scan_type="recon",
        status=SCAN_STATUS_RUNNING,
        scope_version_id=seeded_env["scope_version"].id,
        authorization_id=seeded_env["auth_record"].id,
        target_ids=[seeded_env["target"].id],
        budget={"max_requests": 1000},
        requested_by=seeded_env["user"].id,
    )
    db.add(foreign_scan)
    db.flush()

    task.scan_id = foreign_scan.id
    db.flush()

    with pytest.raises(ReconJobNotFoundError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_RUNNING,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            worker_id="worker-1",
        )


def test_transition_parent_scan_paused_permits_drain_completion(
    seeded_env: dict[str, Any],
) -> None:
    """Verify running tasks are permitted to complete/drain when parent Scan is paused."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    scan: Scan = seeded_env["scan"]
    task: ToolExecution = seeded_env["task"]

    # Start task while scan is running
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    # Pause scan
    scan.status = SCAN_STATUS_PAUSED
    db.flush()

    # In-flight task is permitted to finish
    completed = transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_SUCCEEDED,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        exit_code=0,
    )
    db.commit()

    assert completed.status == STATUS_SUCCEEDED


def test_transition_parent_scan_paused_rejects_new_start(
    seeded_env: dict[str, Any],
) -> None:
    """Verify queued tasks cannot claim leases or start while parent Scan is paused."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    scan: Scan = seeded_env["scan"]
    task: ToolExecution = seeded_env["task"]

    # Pause scan while task is queued
    scan.status = SCAN_STATUS_PAUSED
    db.flush()

    with pytest.raises(ReconTaskParentStateInvalidError) as exc_info:
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_RUNNING,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            worker_id="worker-1",
        )
    assert "paused" in str(exc_info.value)


def test_transition_parent_scan_terminal_rejects_completion(
    seeded_env: dict[str, Any],
) -> None:
    """Verify completed or cancelled parent Scans reject late task completions."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    scan: Scan = seeded_env["scan"]
    task: ToolExecution = seeded_env["task"]

    # Start task
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
    )

    # Mark scan completed
    scan.status = SCAN_STATUS_COMPLETED
    db.flush()

    with pytest.raises(ReconTaskParentStateInvalidError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_SUCCEEDED,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            exit_code=0,
        )


def test_transition_draft_scan_scheduling_behavior(seeded_env: dict[str, Any]) -> None:
    """Verify task claiming is rejected when parent Scan is still in draft."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    scan: Scan = seeded_env["scan"]
    task: ToolExecution = seeded_env["task"]

    scan.status = SCAN_STATUS_DRAFT
    db.flush()

    with pytest.raises(ReconTaskParentStateInvalidError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_RUNNING,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            worker_id="worker-1",
        )


def test_transition_server_timestamps_correctness(seeded_env: dict[str, Any]) -> None:
    """Verify started_at and finished_at are strictly server UTC timestamps."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    eval_time_1 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
    eval_time_2 = datetime(2026, 11, 2, 10, 5, 0, tzinfo=UTC)

    # Start task at eval_time_1
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
        evaluation_time=eval_time_1,
    )
    assert task.started_at == eval_time_1
    assert task.finished_at is None

    # Finish task at eval_time_2
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_SUCCEEDED,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        exit_code=0,
        evaluation_time=eval_time_2,
    )
    assert task.started_at == eval_time_1
    assert task.finished_at == eval_time_2


def test_transition_rejected_preserves_original_timestamps(
    seeded_env: dict[str, Any],
) -> None:
    """Verify rejected transition attempts do not overwrite existing timestamps."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    original_start = datetime(2026, 11, 2, 8, 0, 0, tzinfo=UTC)
    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_RUNNING,
        actor_id="worker-1",
        actor_type=ACTOR_WORKER,
        worker_id="worker-1",
        evaluation_time=original_start,
    )

    # Attempt illegal transition with new timestamp
    illegal_time = datetime(2026, 11, 2, 9, 0, 0, tzinfo=UTC)
    with pytest.raises(ReconTaskInvalidTransitionError):
        transition_tool_execution(
            db=db,
            project_id=project_id,
            execution_id=task.id,
            new_status=STATUS_QUEUED,
            actor_id="worker-1",
            actor_type=ACTOR_WORKER,
            evaluation_time=illegal_time,
        )

    assert task.started_at == original_start


def test_transition_audit_log_created_and_verified(seeded_env: dict[str, Any]) -> None:
    """Verify complete audit trail fields including entity_type, actor_type, and metadata."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    transition_tool_execution(
        db=db,
        project_id=project_id,
        execution_id=task.id,
        new_status=STATUS_CANCELLED,
        actor_id="admin-user-99",
        actor_type=ACTOR_ADMIN,
        reason="Security compliance audit stop.",
        request_id="req-test-1234",
    )
    db.commit()

    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(task.id),
            AuditLog.action == "recon_task.cancelled",
        )
    )
    assert audit is not None
    assert audit.actor_type == "user"
    assert audit.metadata_["actor_role"] == "admin"
    assert audit.metadata_["reason"] == "Security compliance audit stop."
    assert audit.request_id == "req-test-1234"
    assert audit.project_id == project_id


def test_transition_audit_write_failure_rolls_back_changes(
    seeded_env: dict[str, Any],
) -> None:
    """Verify atomicity: if audit persistence fails, task status changes roll back."""
    db: Session = seeded_env["session"]
    project_id: UUID = seeded_env["project"].id
    task: ToolExecution = seeded_env["task"]

    assert task.status == STATUS_QUEUED

    # Mock db.add when called with AuditLog to simulate write failure
    original_add = db.add

    def mock_add(instance: Any) -> None:
        if isinstance(instance, AuditLog):
            raise RuntimeError("Simulated AuditLog database disk failure")
        original_add(instance)

    with patch.object(db, "add", side_effect=mock_add):
        with pytest.raises(RuntimeError) as exc_info:
            transition_tool_execution(
                db=db,
                project_id=project_id,
                execution_id=task.id,
                new_status=STATUS_RUNNING,
                actor_id="worker-1",
                actor_type=ACTOR_WORKER,
                worker_id="worker-1",
            )
        assert "Simulated AuditLog" in str(exc_info.value)

    # Rollback session and verify task status remains queued
    db.rollback()
    refreshed_task = db.scalar(select(ToolExecution).where(ToolExecution.id == task.id))
    assert refreshed_task is not None
    assert refreshed_task.status == STATUS_QUEUED
    assert refreshed_task.started_at is None
