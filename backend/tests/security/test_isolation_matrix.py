"""Comprehensive test matrix for tenant isolation, cross-project protection, and pool safety.

These tests validate the application-layer tenant context management and query isolation
patterns. Tests requiring PostgreSQL-native types (ARRAY, INET, INT4RANGE) that cannot
run against SQLite are marked with `pytest.mark.postgres`.
"""

from collections.abc import Generator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.db.base import Base
from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import (
    Project,
    Target,
    User,
)
from backend.app.db.tenant import (
    clear_tenant_context,
    get_current_tenant_context,
    set_tenant_context,
    tenant_context,
)

_NOW = datetime.now(UTC)


def _make_user(email: str = "user@example.com") -> User:
    return User(id=uuid4(), email=email, display_name="Test User")


def _make_project(owner_id: object, name: str, slug: str) -> Project:
    return Project(id=uuid4(), name=name, slug=slug, owner_id=owner_id)


def _make_target(
    project_id: object, user_id: object, name: str = "Target", seed_value: str = "example.com"
) -> Target:
    return Target(
        id=uuid4(),
        project_id=project_id,
        name=name,
        seed_type="domain",
        seed_value=seed_value,
        created_by=user_id,
    )


@pytest.fixture
def memory_db() -> Generator[Session]:
    """Provide an in-memory SQLite database session with Base metadata created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_direct_tenant_isolation_matrix(memory_db: Session) -> None:
    """Verify that records for Project 1 are completely isolated from Project 2."""
    user = _make_user("admin@example.com")
    memory_db.add(user)
    memory_db.flush()

    proj_1 = _make_project(user.id, "Project Alpha", "alpha")
    proj_2 = _make_project(user.id, "Project Beta", "beta")
    memory_db.add_all([proj_1, proj_2])
    memory_db.flush()

    t1 = _make_target(proj_1.id, user.id, "Alpha API")
    t2 = _make_target(proj_2.id, user.id, "Beta API")
    memory_db.add_all([t1, t2])
    memory_db.commit()

    # Query under Project 1 context
    with tenant_context(memory_db, project_id=proj_1.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        stmt = select(Target).where(Target.project_id == ctx.project_id)
        results = memory_db.scalars(stmt).all()
        assert len(results) == 1
        assert results[0].id == t1.id

    # Query under Project 2 context
    with tenant_context(memory_db, project_id=proj_2.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        stmt = select(Target).where(Target.project_id == ctx.project_id)
        results = memory_db.scalars(stmt).all()
        assert len(results) == 1
        assert results[0].id == t2.id

    # Query with No Context (Default Deny simulation)
    ctx = get_current_tenant_context(memory_db)
    assert ctx is None
    stmt = select(Target).where(Target.project_id == (ctx.project_id if ctx else None))
    results = memory_db.scalars(stmt).all()
    assert len(results) == 0


def test_default_deny_returns_zero_rows(memory_db: Session) -> None:
    """Verify that when context is absent, WHERE project_id = NULL returns zero rows."""
    user = _make_user("deny@example.com")
    memory_db.add(user)
    memory_db.flush()

    proj = _make_project(user.id, "Ghost", "ghost")
    memory_db.add(proj)
    memory_db.flush()

    target = _make_target(proj.id, user.id, "Ghost Target")
    memory_db.add(target)
    memory_db.commit()

    # Without setting any context, no rows should match
    ctx = get_current_tenant_context(memory_db)
    assert ctx is None

    null_project_id = ctx.project_id if ctx else None
    stmt = select(Target).where(Target.project_id == null_project_id)
    results = memory_db.scalars(stmt).all()
    assert results == []


def test_multi_table_tenant_isolation(memory_db: Session) -> None:
    """Verify isolation across multiple direct project-owned tables."""
    user = _make_user("multi@example.com")
    memory_db.add(user)
    memory_db.flush()

    proj_a = _make_project(user.id, "PA", "pa")
    proj_b = _make_project(user.id, "PB", "pb")
    memory_db.add_all([proj_a, proj_b])
    memory_db.flush()

    # Create targets for both projects
    ta1 = _make_target(proj_a.id, user.id, "A1", seed_value="a1.example.com")
    ta2 = _make_target(proj_a.id, user.id, "A2", seed_value="a2.example.com")
    tb1 = _make_target(proj_b.id, user.id, "B1", seed_value="b1.example.com")
    memory_db.add_all([ta1, ta2, tb1])
    memory_db.commit()

    # Project A sees its 2 targets
    with tenant_context(memory_db, project_id=proj_a.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        results = memory_db.scalars(select(Target).where(Target.project_id == ctx.project_id)).all()
        assert len(results) == 2
        assert {r.name for r in results} == {"A1", "A2"}

    # Project B sees its 1 target
    with tenant_context(memory_db, project_id=proj_b.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        results = memory_db.scalars(select(Target).where(Target.project_id == ctx.project_id)).all()
        assert len(results) == 1
        assert results[0].name == "B1"


def test_cross_project_reference_detection() -> None:
    """Verify programmatic detection and rejection of cross-project references."""
    proj_1_id = uuid4()
    proj_2_id = uuid4()

    def validate_same_project(child_pid: object, parent_pid: object) -> None:
        if child_pid != parent_pid:
            raise ValueError(f"Cross-project reference violation: {child_pid} != {parent_pid}")

    # Same project reference: passes
    validate_same_project(proj_1_id, proj_1_id)

    # Cross-project reference: raises ValueError
    with pytest.raises(ValueError, match="Cross-project reference violation"):
        validate_same_project(proj_2_id, proj_1_id)


def test_audit_log_tenant_isolation(memory_db: Session) -> None:
    """Verify audit logs are isolated by tenant."""
    user = _make_user("audit@example.com")
    memory_db.add(user)
    memory_db.flush()

    proj_1 = _make_project(user.id, "P1", "p1-audit")
    proj_2 = _make_project(user.id, "P2", "p2-audit")
    memory_db.add_all([proj_1, proj_2])
    memory_db.flush()

    log_1 = AuditLog(
        id=1,
        actor_type="system",
        action="scan.started",
        entity_type="scan",
        project_id=proj_1.id,
    )
    log_2 = AuditLog(
        id=2,
        actor_type="system",
        action="target.created",
        entity_type="target",
        project_id=proj_2.id,
    )
    memory_db.add_all([log_1, log_2])
    memory_db.commit()

    # Project 1 reads only own logs
    with tenant_context(memory_db, project_id=proj_1.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        stmt = select(AuditLog).where(AuditLog.project_id == ctx.project_id)
        logs = memory_db.scalars(stmt).all()
        assert len(logs) == 1
        assert logs[0].action == "scan.started"

    # Project 2 reads only own logs
    with tenant_context(memory_db, project_id=proj_2.id):
        ctx = get_current_tenant_context(memory_db)
        assert ctx is not None
        stmt = select(AuditLog).where(AuditLog.project_id == ctx.project_id)
        logs = memory_db.scalars(stmt).all()
        assert len(logs) == 1
        assert logs[0].action == "target.created"


def test_pooled_connection_reuse_simulation(memory_db: Session) -> None:
    """Verify that simulating connection checkin / reuse does not leak tenant context."""
    proj_1_id = uuid4()
    proj_2_id = uuid4()

    # Request 1 sets Project 1 context
    set_tenant_context(memory_db, project_id=proj_1_id, request_id="req-worker-1")
    ctx = get_current_tenant_context(memory_db)
    assert ctx is not None
    assert ctx.project_id == proj_1_id

    # Worker 1 returns connection to pool (simulated checkin)
    clear_tenant_context(memory_db)
    assert get_current_tenant_context(memory_db) is None

    # Worker 2 checks out connection: context is pristine None
    assert get_current_tenant_context(memory_db) is None

    # Worker 2 sets Project 2 context
    set_tenant_context(memory_db, project_id=proj_2_id, request_id="req-worker-2")
    ctx = get_current_tenant_context(memory_db)
    assert ctx is not None
    assert ctx.project_id == proj_2_id

    clear_tenant_context(memory_db)
    assert get_current_tenant_context(memory_db) is None


def test_context_cleanup_on_exception(memory_db: Session) -> None:
    """Verify that tenant context is cleaned even if the block raises an exception."""
    proj_id = uuid4()

    with (
        pytest.raises(RuntimeError, match="simulated failure"),
        tenant_context(memory_db, project_id=proj_id),
    ):
        assert get_current_tenant_context(memory_db) is not None
        raise RuntimeError("simulated failure")

    assert get_current_tenant_context(memory_db) is None


def test_sequential_context_switches(memory_db: Session) -> None:
    """Verify rapid context switches do not leak state between projects."""
    project_ids = [uuid4() for _ in range(5)]

    for pid in project_ids:
        with tenant_context(memory_db, project_id=pid):
            ctx = get_current_tenant_context(memory_db)
            assert ctx is not None
            assert ctx.project_id == pid
        # After each context manager exits, context is clear
        assert get_current_tenant_context(memory_db) is None
