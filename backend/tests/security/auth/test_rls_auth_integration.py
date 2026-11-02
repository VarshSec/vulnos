"""Integration tests verifying authentication, project authorization,
and P2.3 RLS context binding.
"""

from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import (
    AuthenticatedPrincipal,
    require_project_context,
)
from backend.app.db.base import Base
from backend.app.db.models.identity import Project, ProjectMember, User
from backend.app.db.tenant import get_current_tenant_context


@pytest.fixture
def integration_db() -> Generator[Session]:
    """In-memory SQLite session with users, projects, and project_members tables."""
    engine = create_engine("sqlite:///:memory:")
    tables = [User.__table__, Project.__table__, ProjectMember.__table__]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_authorized_member_establishes_rls_context(integration_db: Session) -> None:
    """Verify that an authorized member establishes correct transaction-local tenant context."""
    owner = User(id=uuid4(), email="owner@example.com", display_name="Owner")
    operator = User(id=uuid4(), email="op@example.com", display_name="Operator")
    integration_db.add_all([owner, operator])
    integration_db.commit()

    proj = Project(id=uuid4(), name="RLS Proj", slug="rls-proj", owner_id=owner.id)
    integration_db.add(proj)
    integration_db.commit()

    member = ProjectMember(project_id=proj.id, user_id=operator.id, role="operator")
    integration_db.add(member)
    integration_db.commit()

    principal = AuthenticatedPrincipal(user=operator)
    dep_factory = require_project_context(required_role="operator")
    dep_gen = dep_factory(
        project_id=proj.id,
        x_request_id="req-auth-test-1",
        principal=principal,
        db=integration_db,
    )

    # Context is None before generator begins
    assert get_current_tenant_context(integration_db) is None

    # Step into generator (simulating endpoint execution)
    session_out, member_out = next(dep_gen)
    assert session_out is integration_db
    assert member_out.role == "operator"

    # Context MUST be established and equal to proj.id
    active_ctx = get_current_tenant_context(integration_db)
    assert active_ctx is not None
    assert active_ctx.project_id == proj.id
    assert active_ctx.user_id == operator.id
    assert active_ctx.request_id == "req-auth-test-1"

    # Complete generator (simulating request teardown)
    with pytest.raises(StopIteration):
        next(dep_gen)

    # Context MUST be pristine None after teardown
    assert get_current_tenant_context(integration_db) is None


def test_unauthorized_member_never_establishes_rls_context(integration_db: Session) -> None:
    """Verify that a non-member request fails with 404 and NEVER establishes tenant context."""
    owner = User(id=uuid4(), email="owner4@example.com", display_name="Owner 4")
    stranger = User(id=uuid4(), email="stranger4@example.com", display_name="Stranger 4")
    integration_db.add_all([owner, stranger])
    integration_db.commit()

    proj = Project(id=uuid4(), name="Secure Proj", slug="sec-proj", owner_id=owner.id)
    integration_db.add(proj)
    integration_db.commit()

    principal = AuthenticatedPrincipal(user=stranger)
    dep_factory = require_project_context(required_role="viewer")
    dep_gen = dep_factory(
        project_id=proj.id,
        x_request_id="req-attack-1",
        principal=principal,
        db=integration_db,
    )

    # Executing the dependency raises HTTPException 404
    with pytest.raises(HTTPException) as exc_info:
        next(dep_gen)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Project not found"

    # Tenant context MUST remain None (Never contaminated or established!)
    assert get_current_tenant_context(integration_db) is None


def test_insufficient_role_never_establishes_rls_context(integration_db: Session) -> None:
    """Verify that a member lacking required role fails with 403 and never establishes context."""
    owner = User(id=uuid4(), email="owner5@example.com", display_name="Owner 5")
    viewer = User(id=uuid4(), email="viewer5@example.com", display_name="Viewer 5")
    integration_db.add_all([owner, viewer])
    integration_db.commit()

    proj = Project(id=uuid4(), name="Escalate Proj", slug="esc-proj", owner_id=owner.id)
    integration_db.add(proj)
    integration_db.commit()

    member = ProjectMember(project_id=proj.id, user_id=viewer.id, role="viewer")
    integration_db.add(member)
    integration_db.commit()

    principal = AuthenticatedPrincipal(user=viewer)
    # Action requires 'admin', but user is only 'viewer'
    dep_factory = require_project_context(required_role="admin")
    dep_gen = dep_factory(
        project_id=proj.id,
        x_request_id="req-esc-1",
        principal=principal,
        db=integration_db,
    )

    with pytest.raises(HTTPException) as exc_info:
        next(dep_gen)

    assert exc_info.value.status_code == 403
    assert "Insufficient privileges" in exc_info.value.detail

    # Context MUST remain None
    assert get_current_tenant_context(integration_db) is None
