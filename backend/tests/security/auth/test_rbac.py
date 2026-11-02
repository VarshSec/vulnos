"""Unit tests for RBAC roles, hierarchy, and project access verification."""

from collections.abc import Generator
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.auth.exceptions import PermissionDeniedError, ProjectAccessDeniedError
from backend.app.authorization.permissions import (
    ProjectRole,
    has_api_key_scope,
    has_sufficient_role,
)
from backend.app.authorization.project_access import verify_project_access
from backend.app.db.base import Base
from backend.app.db.models.identity import Project, ProjectMember, User


@pytest.fixture
def rbac_db() -> Generator[Session]:
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


def test_role_hierarchy() -> None:
    """Verify role hierarchy comparisons."""
    # Owner satisfies all roles
    assert has_sufficient_role(ProjectRole.OWNER, ProjectRole.VIEWER) is True
    assert has_sufficient_role(ProjectRole.OWNER, ProjectRole.OPERATOR) is True
    assert has_sufficient_role(ProjectRole.OWNER, ProjectRole.ADMIN) is True
    assert has_sufficient_role(ProjectRole.OWNER, ProjectRole.OWNER) is True

    # Admin satisfies admin, operator, viewer
    assert has_sufficient_role(ProjectRole.ADMIN, ProjectRole.VIEWER) is True
    assert has_sufficient_role(ProjectRole.ADMIN, ProjectRole.OPERATOR) is True
    assert has_sufficient_role(ProjectRole.ADMIN, ProjectRole.ADMIN) is True
    assert has_sufficient_role(ProjectRole.ADMIN, ProjectRole.OWNER) is False

    # Operator satisfies operator, viewer
    assert has_sufficient_role(ProjectRole.OPERATOR, ProjectRole.VIEWER) is True
    assert has_sufficient_role(ProjectRole.OPERATOR, ProjectRole.OPERATOR) is True
    assert has_sufficient_role(ProjectRole.OPERATOR, ProjectRole.ADMIN) is False

    # Viewer satisfies only viewer
    assert has_sufficient_role(ProjectRole.VIEWER, ProjectRole.VIEWER) is True
    assert has_sufficient_role(ProjectRole.VIEWER, ProjectRole.OPERATOR) is False


def test_api_key_scope_evaluation() -> None:
    """Verify API key scope checking."""
    # Specific scope match
    assert has_api_key_scope(["read", "scan"], "scan") is True
    assert has_api_key_scope(["read"], "scan") is False

    # Admin scope satisfies all scopes
    assert has_api_key_scope(["admin"], "scan") is True
    assert has_api_key_scope(["admin"], "validate") is True
    assert has_api_key_scope(["admin"], "report") is True


def test_verify_project_access_authorized(rbac_db: Session) -> None:
    """Verify access succeeds when user is a project member with matching or higher role."""
    owner = User(id=uuid4(), email="owner@example.com", display_name="Owner")
    operator = User(id=uuid4(), email="op@example.com", display_name="Operator")
    rbac_db.add_all([owner, operator])
    rbac_db.commit()

    proj = Project(id=uuid4(), name="Alpha", slug="alpha", owner_id=owner.id)
    rbac_db.add(proj)
    rbac_db.commit()

    member = ProjectMember(project_id=proj.id, user_id=operator.id, role="operator")
    rbac_db.add(member)
    rbac_db.commit()

    # Operator accessing as viewer: PASS
    m1 = verify_project_access(rbac_db, proj.id, operator.id, required_role="viewer")
    assert m1.role == "operator"

    # Operator accessing as operator: PASS
    m2 = verify_project_access(rbac_db, proj.id, operator.id, required_role="operator")
    assert m2.role == "operator"


def test_verify_project_access_insufficient_role(rbac_db: Session) -> None:
    """Verify member with lower role receives PermissionDeniedError (403)."""
    owner = User(id=uuid4(), email="owner2@example.com", display_name="Owner 2")
    viewer = User(id=uuid4(), email="viewer@example.com", display_name="Viewer")
    rbac_db.add_all([owner, viewer])
    rbac_db.commit()

    proj = Project(id=uuid4(), name="Beta", slug="beta", owner_id=owner.id)
    rbac_db.add(proj)
    rbac_db.commit()

    member = ProjectMember(project_id=proj.id, user_id=viewer.id, role="viewer")
    rbac_db.add(member)
    rbac_db.commit()

    # Viewer attempting operator action raises 403 / PermissionDeniedError
    with pytest.raises(PermissionDeniedError, match="Insufficient privileges"):
        verify_project_access(rbac_db, proj.id, viewer.id, required_role="operator")


def test_verify_project_access_non_member_not_found(rbac_db: Session) -> None:
    """Verify non-member receives ProjectAccessDeniedError (404) to prevent enumeration."""
    owner = User(id=uuid4(), email="owner3@example.com", display_name="Owner 3")
    stranger = User(id=uuid4(), email="stranger@example.com", display_name="Stranger")
    rbac_db.add_all([owner, stranger])
    rbac_db.commit()

    proj = Project(id=uuid4(), name="Gamma", slug="gamma", owner_id=owner.id)
    rbac_db.add(proj)
    rbac_db.commit()

    # Stranger querying project gamma raises 404 / ProjectAccessDeniedError
    with pytest.raises(ProjectAccessDeniedError, match="Project not found"):
        verify_project_access(rbac_db, proj.id, stranger.id, required_role="viewer")
