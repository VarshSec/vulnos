"""Unit tests for tenant context management and connection pool isolation."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.db.tenant import (
    InvalidTenantContextError,
    attach_tenant_pool_listeners,
    clear_tenant_context,
    get_current_tenant_context,
    get_tenant_db,
    set_tenant_context,
    tenant_context,
)


def test_set_and_clear_tenant_context_sqlite() -> None:
    """Test tenant context setting and clearing on SQLite / in-memory session."""
    engine = create_engine("sqlite:///:memory:")
    session = Session(bind=engine)

    proj_id = uuid4()
    usr_id = uuid4()
    req_id = "req-12345_test"

    ctx = set_tenant_context(session, project_id=proj_id, user_id=usr_id, request_id=req_id)
    assert ctx.project_id == proj_id
    assert ctx.user_id == usr_id
    assert ctx.request_id == req_id

    current = get_current_tenant_context(session)
    assert current is not None
    assert current.project_id == proj_id
    assert current.user_id == usr_id
    assert current.request_id == req_id

    clear_tenant_context(session)
    assert get_current_tenant_context(session) is None


def test_tenant_context_manager() -> None:
    """Test tenant_context context manager lifecycle and error resilience."""
    engine = create_engine("sqlite:///:memory:")
    session = Session(bind=engine)
    proj_id = uuid4()

    with tenant_context(session, project_id=proj_id) as ctx:
        assert ctx.project_id == proj_id
        assert get_current_tenant_context(session) is not None

    assert get_current_tenant_context(session) is None

    # Verify context cleans up even when an exception is raised
    with pytest.raises(RuntimeError), tenant_context(session, project_id=proj_id):
        raise RuntimeError("Database operation failed")

    assert get_current_tenant_context(session) is None


def test_uuid_validation() -> None:
    """Test validation of project and user UUIDs."""
    engine = create_engine("sqlite:///:memory:")
    session = Session(bind=engine)

    # Invalid project UUID format
    with pytest.raises(InvalidTenantContextError, match="Invalid UUID format for project_id"):
        set_tenant_context(session, project_id="not-a-valid-uuid")

    # Empty project UUID string
    with pytest.raises(InvalidTenantContextError, match="must be a valid non-empty UUID"):
        set_tenant_context(session, project_id="")

    # Invalid user UUID format
    with pytest.raises(InvalidTenantContextError, match="Invalid UUID format for user_id"):
        set_tenant_context(session, project_id=uuid4(), user_id="bad-user-id")


def test_request_id_validation() -> None:
    """Test validation and injection prevention in request_id."""
    engine = create_engine("sqlite:///:memory:")
    session = Session(bind=engine)
    proj_id = uuid4()

    # Valid request IDs
    ctx1 = set_tenant_context(session, project_id=proj_id, request_id="trace_123.456-ABC:78")
    assert ctx1.request_id == "trace_123.456-ABC:78"

    # SQL injection / special characters attempt
    with pytest.raises(InvalidTenantContextError, match="Invalid request_id format"):
        set_tenant_context(session, project_id=proj_id, request_id="'; DROP TABLE users; --")

    # Newlines / whitespace attempt
    with pytest.raises(InvalidTenantContextError, match="Invalid request_id format"):
        set_tenant_context(session, project_id=proj_id, request_id="req\nid\tspaces")


def test_postgresql_dialect_execution() -> None:
    """Test that PostgreSQL dialect triggers parameterized set_config statements."""
    mock_session = MagicMock(spec=Session)
    mock_bind = MagicMock()
    mock_bind.dialect.name = "postgresql"
    mock_session.get_bind.return_value = mock_bind
    mock_session.info = {}

    proj_id = uuid4()
    usr_id = uuid4()
    req_id = "req-postgre-test"

    set_tenant_context(mock_session, project_id=proj_id, user_id=usr_id, request_id=req_id)

    # Verify that session.execute was called with set_config
    assert mock_session.execute.call_count == 3
    executed_statements = [str(call[0][0]) for call in mock_session.execute.call_args_list]

    assert any("app.current_project_id" in stmt for stmt in executed_statements)
    assert any("app.current_user_id" in stmt for stmt in executed_statements)
    assert any("app.request_id" in stmt for stmt in executed_statements)

    # Test clear_tenant_context on PostgreSQL
    mock_session.reset_mock()
    clear_tenant_context(mock_session)
    assert mock_session.execute.call_count == 3


def test_attach_tenant_pool_listeners() -> None:
    """Test that connection pool listener attaches and executes on connection return."""
    test_engine = create_engine("sqlite:///:memory:")
    attach_tenant_pool_listeners(test_engine)

    # Checkout and checkin a connection to trigger the pool checkin listener
    conn = test_engine.connect()
    assert not conn.closed
    conn.close()
    test_engine.dispose()


def test_fastapi_tenant_db_dependency() -> None:
    """Test FastAPI get_tenant_db dependency lifecycle."""
    engine = create_engine("sqlite:///:memory:")
    session = Session(bind=engine)
    proj_id = uuid4()

    # Generator execution
    gen = get_tenant_db(project_id=proj_id, x_request_id="req-dep-1", db=session)
    yielded_session = next(gen)
    assert yielded_session is session
    assert session.info.get("tenant_context") is not None
    assert session.info["tenant_context"].project_id == proj_id

    # Finish generator (cleanup)
    with pytest.raises(StopIteration):
        next(gen)

    assert session.info.get("tenant_context") is None
