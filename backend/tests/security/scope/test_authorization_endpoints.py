"""Integration and security tests for VulnOS Authorization Endpoints (P2.5.4).

Validates:
- HTTP API contract conformance for /projects/{project_id}/authorizations endpoints.
- Role-based authorization enforcement (admin vs operator vs viewer vs non-member).
- Non-member 404 responses preventing project existence enumeration.
- Input validation, future date enforcement (422), and duplicate reference rejection (409).
- Cross-project authorization isolation over HTTP (404 on cross-tenant access).
- API key authentication and scope enforcement (admin scope required for creation/revocation).
- Idempotent revocation behavior.
- Immutability enforcement: PATCH, PUT, and DELETE methods are disallowed (405).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from datetime import timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.auth.api_keys import create_user_api_key
from backend.app.auth.sessions import SessionManager
from backend.app.auth.tokens import create_access_token
from backend.app.core.config import Settings
from backend.app.db.base import Base
from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import (
    APIKey,
    AuthorizationRecord,
    Project,
    ProjectMember,
    ScopeRule,
    ScopeVersion,
    Target,
    User,
)
from backend.app.db.session import get_db
from backend.app.db.types import utc_now, uuid7
from backend.app.main import create_app
from backend.tests.security.auth.test_sessions import FakeRedisClient


@pytest.fixture
def auth_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for authorization endpoint testing."""
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
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def auth_seed_data(
    auth_session_factory: sessionmaker[Session],
) -> dict[str, Any]:
    """Seed test database with users, projects, memberships, and API keys."""
    session = auth_session_factory()
    try:
        # 1. Users
        owner = User(
            id=uuid7(),
            email="owner@vulnos.test",
            display_name="Project Owner",
            password_hash="argon2id$test",
            is_active=True,
        )
        admin = User(
            id=uuid7(),
            email="admin@vulnos.test",
            display_name="Security Admin",
            password_hash="argon2id$test",
            is_active=True,
        )
        operator = User(
            id=uuid7(),
            email="operator@vulnos.test",
            display_name="Scan Operator",
            password_hash="argon2id$test",
            is_active=True,
        )
        viewer = User(
            id=uuid7(),
            email="viewer@vulnos.test",
            display_name="Read-only Auditor",
            password_hash="argon2id$test",
            is_active=True,
        )
        outsider = User(
            id=uuid7(),
            email="outsider@vulnos.test",
            display_name="Non-Member",
            password_hash="argon2id$test",
            is_active=True,
        )
        session.add_all([owner, admin, operator, viewer, outsider])
        session.flush()

        # 2. Projects
        proj_alpha = Project(
            id=uuid7(),
            name="Project Alpha",
            slug="proj-alpha",
            owner_id=owner.id,
            status="active",
        )
        proj_beta = Project(
            id=uuid7(),
            name="Project Beta",
            slug="proj-beta",
            owner_id=owner.id,
            status="active",
        )
        session.add_all([proj_alpha, proj_beta])
        session.flush()

        # 3. Memberships for Project Alpha
        m_owner = ProjectMember(project_id=proj_alpha.id, user_id=owner.id, role="owner")
        m_admin = ProjectMember(project_id=proj_alpha.id, user_id=admin.id, role="admin")
        m_operator = ProjectMember(project_id=proj_alpha.id, user_id=operator.id, role="operator")
        m_viewer = ProjectMember(project_id=proj_alpha.id, user_id=viewer.id, role="viewer")
        session.add_all([m_owner, m_admin, m_operator, m_viewer])
        session.flush()

        # 4. API Keys
        _admin_key_rec, admin_api_key = create_user_api_key(
            db=session,
            user_id=admin.id,
            name="Admin Key",
            scopes=["admin"],
        )
        _read_key_rec, read_api_key = create_user_api_key(
            db=session,
            user_id=viewer.id,
            name="Read Key",
            scopes=["read"],
        )

        proj_alpha_id = proj_alpha.id
        proj_beta_id = proj_beta.id
        owner_id = owner.id
        admin_id = admin.id
        operator_id = operator.id
        viewer_id = viewer.id
        outsider_id = outsider.id

        session.commit()

        return {
            "owner_id": owner_id,
            "admin_id": admin_id,
            "operator_id": operator_id,
            "viewer_id": viewer_id,
            "outsider_id": outsider_id,
            "proj_alpha_id": proj_alpha_id,
            "proj_beta_id": proj_beta_id,
            "owner_token": create_access_token(owner_id),
            "admin_token": create_access_token(admin_id),
            "operator_token": create_access_token(operator_id),
            "viewer_token": create_access_token(viewer_id),
            "outsider_token": create_access_token(outsider_id),
            "admin_api_key": admin_api_key,
            "read_api_key": read_api_key,
        }
    finally:
        session.close()


@pytest.fixture
async def auth_client(
    auth_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient]:
    """Test AsyncClient configured with fake redis and session factory."""
    fake_redis = FakeRedisClient()
    fake_session_mgr = SessionManager(client=fake_redis)

    import backend.app.api.v1.auth as auth_mod
    import backend.app.auth.dependencies as dep_mod
    import backend.app.auth.rate_limits as rl_mod

    monkeypatch.setattr(auth_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(dep_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(rl_mod, "get_redis_client", lambda: fake_redis)

    settings = Settings(
        APP_ENV="test",
        APP_DEBUG=False,
        SECRET_KEY="test-secret-key-for-unit-testing-32bytes",
        ALLOWED_HOSTS=["testserver", "localhost"],
        CORS_ORIGINS=["http://localhost:5173"],
    )
    app = create_app(settings=settings)

    def override_get_db() -> Generator[Session]:
        session = auth_session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    app.dependency_overrides.clear()


# -----------------------------------------------------------------------------
# POST /projects/{project_id}/authorizations Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_admin_creates_authorization_201(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Project admin can create an authorization record (201 Created)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["admin_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-2026-HTTP-001",
        "authorized_by_name": "Jane CISO",
        "authorized_by_contact": "jane@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=60)).isoformat(),
        "allowed_actions": ["scan", "validate", "agent_run"],
        "destructive_allowed": False,
        "allow_private_ranges": False,
        "max_requests_per_scan": 25000,
        "notes": "External assessment only",
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["reference"] == "ENG-2026-HTTP-001"
    assert data["project_id"] == str(proj_id)
    assert data["authorized_by_name"] == "Jane CISO"
    assert data["allowed_actions"] == ["agent_run", "scan", "validate"]  # Sorted deduplicated
    assert data["revoked_at"] is None


@pytest.mark.anyio
async def test_viewer_cannot_create_authorization_403(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Project viewer is forbidden from creating authorization records (403)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["viewer_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-FAIL-VIEWER",
        "authorized_by_name": "Alice",
        "authorized_by_contact": "alice@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_operator_cannot_create_authorization_403(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Project operator is forbidden from creating authorization records (403)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["operator_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-FAIL-OPERATOR",
        "authorized_by_name": "Bob",
        "authorized_by_contact": "bob@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_non_member_receives_404_on_create(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Non-member receives 404 Not Found to prevent project enumeration."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["outsider_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-FAIL-OUTSIDER",
        "authorized_by_name": "Charlie",
        "authorized_by_contact": "charlie@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_api_key_admin_scope_creates_authorization(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """API key with 'admin' scope succeeds in creating authorization (201)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    api_key = auth_seed_data["admin_api_key"]
    now = utc_now()

    payload = {
        "reference": "ENG-API-KEY-001",
        "authorized_by_name": "API Officer",
        "authorized_by_contact": "api@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 201
    assert resp.json()["reference"] == "ENG-API-KEY-001"


@pytest.mark.anyio
async def test_api_key_read_scope_rejected_on_create_403(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """API key with only 'read' scope is rejected with 403."""
    proj_id = auth_seed_data["proj_alpha_id"]
    api_key = auth_seed_data["read_api_key"]
    now = utc_now()

    payload = {
        "reference": "ENG-READ-KEY-FAIL",
        "authorized_by_name": "API Officer",
        "authorized_by_contact": "api@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_create_authorization_with_past_valid_to_rejected_422(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Creating an authorization with valid_to in the past is rejected with 422.

    Ref: API_CONTRACTS.md §8.5.
    """
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["admin_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-PAST-REJECTED",
        "authorized_by_name": "Past Officer",
        "authorized_by_contact": "past@corp.test",
        "valid_from": (now - timedelta(days=60)).isoformat(),
        "valid_to": (now - timedelta(days=30)).isoformat(),  # In the past!
        "allowed_actions": ["scan"],
    }

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_create_authorization_duplicate_reference_409(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Duplicate active authorization reference returns 409 Conflict."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["admin_token"]
    now = utc_now()

    payload = {
        "reference": "ENG-DUP-HTTP",
        "authorized_by_name": "Officer",
        "authorized_by_contact": "officer@corp.test",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=30)).isoformat(),
        "allowed_actions": ["scan"],
    }

    r1 = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 201

    r2 = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 409


# -----------------------------------------------------------------------------
# GET /projects/{project_id}/authorizations Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_viewer_can_list_authorizations_200(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Project viewer can list authorizations in project (200 OK)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token_admin = auth_seed_data["admin_token"]
    token_viewer = auth_seed_data["viewer_token"]
    now = utc_now()

    # Admin creates record
    await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json={
            "reference": "ENG-LIST-01",
            "authorized_by_name": "Lead",
            "authorized_by_contact": "lead@test.com",
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "allowed_actions": ["scan"],
        },
        headers={"Authorization": f"Bearer {token_admin}"},
    )

    # Viewer lists
    resp = await auth_client.get(
        f"/api/v1/projects/{proj_id}/authorizations",
        headers={"Authorization": f"Bearer {token_viewer}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["total"] >= 1
    assert any(i["reference"] == "ENG-LIST-01" for i in data["items"])


@pytest.mark.anyio
async def test_non_member_receives_404_on_list(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Non-member receives 404 on list request."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["outsider_token"]

    resp = await auth_client.get(
        f"/api/v1/projects/{proj_id}/authorizations",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# -----------------------------------------------------------------------------
# GET /projects/{project_id}/authorizations/{authorization_id} Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_viewer_can_get_single_authorization_200(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Viewer can retrieve single authorization record details (200 OK)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token_admin = auth_seed_data["admin_token"]
    token_viewer = auth_seed_data["viewer_token"]
    now = utc_now()

    create_resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json={
            "reference": "ENG-SINGLE-01",
            "authorized_by_name": "Lead",
            "authorized_by_contact": "lead@test.com",
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "allowed_actions": ["scan"],
        },
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    auth_id = create_resp.json()["id"]

    get_resp = await auth_client.get(
        f"/api/v1/projects/{proj_id}/authorizations/{auth_id}",
        headers={"Authorization": f"Bearer {token_viewer}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == auth_id
    assert get_resp.json()["reference"] == "ENG-SINGLE-01"


@pytest.mark.anyio
async def test_cross_project_get_authorization_404(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Accessing an authorization belonging to Project A under Project B returns 404."""
    proj_alpha_id = auth_seed_data["proj_alpha_id"]
    proj_beta_id = auth_seed_data["proj_beta_id"]
    token_admin = auth_seed_data["admin_token"]
    token_owner = auth_seed_data["owner_token"]
    now = utc_now()

    create_resp = await auth_client.post(
        f"/api/v1/projects/{proj_alpha_id}/authorizations",
        json={
            "reference": "ENG-CROSS-01",
            "authorized_by_name": "Lead",
            "authorized_by_contact": "lead@test.com",
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "allowed_actions": ["scan"],
        },
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    auth_id = create_resp.json()["id"]

    # Owner has access to beta, but record is in alpha -> 404
    resp = await auth_client.get(
        f"/api/v1/projects/{proj_beta_id}/authorizations/{auth_id}",
        headers={"Authorization": f"Bearer {token_owner}"},
    )
    assert resp.status_code == 404


# -----------------------------------------------------------------------------
# POST /projects/{project_id}/authorizations/{authorization_id}/revoke Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_admin_revokes_authorization_idempotent_200(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Admin can revoke authorization, and repeated revocation is idempotent (200 OK)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token_admin = auth_seed_data["admin_token"]
    now = utc_now()

    create_resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json={
            "reference": "ENG-REVOKE-HTTP",
            "authorized_by_name": "Lead",
            "authorized_by_contact": "lead@test.com",
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "allowed_actions": ["scan"],
        },
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    auth_id = create_resp.json()["id"]

    # 1. First revocation
    r1 = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations/{auth_id}/revoke",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert r1.status_code == 200
    revoked_at_1 = r1.json()["revoked_at"]
    assert revoked_at_1 is not None

    # 2. Repeated revocation (idempotent: returns 200 with identical revoked_at)
    r2 = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations/{auth_id}/revoke",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert r2.status_code == 200
    assert r2.json()["revoked_at"] == revoked_at_1


@pytest.mark.anyio
async def test_viewer_cannot_revoke_authorization_403(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Viewer is forbidden from revoking an authorization (403)."""
    proj_id = auth_seed_data["proj_alpha_id"]
    token_admin = auth_seed_data["admin_token"]
    token_viewer = auth_seed_data["viewer_token"]
    now = utc_now()

    create_resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations",
        json={
            "reference": "ENG-REVOKE-FAIL",
            "authorized_by_name": "Lead",
            "authorized_by_contact": "lead@test.com",
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "allowed_actions": ["scan"],
        },
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    auth_id = create_resp.json()["id"]

    resp = await auth_client.post(
        f"/api/v1/projects/{proj_id}/authorizations/{auth_id}/revoke",
        headers={"Authorization": f"Bearer {token_viewer}"},
    )
    assert resp.status_code == 403


# -----------------------------------------------------------------------------
# Immutability Tests (PATCH, PUT, DELETE Disallowed)
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_immutability_patch_put_delete_not_allowed(
    auth_client: AsyncClient,
    auth_seed_data: dict[str, Any],
) -> None:
    """Legal authorizations are strictly immutable.

    Verifies PATCH, PUT, and DELETE return 405 Method Not Allowed.
    """
    proj_id = auth_seed_data["proj_alpha_id"]
    token = auth_seed_data["admin_token"]
    dummy_auth_id = uuid7()

    patch_resp = await auth_client.patch(
        f"/api/v1/projects/{proj_id}/authorizations/{dummy_auth_id}",
        json={"notes": "Illegal modification"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_resp.status_code == 405

    put_resp = await auth_client.put(
        f"/api/v1/projects/{proj_id}/authorizations/{dummy_auth_id}",
        json={"notes": "Illegal replacement"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert put_resp.status_code == 405

    delete_resp = await auth_client.delete(
        f"/api/v1/projects/{proj_id}/authorizations/{dummy_auth_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert delete_resp.status_code == 405
