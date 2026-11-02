"""Integration and security tests for VulnOS Target Management Endpoints (P2.5.3).

Validates:
- HTTP API contract conformance for /projects/{project_id}/targets endpoints.
- Role-based authorization enforcement (admin vs viewer vs non-member).
- Non-member 404 responses preventing project existence enumeration.
- Input validation and deterministic normalization error mapping (400 / 409).
- Cross-project target isolation over HTTP.
- API key authentication and scope enforcement.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
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
    Project,
    ProjectMember,
    Target,
    User,
)
from backend.app.db.session import get_db
from backend.app.db.types import uuid7
from backend.app.main import create_app
from backend.tests.security.auth.test_sessions import FakeRedisClient


@pytest.fixture
def target_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for target endpoint testing."""
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
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def target_seed_data(
    target_session_factory: sessionmaker[Session],
) -> dict[str, Any]:
    """Seed test database with users, projects, and memberships."""
    session = target_session_factory()
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
        session.add_all([owner, admin, viewer, outsider])
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

        # 3. Memberships
        m_owner = ProjectMember(project_id=proj_alpha.id, user_id=owner.id, role="owner")
        m_admin = ProjectMember(project_id=proj_alpha.id, user_id=admin.id, role="admin")
        m_viewer = ProjectMember(project_id=proj_alpha.id, user_id=viewer.id, role="viewer")
        session.add_all([m_owner, m_admin, m_viewer])
        session.flush()

        # 4. API Keys for admin
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
        viewer_id = viewer.id
        outsider_id = outsider.id

        session.commit()

        return {
            "owner_id": owner_id,
            "admin_id": admin_id,
            "viewer_id": viewer_id,
            "outsider_id": outsider_id,
            "proj_alpha_id": proj_alpha_id,
            "proj_beta_id": proj_beta_id,
            "owner_token": create_access_token(owner_id),
            "admin_token": create_access_token(admin_id),
            "viewer_token": create_access_token(viewer_id),
            "outsider_token": create_access_token(outsider_id),
            "admin_api_key": admin_api_key,
            "read_api_key": read_api_key,
        }
    finally:
        session.close()


@pytest.fixture
async def target_client(
    target_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient]:
    """Test AsyncClient configured with mock redis and test db session."""
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
        session = target_session_factory()
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
# POST /projects/{project_id}/targets Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_creates_target_success_and_normalization(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Admin successfully creates a target; response contains normalized value."""
    proj_id = target_seed_data["proj_alpha_id"]
    headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    payload = {
        "name": "Production API Gateway",
        "seed_type": "url",
        "seed_value": "HTTPS://API.EXAMPLE.COM:443/api/./v1/?b=2&a=1#frag",
        "description": "Main API endpoint",
    }
    res = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload, headers=headers
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Production API Gateway"
    assert data["seed_type"] == "url"
    assert data["seed_value"] == "https://api.example.com/api/v1/?a=1&b=2"
    assert data["status"] == "active"
    assert data["project_id"] == str(proj_id)


@pytest.mark.asyncio
async def test_viewer_cannot_create_target(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Viewer receives 403 Forbidden when attempting to create a target."""
    proj_id = target_seed_data["proj_alpha_id"]
    headers = {"Authorization": f"Bearer {target_seed_data['viewer_token']}"}
    payload = {
        "name": "Viewer Target",
        "seed_type": "domain",
        "seed_value": "viewer.example.com",
    }
    res = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload, headers=headers
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_non_member_receives_404_on_target_creation(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Non-member receives 404 to prevent project existence enumeration."""
    proj_id = target_seed_data["proj_alpha_id"]
    headers = {"Authorization": f"Bearer {target_seed_data['outsider_token']}"}
    payload = {
        "name": "Outsider Target",
        "seed_type": "domain",
        "seed_value": "outsider.example.com",
    }
    res = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload, headers=headers
    )
    assert res.status_code == 404
    body = res.json()
    assert body["error"]["message"] == "Project not found"
    assert body["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_unauthenticated_receives_401_on_target_creation(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Unauthenticated request receives 401 Unauthorized."""
    proj_id = target_seed_data["proj_alpha_id"]
    payload = {
        "name": "Unauth Target",
        "seed_type": "domain",
        "seed_value": "unauth.example.com",
    }
    res = await target_client.post(f"/api/v1/projects/{proj_id}/targets", json=payload)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_create_target_invalid_syntax_returns_400(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Target value with invalid syntax or disallowed characters returns 400."""
    proj_id = target_seed_data["proj_alpha_id"]
    headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    payload = {
        "name": "Bad Target",
        "seed_type": "domain",
        "seed_value": "-invalid.-domain.com",
    }
    res = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload, headers=headers
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_create_duplicate_target_returns_409(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Duplicate normalized target seed in project returns 409 Conflict."""
    proj_id = target_seed_data["proj_alpha_id"]
    headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    payload1 = {
        "name": "Seed Target",
        "seed_type": "domain",
        "seed_value": "duplicate.example.com",
    }
    res1 = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload1, headers=headers
    )
    assert res1.status_code == 201

    payload2 = {
        "name": "Duplicate Attempt",
        "seed_type": "domain",
        "seed_value": "DUPLICATE.EXAMPLE.COM.",  # Normalizes identically
    }
    res2 = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets", json=payload2, headers=headers
    )
    assert res2.status_code == 409


# -----------------------------------------------------------------------------
# GET /projects/{project_id}/targets (List & Get) Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_lists_targets_and_isolation(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Viewer can list targets; targets in other projects are never leaked."""
    proj_a_id = target_seed_data["proj_alpha_id"]
    admin_headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    viewer_headers = {"Authorization": f"Bearer {target_seed_data['viewer_token']}"}

    # Create target in Project Alpha
    await target_client.post(
        f"/api/v1/projects/{proj_a_id}/targets",
        json={"name": "T Alpha", "seed_type": "domain", "seed_value": "alpha.example.com"},
        headers=admin_headers,
    )

    # Viewer lists Project Alpha targets
    res = await target_client.get(f"/api/v1/projects/{proj_a_id}/targets", headers=viewer_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert any(t["seed_value"] == "alpha.example.com" for t in data["items"])

    # Viewer tries to list Project Beta (where they are not a member) -> 404
    proj_b_id = target_seed_data["proj_beta_id"]
    res_b = await target_client.get(f"/api/v1/projects/{proj_b_id}/targets", headers=viewer_headers)
    assert res_b.status_code == 404


@pytest.mark.asyncio
async def test_get_target_by_id_and_cross_project_isolation(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Viewer can retrieve single target; querying under wrong project returns 404."""
    proj_a_id = target_seed_data["proj_alpha_id"]
    admin_headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    viewer_headers = {"Authorization": f"Bearer {target_seed_data['viewer_token']}"}

    # Create target in Project Alpha
    res_create = await target_client.post(
        f"/api/v1/projects/{proj_a_id}/targets",
        json={"name": "T Single", "seed_type": "domain", "seed_value": "single.example.com"},
        headers=admin_headers,
    )
    target_id = res_create.json()["id"]

    # Viewer gets target under Project Alpha -> 200
    res_get = await target_client.get(
        f"/api/v1/projects/{proj_a_id}/targets/{target_id}",
        headers=viewer_headers,
    )
    assert res_get.status_code == 200
    assert res_get.json()["seed_value"] == "single.example.com"

    # Owner tries to access Target Alpha using Project Beta's URL path -> 404
    proj_b_id = target_seed_data["proj_beta_id"]
    owner_headers = {"Authorization": f"Bearer {target_seed_data['owner_token']}"}
    res_cross = await target_client.get(
        f"/api/v1/projects/{proj_b_id}/targets/{target_id}",
        headers=owner_headers,
    )
    assert res_cross.status_code == 404


# -----------------------------------------------------------------------------
# PATCH & DELETE /projects/{project_id}/targets/{target_id} Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_patches_target_and_viewer_forbidden(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Admin updates target metadata; viewer is forbidden."""
    proj_id = target_seed_data["proj_alpha_id"]
    admin_headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    viewer_headers = {"Authorization": f"Bearer {target_seed_data['viewer_token']}"}

    res_create = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets",
        json={"name": "Original Name", "seed_type": "domain", "seed_value": "patch.example.com"},
        headers=admin_headers,
    )
    target_id = res_create.json()["id"]

    # Viewer attempts PATCH -> 403
    res_v_patch = await target_client.patch(
        f"/api/v1/projects/{proj_id}/targets/{target_id}",
        json={"name": "Hacked Name"},
        headers=viewer_headers,
    )
    assert res_v_patch.status_code == 403

    # Admin performs PATCH -> 200
    res_a_patch = await target_client.patch(
        f"/api/v1/projects/{proj_id}/targets/{target_id}",
        json={"name": "Updated Gateway", "description": "Updated notes"},
        headers=admin_headers,
    )
    assert res_a_patch.status_code == 200
    data = res_a_patch.json()
    assert data["name"] == "Updated Gateway"
    assert data["description"] == "Updated notes"


@pytest.mark.asyncio
async def test_admin_deletes_archives_target_and_viewer_forbidden(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """Admin archives target via DELETE; viewer is forbidden."""
    proj_id = target_seed_data["proj_alpha_id"]
    admin_headers = {"Authorization": f"Bearer {target_seed_data['admin_token']}"}
    viewer_headers = {"Authorization": f"Bearer {target_seed_data['viewer_token']}"}

    res_create = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets",
        json={"name": "To Archive", "seed_type": "domain", "seed_value": "archive.example.com"},
        headers=admin_headers,
    )
    target_id = res_create.json()["id"]

    # Viewer attempts DELETE -> 403
    res_v_del = await target_client.delete(
        f"/api/v1/projects/{proj_id}/targets/{target_id}",
        headers=viewer_headers,
    )
    assert res_v_del.status_code == 403

    # Admin performs DELETE -> 200 (archives)
    res_a_del = await target_client.delete(
        f"/api/v1/projects/{proj_id}/targets/{target_id}",
        headers=admin_headers,
    )
    assert res_a_del.status_code == 200
    assert res_a_del.json()["status"] == "archived"
    assert res_a_del.json()["archived_at"] is not None


# -----------------------------------------------------------------------------
# API Key Authentication & Scope Enforcement Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_key_scopes_enforced_on_target_endpoints(
    target_client: AsyncClient, target_seed_data: dict[str, Any]
) -> None:
    """API key with 'read' can list targets, but cannot create (403). Admin key can create."""
    proj_id = target_seed_data["proj_alpha_id"]
    read_headers = {"Authorization": f"Bearer {target_seed_data['read_api_key']}"}
    admin_headers = {"Authorization": f"Bearer {target_seed_data['admin_api_key']}"}

    # Read API key listing -> 200
    res_list = await target_client.get(f"/api/v1/projects/{proj_id}/targets", headers=read_headers)
    assert res_list.status_code == 200

    # Read API key attempting create -> 403 (needs admin scope)
    res_create_fail = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets",
        json={"name": "Key Target", "seed_type": "domain", "seed_value": "key.example.com"},
        headers=read_headers,
    )
    assert res_create_fail.status_code == 403

    # Admin API key attempting create -> 201
    res_create_ok = await target_client.post(
        f"/api/v1/projects/{proj_id}/targets",
        json={
            "name": "Admin Key Target",
            "seed_type": "domain",
            "seed_value": "admin-key.example.com",
        },
        headers=admin_headers,
    )
    assert res_create_ok.status_code == 201
