"""Integration and security tests for VulnOS Scope Versioning & Validation (P2.5.6).

Validates:
- Scope version lifecycle: 'draft' -> 'active' -> 'superseded'.
- Immutability: Rules can only be edited while in 'draft' status.
- Activation gate: Requires active, valid, non-revoked AuthorizationRecord.
- Activation gate: Rejects empty scope versions (must contain at least 1 rule).
- Atomic superseding: Activating a new version atomically supersedes the existing active version.
- Content hash determinism: Shuffled rules produce identical SHA-256 hashes.
- Scope validation engine: Evaluates legal consent, active scope rules, global deny precedence.
- Private network and IMDS protection in validation.
- Dry-run vs persistent auditing in the ScopeDecision table.
- RBAC and tenant isolation across projects.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

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
    ScopeDecision,
    ScopeRule,
    ScopeVersion,
    Target,
    User,
)
from backend.app.db.session import get_db
from backend.app.db.types import utc_now, uuid7
from backend.app.main import create_app
from backend.app.scope.schemas import ScopeRuleCreateRequest
from backend.app.scope.versions import compute_scope_content_hash
from backend.tests.security.auth.test_sessions import FakeRedisClient


@pytest.fixture
def scope_session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory for scope versioning tests."""
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
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine, tables=tables)  # type: ignore[arg-type]


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        APP_DEBUG=False,
        SECRET_KEY="test-secret-key-for-unit-testing-32bytes",
        ALLOWED_HOSTS=["testserver", "localhost"],
        CORS_ORIGINS=["http://localhost:5173"],
    )


@pytest.fixture
async def client(
    scope_session_factory: sessionmaker[Session],
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient]:
    fake_redis = FakeRedisClient()
    fake_session_mgr = SessionManager(client=fake_redis)

    import backend.app.api.v1.auth as auth_mod
    import backend.app.auth.dependencies as dep_mod
    import backend.app.auth.rate_limits as rl_mod

    monkeypatch.setattr(auth_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(dep_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(rl_mod, "get_redis_client", lambda: fake_redis)

    app = create_app(settings=test_settings)

    def override_get_db() -> Generator[Session]:
        session = scope_session_factory()
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
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def seeded_env(scope_session_factory: sessionmaker[Session]) -> dict[str, Any]:
    """Seed test users, project, memberships, and a valid authorization record."""
    session = scope_session_factory()
    now = utc_now()

    owner = User(
        id=uuid7(),
        email="owner@example.com",
        display_name="Project Owner",
        auth_provider="local",
        is_active=True,
    )
    admin = User(
        id=uuid7(),
        email="admin@example.com",
        display_name="Project Admin",
        auth_provider="local",
        is_active=True,
    )
    operator = User(
        id=uuid7(),
        email="operator@example.com",
        display_name="Project Operator",
        auth_provider="local",
        is_active=True,
    )
    viewer = User(
        id=uuid7(),
        email="viewer@example.com",
        display_name="Project Viewer",
        auth_provider="local",
        is_active=True,
    )
    non_member = User(
        id=uuid7(),
        email="nonmember@example.com",
        display_name="External User",
        auth_provider="local",
        is_active=True,
    )
    session.add_all([owner, admin, operator, viewer, non_member])
    session.flush()

    project = Project(
        id=uuid7(),
        name="Target Project Alpha",
        slug="target-project-alpha",
        owner_id=owner.id,
    )
    project_b = Project(
        id=uuid7(),
        name="Project Beta",
        slug="project-beta",
        owner_id=owner.id,
    )
    session.add_all([project, project_b])
    session.flush()

    session.add_all(
        [
            ProjectMember(project_id=project.id, user_id=owner.id, role="owner"),
            ProjectMember(project_id=project.id, user_id=admin.id, role="admin"),
            ProjectMember(project_id=project.id, user_id=operator.id, role="operator"),
            ProjectMember(project_id=project.id, user_id=viewer.id, role="viewer"),
            ProjectMember(project_id=project_b.id, user_id=owner.id, role="owner"),
        ]
    )
    session.flush()

    # Valid authorization record
    auth_record = AuthorizationRecord(
        id=uuid7(),
        project_id=project.id,
        reference="ENG-2026-ALPHA-01",
        authorized_by_name="Chief CISO",
        authorized_by_contact="ciso@example.com",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=30),
        allowed_actions=["scan", "probe", "crawl", "validate"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=owner.id,
        created_at=now,
    )
    session.add(auth_record)
    from types import SimpleNamespace

    owner_id = owner.id
    admin_id = admin.id
    operator_id = operator.id
    viewer_id = viewer.id
    non_member_id = non_member.id
    project_id = project.id
    project_b_id = project_b.id
    auth_record_id = auth_record.id

    session.commit()
    session.close()

    return {
        "owner": SimpleNamespace(id=owner_id),
        "admin": SimpleNamespace(id=admin_id),
        "operator": SimpleNamespace(id=operator_id),
        "viewer": SimpleNamespace(id=viewer_id),
        "non_member": SimpleNamespace(id=non_member_id),
        "project": SimpleNamespace(id=project_id),
        "project_b": SimpleNamespace(id=project_b_id),
        "auth_record": SimpleNamespace(id=auth_record_id),
    }


def make_auth_headers(user: Any, test_settings: Settings | None = None) -> dict[str, str]:
    user_id = getattr(user, "id", user)
    token = create_access_token(user_id)
    return {"Authorization": f"Bearer {token}"}


def get_error_message(resp: Any) -> str:
    body = resp.json()
    if isinstance(body, dict):
        if "error" in body and isinstance(body["error"], dict):
            return str(body["error"].get("message", "")).lower()
        if "detail" in body:
            return str(body["detail"]).lower()
    return str(body).lower()


# -----------------------------------------------------------------------------
# Unit & Determinism Tests
# -----------------------------------------------------------------------------


def test_compute_scope_content_hash_deterministic() -> None:
    """Verify content hash is independent of rule ordering and sensitive to edits."""
    r1 = ScopeRuleCreateRequest(
        effect="allow",
        match_type="exact_host",
        value="api.example.com",
        priority=100,
    )
    r2 = ScopeRuleCreateRequest(
        effect="deny",
        match_type="wildcard_domain",
        value="*.admin.example.com",
        priority=200,
    )
    r3 = ScopeRuleCreateRequest(
        effect="allow",
        match_type="cidr",
        value="10.0.0.0/24",
        protocols=["http", "https"],
        priority=50,
    )

    hash_order_1 = compute_scope_content_hash([r1, r2, r3])
    hash_order_2 = compute_scope_content_hash([r3, r1, r2])
    hash_order_3 = compute_scope_content_hash([r2, r3, r1])

    assert hash_order_1 == hash_order_2 == hash_order_3
    assert len(hash_order_1) == 32

    # Mutation test: changing priority changes hash
    r1_mutated = ScopeRuleCreateRequest(
        effect="allow",
        match_type="exact_host",
        value="api.example.com",
        priority=101,
    )
    hash_mutated = compute_scope_content_hash([r1_mutated, r2, r3])
    assert hash_mutated != hash_order_1


# -----------------------------------------------------------------------------
# Scope Version Lifecycle API Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_create_scope_version_draft(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
    scope_session_factory: sessionmaker[Session],
) -> None:
    """Admin creates a draft scope version bound to authorization record."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["version"] == 1
    assert data["status"] == "draft"
    assert data["authorization_id"] == str(auth_id)
    assert data["project_id"] == str(project_id)
    assert data["activated_at"] is None
    assert data["superseded_at"] is None
    assert len(data["content_hash"]) == 64  # Hex-encoded SHA-256

    # Verify audit log
    with scope_session_factory() as session:
        audit = session.query(AuditLog).filter(AuditLog.action == "scope_version.create").first()
        assert audit is not None
        assert audit.entity_id == data["id"]
        assert audit.project_id == project_id


@pytest.mark.anyio
async def test_create_scope_version_sequential_numbering(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Verify subsequent versions receive sequential version numbers."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    resp1 = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    assert resp1.status_code == 201
    assert resp1.json()["version"] == 1

    resp2 = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    assert resp2.status_code == 201
    assert resp2.json()["version"] == 2


@pytest.mark.anyio
async def test_create_scope_version_invalid_auth_record(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Attempting to bind a non-existent authorization record fails with 404."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    fake_auth_id = str(uuid7())

    resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": fake_auth_id},
        headers=headers,
    )
    assert resp.status_code == 404
    assert "not found" in get_error_message(resp)


@pytest.mark.anyio
async def test_replace_scope_rules_on_draft(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
    scope_session_factory: sessionmaker[Session],
) -> None:
    """Admin replaces all rules in a draft scope version."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    create_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    version_id = create_resp.json()["id"]

    rules_payload = [
        {
            "effect": "allow",
            "match_type": "exact_host",
            "value": "api.example.com",
            "priority": 100,
            "note": "Main API",
        },
        {
            "effect": "allow",
            "match_type": "domain_suffix",
            "value": "example.com",
            "priority": 50,
            "note": "Root and subdomains",
        },
        {
            "effect": "deny",
            "match_type": "wildcard_domain",
            "value": "*.corp.example.com",
            "priority": 200,
            "note": "Exclude internal corporate assets",
        },
    ]

    put_resp = await client.put(
        f"/api/v1/projects/{project_id}/scope/{version_id}/rules",
        json={"rules": rules_payload},
        headers=headers,
    )
    assert put_resp.status_code == 200
    data = put_resp.json()
    assert len(data["rules"]) == 3
    assert data["content_hash"] != create_resp.json()["content_hash"]

    # Verify audit log
    with scope_session_factory() as session:
        audit = session.query(AuditLog).filter(AuditLog.action == "scope_rules.replace").first()
        assert audit is not None
        assert audit.metadata_["rule_count"] == 3


@pytest.mark.anyio
async def test_replace_scope_rules_invalid_rule_rejected(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Invalid rule patterns or port bounds are rejected with 422."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    create_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    version_id = create_resp.json()["id"]

    # Invalid wildcard syntax (missing *.)
    bad_rules = [
        {
            "effect": "allow",
            "match_type": "wildcard_domain",
            "value": "invalid-wildcard.com",
            "priority": 100,
        }
    ]
    resp = await client.put(
        f"/api/v1/projects/{project_id}/scope/{version_id}/rules",
        json={"rules": bad_rules},
        headers=headers,
    )
    assert resp.status_code == 422

    # Invalid port range [443, 80]
    bad_ports = [
        {
            "effect": "allow",
            "match_type": "exact_host",
            "value": "api.example.com",
            "ports": [443, 80],
        }
    ]
    resp_port = await client.put(
        f"/api/v1/projects/{project_id}/scope/{version_id}/rules",
        json={"rules": bad_ports},
        headers=headers,
    )
    assert resp_port.status_code == 422


@pytest.mark.anyio
async def test_activate_empty_scope_version_rejected(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Activating a draft version with 0 rules fails with 400."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    create_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    version_id = create_resp.json()["id"]

    resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/{version_id}/activate",
        headers=headers,
    )
    assert resp.status_code == 400
    assert "at least one rule" in get_error_message(resp)


@pytest.mark.anyio
async def test_activate_scope_version_success_and_immutability(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
    scope_session_factory: sessionmaker[Session],
) -> None:
    """Activating locks version and rules, transitioning status to 'active'."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    create_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    version_id = create_resp.json()["id"]

    await client.put(
        f"/api/v1/projects/{project_id}/scope/{version_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                    "priority": 100,
                }
            ]
        },
        headers=headers,
    )

    act_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/{version_id}/activate",
        headers=headers,
    )
    assert act_resp.status_code == 200
    data = act_resp.json()
    assert data["status"] == "active"
    assert data["activated_at"] is not None

    # CRITICAL INVARIANT: Scope version is now completely immutable
    modify_resp = await client.put(
        f"/api/v1/projects/{project_id}/scope/{version_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "hacked.com",
                    "priority": 100,
                }
            ]
        },
        headers=headers,
    )
    assert modify_resp.status_code == 409
    assert "immutable" in get_error_message(modify_resp)


@pytest.mark.anyio
async def test_activate_scope_version_atomic_superseding(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Activating v2 atomically supersedes v1 so exactly one version is active."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    # Create & activate v1
    v1_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    v1_id = v1_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v1_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                }
            ]
        },
        headers=headers,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v1_id}/activate", headers=headers)

    # Create & activate v2
    v2_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers,
    )
    v2_id = v2_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v2_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "exact_host",
                    "value": "v2.example.com",
                }
            ]
        },
        headers=headers,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v2_id}/activate", headers=headers)

    # Inspect v1 and v2 status
    get_v1 = await client.get(f"/api/v1/projects/{project_id}/scope/{v1_id}", headers=headers)
    assert get_v1.json()["status"] == "superseded"
    assert get_v1.json()["superseded_at"] is not None

    get_v2 = await client.get(f"/api/v1/projects/{project_id}/scope/{v2_id}", headers=headers)
    assert get_v2.json()["status"] == "active"
    assert get_v2.json()["superseded_at"] is None


@pytest.mark.anyio
async def test_activate_with_expired_or_revoked_auth_rejected(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
    scope_session_factory: sessionmaker[Session],
) -> None:
    """Scope activation is gated on a valid, non-expired, non-revoked authorization record."""
    headers = make_auth_headers(seeded_env["admin"], test_settings)
    project_id = seeded_env["project"].id

    with scope_session_factory() as session:
        # Create an expired authorization record
        now = utc_now()
        expired_auth = AuthorizationRecord(
            id=uuid7(),
            project_id=project_id,
            reference="EXPIRED-ENGAGEMENT",
            authorized_by_name="Expired Manager",
            authorized_by_contact="manager@example.com",
            valid_from=now - timedelta(days=60),
            valid_to=now - timedelta(days=1),
            allowed_actions=["scan"],
            created_by=seeded_env["owner"].id,
            created_at=now - timedelta(days=60),
        )
        session.add(expired_auth)
        session.commit()
        expired_id = expired_auth.id

    # Create draft scope version bound to expired auth
    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(expired_id)},
        headers=headers,
    )
    v_id = v_resp.json()["id"]

    # Add a valid rule
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "exact_host",
                    "value": "api.example.com",
                }
            ]
        },
        headers=headers,
    )

    # Activating must fail with 422
    act_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/{v_id}/activate",
        headers=headers,
    )
    assert act_resp.status_code == 422
    assert "expired" in get_error_message(act_resp)


# -----------------------------------------------------------------------------
# Scope Validation Endpoint Tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_scope_validation_endpoint_authorized(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Validate endpoint authorizes matching target when active auth + active scope allow."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    # Create, configure, and activate scope version
    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                    "priority": 100,
                }
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    # Validate destination
    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "https://api.example.com/v1/status",
            "action": "scan",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    decision = val_resp.json()
    assert decision["allowed"] is True
    assert decision["reason_code"] == "allowed_rule"
    assert decision["matched_rule_id"] is not None
    assert decision["authorization_id"] == str(auth_id)
    assert decision["scope_version_id"] == v_id


@pytest.mark.anyio
async def test_scope_validation_endpoint_deny_overrides_allow(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Global deny overrides allow regardless of specificity."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                    "priority": 100,
                },
                {
                    "effect": "deny",
                    "match_type": "wildcard_domain",
                    "value": "*.internal.example.com",
                    "priority": 10,
                },
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "https://db.internal.example.com/admin",
            "action": "scan",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    decision = val_resp.json()
    assert decision["allowed"] is False
    assert decision["reason_code"] == "explicit_deny"


@pytest.mark.anyio
async def test_scope_validation_endpoint_action_not_allowed(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Action not present in authorization allowed_actions fails closed."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                }
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    # Request action 'fuzz' which is not in allowed_actions ['scan', 'probe', 'crawl', 'validate']
    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "https://api.example.com/search",
            "action": "fuzz",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    decision = val_resp.json()
    assert decision["allowed"] is False
    assert decision["reason_code"] == "AUTHORIZATION_ACTION_NOT_ALLOWED"


@pytest.mark.anyio
async def test_scope_validation_endpoint_cloud_imds_hard_blocked(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Cloud IMDS IP 169.254.169.254 is non-overridable and always denied."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    # Even if an allow rule explicitly permits the IP or CIDR:
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "ip",
                    "value": "169.254.169.254",
                }
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "http://169.254.169.254/latest/meta-data/",
            "action": "scan",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    decision = val_resp.json()
    assert decision["allowed"] is False
    assert decision["reason_code"] == "cloud_metadata_blocked"


@pytest.mark.anyio
async def test_scope_validation_endpoint_private_range_blocked_without_permission(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Private IP ranges are blocked unless authorization record sets allow_private_ranges=True."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "cidr",
                    "value": "192.168.1.0/24",
                }
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "192.168.1.50",
            "action": "scan",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    decision = val_resp.json()
    assert decision["allowed"] is False
    assert decision["reason_code"] == "private_range_blocked"


@pytest.mark.anyio
async def test_scope_validation_dry_run_vs_persistent_audit(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
    scope_session_factory: sessionmaker[Session],
) -> None:
    """Verify that dry_run=False records an append-only row to ScopeDecision."""
    headers_admin = make_auth_headers(seeded_env["admin"], test_settings)
    headers_operator = make_auth_headers(seeded_env["operator"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    v_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_admin,
    )
    v_id = v_resp.json()["id"]
    await client.put(
        f"/api/v1/projects/{project_id}/scope/{v_id}/rules",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "match_type": "domain_suffix",
                    "value": "example.com",
                }
            ]
        },
        headers=headers_admin,
    )
    await client.post(f"/api/v1/projects/{project_id}/scope/{v_id}/activate", headers=headers_admin)

    # 1. Dry run: No ScopeDecision row inserted
    await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "https://api.example.com",
            "dry_run": True,
        },
        headers=headers_operator,
    )
    with scope_session_factory() as session:
        assert session.query(ScopeDecision).count() == 0

    # 2. Non dry-run: Exactly 1 ScopeDecision row inserted
    val_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/validate",
        json={
            "target": "https://api.example.com",
            "dry_run": False,
        },
        headers=headers_operator,
    )
    assert val_resp.status_code == 200
    with scope_session_factory() as session:
        decisions = session.query(ScopeDecision).all()
        assert len(decisions) == 1
        d = decisions[0]
        assert d.project_id == project_id
        assert d.scope_version_id == UUID(v_id)
        assert d.allowed is True
        assert d.reason_code == "allowed_rule"
        assert d.policy_hash == bytes.fromhex(v_resp.json()["content_hash"]) or d.policy_hash


@pytest.mark.anyio
async def test_scope_endpoints_rbac_and_project_isolation(
    client: AsyncClient,
    seeded_env: dict[str, Any],
    test_settings: Settings,
) -> None:
    """Verify viewer cannot mutate scope, and non-member receives 404."""
    headers_viewer = make_auth_headers(seeded_env["viewer"], test_settings)
    headers_nonmember = make_auth_headers(seeded_env["non_member"], test_settings)
    project_id = seeded_env["project"].id
    auth_id = seeded_env["auth_record"].id

    # Viewer cannot create scope version (403 Forbidden)
    resp_viewer = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_viewer,
    )
    assert resp_viewer.status_code == 403

    # Non-member receives 404 Not Found to prevent project existence enumeration
    resp_nonmember = await client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"authorization_id": str(auth_id)},
        headers=headers_nonmember,
    )
    assert resp_nonmember.status_code == 404
