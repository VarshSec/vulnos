"""End-to-end integration tests for authentication and API key HTTP endpoints."""

from collections.abc import AsyncGenerator, Generator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.auth.sessions import SessionManager
from backend.app.core.config import Settings
from backend.app.db.base import Base
from backend.app.db.models.identity import User
from backend.app.db.session import get_db
from backend.app.main import create_app
from backend.tests.security.auth.test_sessions import FakeRedisClient


@pytest.fixture
def session_factory() -> Generator[sessionmaker[Session]]:
    """In-memory SQLite session factory with StaticPool for thread-safe testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [
        User.__table__,
        Base.metadata.tables["api_keys"],
        Base.metadata.tables["audit_logs"],
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
async def async_client(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[AsyncClient]:
    """AsyncClient wired with in-memory DB and FakeRedisClient."""
    fake_redis = FakeRedisClient()
    fake_session_mgr = SessionManager(client=fake_redis)

    import backend.app.api.v1.auth as auth_mod
    import backend.app.auth.dependencies as dep_mod
    import backend.app.auth.rate_limits as rl_mod

    monkeypatch.setattr(auth_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(dep_mod, "_session_manager", fake_session_mgr)
    monkeypatch.setattr(rl_mod, "get_redis_client", lambda: fake_redis)

    test_settings = Settings(
        APP_ENV="test",
        APP_DEBUG=False,
        SECRET_KEY="test-secret-key-for-unit-testing-32bytes",
        ALLOWED_HOSTS=["testserver", "localhost"],
        CORS_ORIGINS=["http://localhost:5173"],
    )
    app = create_app(settings=test_settings)

    def override_get_db() -> Generator[Session]:
        session = session_factory()
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


@pytest.mark.asyncio
async def test_register_and_login_flow(async_client: AsyncClient) -> None:
    """Verify user registration and subsequent login returning tokens and cookies."""
    reg_payload = {
        "email": "developer@example.com",
        "password": "CorrectHorseBatteryStaple123!",
        "display_name": "Lead Developer",
    }
    # 1. Register
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["email"] == "developer@example.com"
    assert user_data["display_name"] == "Lead Developer"
    assert "password" not in user_data
    assert "password_hash" not in user_data

    # 2. Login
    login_payload = {
        "email": "developer@example.com",
        "password": "CorrectHorseBatteryStaple123!",
    }
    login_res = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert "refresh_token" in token_data

    # Verify session cookie was set
    assert "vulnos_session" in login_res.cookies

    # 3. GET /api/v1/auth/me using Bearer Access Token
    auth_header = {"Authorization": f"Bearer {token_data['access_token']}"}
    me_res = await async_client.get("/api/v1/auth/me", headers=auth_header)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "developer@example.com"


@pytest.mark.asyncio
async def test_api_key_lifecycle_endpoints(async_client: AsyncClient) -> None:
    """Verify creating, listing, using, and revoking API keys."""
    # First register and login a user
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "ci_bot@example.com",
            "password": "AutomatedTestingPassword123!",
            "display_name": "CI Bot",
        },
    )
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "ci_bot@example.com",
            "password": "AutomatedTestingPassword123!",
        },
    )
    bearer_token = login_res.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {bearer_token}"}

    # 1. Create API Key
    create_res = await async_client.post(
        "/api/v1/api-keys",
        headers=user_headers,
        json={"name": "GitHub Actions Key", "scopes": ["read", "scan"]},
    )
    assert create_res.status_code == 201
    key_data = create_res.json()
    assert "api_key" in key_data
    raw_api_key = key_data["api_key"]
    assert raw_api_key.startswith("vulnos_")
    key_id = key_data["id"]

    # 2. List API Keys
    list_res = await async_client.get("/api/v1/api-keys", headers=user_headers)
    assert list_res.status_code == 200
    keys_list = list_res.json()
    assert len(keys_list) == 1
    assert keys_list[0]["id"] == key_id
    assert "api_key" not in keys_list[0]  # Secret must NOT be returned in list!

    # 3. Authenticate with the newly issued API Key
    api_key_headers = {"Authorization": f"Bearer {raw_api_key}"}
    me_res = await async_client.get("/api/v1/auth/me", headers=api_key_headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "ci_bot@example.com"

    # 4. Revoke the API Key
    del_res = await async_client.delete(f"/api/v1/api-keys/{key_id}", headers=user_headers)
    assert del_res.status_code == 204

    # 5. Verify revoked API Key cannot authenticate
    revoked_me_res = await async_client.get("/api/v1/auth/me", headers=api_key_headers)
    assert revoked_me_res.status_code == 401
