"""Tests for settings validation, defaults, and production fail-fast rules."""

import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings


def test_default_development_settings() -> None:
    """Verify default development configuration is loaded safely."""
    settings = Settings()
    assert settings.APP_NAME == "VulnOS"
    assert settings.APP_ENV == "development"
    assert settings.APP_DEBUG is False
    assert not settings.is_production
    assert "localhost" in settings.ALLOWED_HOSTS
    assert "http://localhost:5173" in settings.CORS_ORIGINS

    host, port = settings.parsed_db_host_port
    assert host == "localhost"
    assert port == 5432

    r_host, r_port = settings.parsed_redis_host_port
    assert r_host == "localhost"
    assert r_port == 6379

    s3_host, s3_port = settings.parsed_s3_host_port
    assert s3_host == "localhost"
    assert s3_port == 9000


def test_comma_separated_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify comma-separated string environment variables parse into clean lists."""
    monkeypatch.setenv("ALLOWED_HOSTS", "api.vulnos.local, 10.0.0.1, internal.host")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000, https://app.vulnos.com")
    settings = Settings()
    assert settings.ALLOWED_HOSTS == ["api.vulnos.local", "10.0.0.1", "internal.host"]
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "https://app.vulnos.com"]


def test_production_rejects_debug_mode() -> None:
    """Production configuration must reject APP_DEBUG=True."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            APP_DEBUG=True,
            SECRET_KEY="A" * 48,
            API_KEY_PEPPER="B" * 32,
            ALLOWED_HOSTS=["api.vulnos.com"],
            CORS_ORIGINS=["https://app.vulnos.com"],
            DATABASE_URL="postgresql+psycopg://user:realpass123@db.prod:5432/vulnos",
            S3_ACCESS_KEY="real-s3-access-key-prod",
            S3_SECRET_KEY="real-s3-secret-key-prod",
        )
    assert "APP_DEBUG must be False in production" in str(exc_info.value)


def test_production_rejects_placeholder_secret_key() -> None:
    """Production must reject placeholder or short SECRET_KEY."""
    # Test short key
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            SECRET_KEY="too-short",
            API_KEY_PEPPER="B" * 32,
            ALLOWED_HOSTS=["api.vulnos.com"],
            DATABASE_URL="postgresql+psycopg://user:realpass@db:5432/vulnos",
            S3_ACCESS_KEY="real-access",
            S3_SECRET_KEY="real-secret",
        )
    assert "SECRET_KEY must be at least 32 characters" in str(exc_info.value)

    # Test placeholder string
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            SECRET_KEY="replace-with-a-random-48-byte-value-long-enough",
            API_KEY_PEPPER="B" * 32,
            ALLOWED_HOSTS=["api.vulnos.com"],
            DATABASE_URL="postgresql+psycopg://user:realpass@db:5432/vulnos",
            S3_ACCESS_KEY="real-access",
            S3_SECRET_KEY="real-secret",
        )
    assert "SECRET_KEY is using an insecure or placeholder value" in str(exc_info.value)


def test_production_rejects_placeholder_pepper() -> None:
    """Production must reject placeholder or short API_KEY_PEPPER."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            SECRET_KEY="A" * 48,
            API_KEY_PEPPER="dev-insecure-pepper-change-in-production",
            ALLOWED_HOSTS=["api.vulnos.com"],
            DATABASE_URL="postgresql+psycopg://user:realpass@db:5432/vulnos",
            S3_ACCESS_KEY="real-access",
            S3_SECRET_KEY="real-secret",
        )
    assert "API_KEY_PEPPER is using an insecure or placeholder value" in str(exc_info.value)


def test_production_rejects_wildcard_allowed_hosts() -> None:
    """Production must reject wildcard '*' in ALLOWED_HOSTS."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            SECRET_KEY="A" * 48,
            API_KEY_PEPPER="B" * 32,
            ALLOWED_HOSTS=["*"],
            DATABASE_URL="postgresql+psycopg://user:realpass@db:5432/vulnos",
            S3_ACCESS_KEY="real-access",
            S3_SECRET_KEY="real-secret",
        )
    assert "Wildcard '*' in ALLOWED_HOSTS is forbidden" in str(exc_info.value)


def test_production_rejects_credentialed_wildcard_cors() -> None:
    """Production must reject wildcard CORS origin when credentials are enabled."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            SECRET_KEY="A" * 48,
            API_KEY_PEPPER="B" * 32,
            ALLOWED_HOSTS=["api.vulnos.com"],
            CORS_ALLOW_CREDENTIALS=True,
            CORS_ORIGINS=["*"],
            DATABASE_URL="postgresql+psycopg://user:realpass@db:5432/vulnos",
            S3_ACCESS_KEY="real-access",
            S3_SECRET_KEY="real-secret",
        )
    assert "CORS wildcard '*' origin cannot be used with credentials" in str(exc_info.value)


def test_production_accepts_valid_hardened_settings() -> None:
    """Verify production passes validation when all security parameters are hardened."""
    settings = Settings(
        APP_ENV="production",
        APP_DEBUG=False,
        SECRET_KEY="Z" * 64,
        API_KEY_PEPPER="Y" * 32,
        ALLOWED_HOSTS=["api.vulnos.com"],
        CORS_ALLOW_CREDENTIALS=True,
        CORS_ORIGINS=["https://dashboard.vulnos.com"],
        DATABASE_URL="postgresql+psycopg://vulnos_app:ComplexPass987!@pg.internal:5432/vulnos",
        S3_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE",
        S3_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    assert settings.is_production
    assert settings.SECRET_KEY == "Z" * 64
