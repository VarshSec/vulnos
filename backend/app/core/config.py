"""VulnOS typed application settings.

Environment-based configuration with Pydantic Settings v2.
Includes production fail-fast validations that reject placeholder credentials,
wildcard hosts, and debug flags in production.
"""

from typing import Any
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

# Known insecure/placeholder strings that must be rejected in production
DISALLOWED_PRODUCTION_SECRETS: frozenset[str] = frozenset(
    {
        "replace-with-a-random-48-byte-value",
        "replace-with-a-random-pepper",
        "replace-me",
        "change-me",
        "dev-insecure-secret-key-change-in-production-only-32bytesmin",
        "dev-insecure-pepper-change-in-production",
        "secret",
        "password",
        "admin",
    }
)


class _LenientEnvSettingsSource(EnvSettingsSource):
    """Custom Env source that allows comma-separated strings instead of requiring JSON."""

    def decode_complex_value(self, field_name: str, field: Any, value: Any) -> Any:
        try:
            return super().decode_complex_value(field_name, field, value)
        except Exception:
            return value


class _LenientDotEnvSettingsSource(DotEnvSettingsSource):
    """Custom DotEnv source that allows comma-separated strings instead of requiring JSON."""

    def decode_complex_value(self, field_name: str, field: Any, value: Any) -> Any:
        try:
            return super().decode_complex_value(field_name, field, value)
        except Exception:
            return value


class Settings(BaseSettings):
    """Application settings with environment override and validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            _LenientEnvSettingsSource(settings_cls),
            _LenientDotEnvSettingsSource(settings_cls, env_file=".env", env_file_encoding="utf-8"),
            file_secret_settings,
        )

    # Application
    APP_NAME: str = "VulnOS"
    APP_ENV: str = "development"  # development | test | production
    APP_DEBUG: bool = False
    API_BASE_URL: str = "http://localhost:8000"
    API_V1_PREFIX: str = "/api/v1"
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json | console

    # Security
    SECRET_KEY: str = "dev-insecure-secret-key-change-in-production-only-32bytesmin"  # noqa: S105
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: str = "lax"
    ACCESS_TOKEN_TTL_MINUTES: int = 30
    REFRESH_TOKEN_TTL_DAYS: int = 14
    API_KEY_PEPPER: str = "dev-insecure-pepper-change-in-production"
    ALLOWED_HOSTS: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    CORS_ORIGINS: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    CORS_ALLOW_CREDENTIALS: bool = True

    # Database
    DATABASE_URL: str = "postgresql+psycopg://vulnos:change-me@localhost:5432/vulnos"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_ECHO: bool = False

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_DEFAULT_QUEUE: str = "vulnos.default"
    CELERY_WORKER_CONCURRENCY: int = 4
    CELERY_TASK_SOFT_TIME_LIMIT_SECONDS: int = 3600
    CELERY_TASK_TIME_LIMIT_SECONDS: int = 3900

    # Evidence Object Storage (S3-compatible)
    S3_ENDPOINT_URL: str = "http://localhost:9000"
    S3_REGION: str = "us-east-1"
    S3_ACCESS_KEY: str = "replace-me"
    S3_SECRET_KEY: str = "replace-me"  # noqa: S105
    S3_BUCKET_EVIDENCE: str = "vulnos-evidence"
    S3_BUCKET_REPORTS: str = "vulnos-reports"
    S3_USE_SSL: bool = False
    S3_SERVER_SIDE_ENCRYPTION: str = "SSE-S3"
    S3_SIGNED_URL_TTL_SECONDS: int = 300
    EVIDENCE_MAX_BODY_BYTES: int = 5242880
    EVIDENCE_RETENTION_DAYS: int = 90

    # Readiness check timeouts (seconds)
    READINESS_CHECK_TIMEOUT_SECONDS: float = 2.0

    @field_validator("ALLOWED_HOSTS", "CORS_ORIGINS", mode="before")
    @classmethod
    def _parse_comma_separated_list(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    @property
    def is_production(self) -> bool:
        """Check whether application is running in production mode."""
        return self.APP_ENV.lower() in {"production", "prod"}

    @model_validator(mode="after")
    def _validate_production_invariants(self) -> "Settings":
        """Enforce fail-fast security constraints for production environments."""
        if not self.is_production:
            return self

        errors: list[str] = []

        # 1. APP_DEBUG must be False in production
        if self.APP_DEBUG:
            errors.append("APP_DEBUG must be False in production.")

        # 2. SECRET_KEY validation
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be at least 32 characters long in production.")
        if self.SECRET_KEY in DISALLOWED_PRODUCTION_SECRETS or any(
            placeholder in self.SECRET_KEY.lower()
            for placeholder in ("replace", "change-me", "insecure")
        ):
            errors.append("SECRET_KEY is using an insecure or placeholder value in production.")

        # 3. API_KEY_PEPPER validation
        if not self.API_KEY_PEPPER or len(self.API_KEY_PEPPER) < 16:
            errors.append("API_KEY_PEPPER must be at least 16 characters long in production.")
        if self.API_KEY_PEPPER in DISALLOWED_PRODUCTION_SECRETS or any(
            placeholder in self.API_KEY_PEPPER.lower()
            for placeholder in ("replace", "change-me", "insecure")
        ):
            errors.append("API_KEY_PEPPER is using an insecure or placeholder value in production.")

        # 4. ALLOWED_HOSTS must not contain wildcard '*'
        if "*" in self.ALLOWED_HOSTS:
            errors.append("Wildcard '*' in ALLOWED_HOSTS is forbidden in production.")
        if not self.ALLOWED_HOSTS:
            errors.append("ALLOWED_HOSTS must contain at least one valid host in production.")

        # 5. CORS wildcard origin forbidden when credentials enabled
        if self.CORS_ALLOW_CREDENTIALS and "*" in self.CORS_ORIGINS:
            errors.append("CORS wildcard '*' origin cannot be used with credentials enabled.")

        # 6. Reject placeholder S3 credentials in production
        if (
            self.S3_ACCESS_KEY in DISALLOWED_PRODUCTION_SECRETS
            or self.S3_SECRET_KEY in DISALLOWED_PRODUCTION_SECRETS
        ):
            errors.append("S3 credentials contain placeholder values in production.")

        # 7. Reject placeholder DATABASE_URL in production
        if "change-me" in self.DATABASE_URL:
            errors.append("DATABASE_URL contains placeholder password in production.")

        if errors:
            raise ValueError(
                "Production configuration security checks failed:\n - " + "\n - ".join(errors)
            )

        return self

    @property
    def parsed_db_host_port(self) -> tuple[str, int]:
        """Extract (host, port) for TCP connectivity checks without exposing credentials."""
        # Handles standard URLs like postgresql+psycopg://user:pass@host:port/dbname
        clean_url = self.DATABASE_URL.replace("postgresql+psycopg://", "http://").replace(
            "postgresql://", "http://"
        )
        parsed = urlparse(clean_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        return host, port

    @property
    def parsed_redis_host_port(self) -> tuple[str, int]:
        """Extract (host, port) for TCP connectivity check."""
        parsed = urlparse(self.REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        return host, port

    @property
    def parsed_s3_host_port(self) -> tuple[str, int]:
        """Extract (host, port) for S3 TCP connectivity check."""
        parsed = urlparse(self.S3_ENDPOINT_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 9000)
        return host, port


def get_settings() -> Settings:
    """Settings factory/accessor."""
    return Settings()
