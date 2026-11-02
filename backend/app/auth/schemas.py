"""Pydantic request and response schemas for authentication and API keys."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRegisterRequest(BaseModel):
    """Payload for user registration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(
        ..., min_length=12, max_length=128, description="User password (min 12 chars)"
    )
    display_name: str = Field(..., min_length=1, max_length=100, description="User display name")


class UserLoginRequest(BaseModel):
    """Payload for user credential login."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="Password")


class PasswordChangeRequest(BaseModel):
    """Payload for user password update."""

    model_config = ConfigDict(str_strip_whitespace=True)

    current_password: str = Field(..., min_length=1, max_length=128, description="Current password")
    new_password: str = Field(
        ..., min_length=12, max_length=128, description="New password (min 12 chars)"
    )


class UserResponse(BaseModel):
    """Safe public representation of a user identity (no credentials)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    display_name: str
    is_active: bool
    auth_provider: str
    created_at: datetime
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    """Access token pair returned upon successful authentication or refresh."""

    access_token: str = Field(..., description="Short-lived JWT access token")
    token_type: str = Field(default="bearer", description="Token type indicator")
    expires_in_seconds: int = Field(..., description="Access token TTL in seconds")
    refresh_token: str | None = Field(default=None, description="Cryptographic refresh token")


class TokenRefreshRequest(BaseModel):
    """Payload for token refresh when not using cookie-based refresh."""

    model_config = ConfigDict(str_strip_whitespace=True)

    refresh_token: str | None = Field(
        default=None, description="Refresh token string (if not in cookie)"
    )


class APIKeyCreateRequest(BaseModel):
    """Payload to issue a new API key."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(
        ..., min_length=1, max_length=100, description="Descriptive identifier for the key"
    )
    scopes: list[str] = Field(
        default_factory=lambda: ["read"],
        description="Permission scopes: read, scan, validate, report, admin",
    )
    expires_at: datetime | None = Field(
        default=None, description="Optional key expiration timestamp (UTC)"
    )


class APIKeyCreateResponse(BaseModel):
    """Response containing the plaintext API key displayed strictly once upon creation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    key_prefix: str
    api_key: str = Field(..., description="Plaintext secret key — displayed once, never stored")
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None


class APIKeyResponse(BaseModel):
    """Safe metadata representation of an API key (never contains secret)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
