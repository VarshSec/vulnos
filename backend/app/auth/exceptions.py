"""Authentication and authorization exception definitions for VulnOS."""


class AuthError(Exception):
    """Base exception for all authentication and authorization errors."""

    def __init__(self, message: str = "Authentication error"):
        self.message = message
        super().__init__(self.message)


class InvalidCredentialsError(AuthError):
    """Raised when authentication credentials (email/password, secret) are invalid."""

    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(message)


class UserNotFoundError(AuthError):
    """Raised when a user cannot be found."""

    def __init__(self, message: str = "User not found"):
        super().__init__(message)


class UserInactiveError(AuthError):
    """Raised when a user account is disabled or deactivated."""

    def __init__(self, message: str = "User account is inactive"):
        super().__init__(message)


class PasswordPolicyError(AuthError):
    """Raised when a candidate password violates policy constraints."""


class TokenError(AuthError):
    """Base exception for JWT and refresh token failures."""


class TokenExpiredError(TokenError):
    """Raised when an access or refresh token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)


class TokenInvalidError(TokenError):
    """Raised when a token signature, type, or claim is invalid or malformed."""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)


class TokenReplayError(TokenError):
    """Raised when a previously rotated refresh token is reused (replay attack)."""

    def __init__(self, message: str = "Token replay detected"):
        super().__init__(message)


class SessionNotFoundError(AuthError):
    """Raised when a session identifier cannot be resolved in Redis."""

    def __init__(self, message: str = "Session not found or expired"):
        super().__init__(message)


class SessionExpiredError(AuthError):
    """Raised when a session has exceeded its maximum lifetime."""

    def __init__(self, message: str = "Session has expired"):
        super().__init__(message)


class APIKeyError(AuthError):
    """Base exception for API key operations."""


class APIKeyNotFoundError(APIKeyError):
    """Raised when an API key cannot be found by prefix."""

    def __init__(self, message: str = "API key not found"):
        super().__init__(message)


class APIKeyRevokedError(APIKeyError):
    """Raised when an API key has been revoked."""

    def __init__(self, message: str = "API key has been revoked"):
        super().__init__(message)


class APIKeyExpiredError(APIKeyError):
    """Raised when an API key has passed its expiration timestamp."""

    def __init__(self, message: str = "API key has expired"):
        super().__init__(message)


class PermissionDeniedError(AuthError):
    """Raised when an authenticated principal lacks required RBAC role or scope."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)


class ProjectAccessDeniedError(AuthError):
    """Raised when an authenticated principal is not a member of the requested project."""

    def __init__(self, message: str = "Project not found"):
        # Intentionally returns "Project not found" to prevent enumeration
        super().__init__(message)


class RateLimitExceededError(AuthError):
    """Raised when request rate limits are exceeded."""

    def __init__(self, message: str = "Too many requests", retry_after_seconds: int = 60):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)
