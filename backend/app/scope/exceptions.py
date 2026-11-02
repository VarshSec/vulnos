"""Scope and target management exceptions for VulnOS."""

from __future__ import annotations


class ScopeError(Exception):
    """Base exception for all target and scope management errors."""


class TargetNotFoundError(ScopeError):
    """Raised when a requested target does not exist within the specified project."""


class DuplicateTargetError(ScopeError):
    """Raised when a target with the same (project_id, seed_type, seed_value) already exists."""


class TargetArchivedError(ScopeError):
    """Raised when an operation cannot be performed on an archived target."""


class InvalidTargetStateError(ScopeError):
    """Raised when a target state transition or parameter combination is invalid."""


class AuthorizationNotFoundError(ScopeError):
    """Raised when a requested authorization record does not exist within the specified project."""


class DuplicateAuthorizationError(ScopeError):
    """Raised when an authorization record with the same reference already exists in the project."""


class AuthorizationAlreadyRevokedError(ScopeError):
    """Raised when attempting an invalid operation on an already revoked authorization record."""


class AuthorizationImmutableError(ScopeError):
    """Raised when an illegal mutation or modification is attempted on an authorization record."""


class ScopeVersionNotFoundError(ScopeError):
    """Raised when a requested scope version does not exist within the specified project."""


class ScopeVersionImmutableError(ScopeError):
    """Raised when an illegal modification is attempted on an active or superseded scope version."""


class ScopeVersionInvalidStateError(ScopeError):
    """Raised when a scope version lifecycle transition is invalid."""


class AuthorizationNotValidForActivationError(ScopeError):
    """Raised when a scope version cannot be activated.

    Occurs when the associated authorization record is missing, expired, or revoked.
    """


class ScopeRuleValidationError(ScopeError):
    """Raised when scope rule parameters, values, ports, or protocols fail validation."""
