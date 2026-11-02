"""RBAC roles, hierarchy, and permission evaluations for VulnOS."""

from enum import StrEnum
from typing import Final


class ProjectRole(StrEnum):
    """Supported project roles in ascending privilege order."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    OWNER = "owner"


ROLE_LEVELS: Final[dict[str, int]] = {
    ProjectRole.VIEWER: 10,
    ProjectRole.OPERATOR: 20,
    ProjectRole.ADMIN: 30,
    ProjectRole.OWNER: 40,
}


def has_sufficient_role(current_role: str, required_role: str) -> bool:
    """Check whether a user's role meets or exceeds the required role in hierarchy."""
    user_lvl = ROLE_LEVELS.get(current_role, 0)
    req_lvl = ROLE_LEVELS.get(required_role, 999)
    return user_lvl >= req_lvl


def has_api_key_scope(key_scopes: list[str], required_scope: str) -> bool:
    """Verify that an API key possesses the requested scope or administrative scope."""
    if "admin" in key_scopes:
        return True
    return required_scope in key_scopes
