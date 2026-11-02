"""Project access verification and membership enforcement for VulnOS.

Enforces:
- Deny-by-default access control.
- Returning 404 / ProjectAccessDeniedError for non-members to prevent project enumeration.
- Role hierarchy verification (viewer -> operator -> admin -> owner).
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.exceptions import PermissionDeniedError, ProjectAccessDeniedError
from backend.app.authorization.permissions import has_sufficient_role
from backend.app.db.models.identity import Project, ProjectMember


def get_project_member_role(
    db: Session,
    project_id: UUID,
    user_id: UUID,
) -> str | None:
    """Retrieve the role of a user in a project, or None if not a member."""
    stmt = select(ProjectMember.role).where(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == user_id,
    )
    return db.scalar(stmt)


def verify_project_access(
    db: Session,
    project_id: UUID,
    user_id: UUID,
    required_role: str = "viewer",
) -> ProjectMember:
    """Verify that a user is an active member of a project with sufficient role.

    Raises:
        ProjectAccessDeniedError: If the user is not a member (treated as 404).
        PermissionDeniedError: If the user is a member but role is insufficient (403).
    """
    stmt = (
        select(ProjectMember)
        .join(Project, ProjectMember.project_id == Project.id)
        .where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id,
            Project.status == "active",
        )
    )
    member = db.scalar(stmt)
    if not member:
        # Non-members receive "Project not found" to prevent project ID existence leaks
        raise ProjectAccessDeniedError("Project not found")

    if not has_sufficient_role(member.role, required_role):
        raise PermissionDeniedError(
            f"Insufficient privileges: requires {required_role!r}, user has {member.role!r}"
        )

    return member
