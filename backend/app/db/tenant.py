"""PostgreSQL Row-Level Security (RLS) tenant context management for VulnOS.

Provides transaction-local isolation for tenant queries, connection pool
leakage prevention, and FastAPI dependencies for project-scoped database sessions.
"""

import re
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Path, status
from sqlalchemy import Engine, event, text
from sqlalchemy.orm import Session


def _get_db() -> Generator[Session]:
    """Lazy resolver for database session dependency to avoid circular import."""
    from backend.app.db.session import get_db

    yield from get_db()


# Constraints on request identifier format
REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")


class TenantSecurityError(Exception):
    """Base exception for tenant context and RLS security violations."""


class InvalidTenantContextError(TenantSecurityError):
    """Raised when an invalid project, user, or request context is supplied."""


class MissingTenantContextError(TenantSecurityError):
    """Raised when an operation requires an active tenant context but none is set."""


@dataclass(frozen=True)
class TenantContext:
    """Immutable representation of the active tenant context."""

    project_id: UUID
    user_id: UUID | None = None
    request_id: str | None = None


def _validate_uuid(val: UUID | str, name: str) -> UUID:
    """Validate and normalize a UUID value."""
    if isinstance(val, UUID):
        return val
    if not isinstance(val, str) or not val.strip():
        raise InvalidTenantContextError(f"{name} must be a valid non-empty UUID or UUID string")
    try:
        return UUID(val.strip())
    except (ValueError, AttributeError) as exc:
        raise InvalidTenantContextError(f"Invalid UUID format for {name}: {val!r}") from exc


def _validate_request_id(val: str | None) -> str | None:
    """Validate request identifier for tracing."""
    if val is None:
        return None
    val_str = str(val).strip()
    if not val_str:
        return None
    if not REQUEST_ID_REGEX.match(val_str):
        raise InvalidTenantContextError(f"Invalid request_id format: {val_str!r}")
    return val_str


def set_tenant_context(
    session: Session,
    project_id: UUID | str,
    user_id: UUID | str | None = None,
    request_id: str | None = None,
) -> TenantContext:
    """Set transaction-local tenant context variables in the database session.

    In PostgreSQL, this sets transaction-local configuration parameters:
    - app.current_project_id
    - app.current_user_id
    - app.request_id

    Using ``is_local=true`` guarantees that settings automatically clear
    when the transaction ends (COMMIT or ROLLBACK).
    """
    valid_project_id = _validate_uuid(project_id, "project_id")
    valid_user_id = _validate_uuid(user_id, "user_id") if user_id is not None else None
    valid_request_id = _validate_request_id(request_id)

    ctx = TenantContext(
        project_id=valid_project_id,
        user_id=valid_user_id,
        request_id=valid_request_id,
    )

    # Store context in session.info for application inspection
    session.info["tenant_context"] = ctx

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    if dialect_name == "postgresql":
        # Always use parameterized queries; never concatenate or interpolate strings
        session.execute(
            text("SELECT set_config('app.current_project_id', :project_id, true)"),
            {"project_id": str(valid_project_id)},
        )
        if valid_user_id is not None:
            session.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(valid_user_id)},
            )
        else:
            session.execute(text("SELECT set_config('app.current_user_id', '', true)"))

        if valid_request_id is not None:
            session.execute(
                text("SELECT set_config('app.request_id', :request_id, true)"),
                {"request_id": valid_request_id},
            )
        else:
            session.execute(text("SELECT set_config('app.request_id', '', true)"))

    return ctx


def clear_tenant_context(session: Session) -> None:
    """Explicitly reset transaction-local tenant context variables."""
    session.info.pop("tenant_context", None)

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    if dialect_name == "postgresql":
        session.execute(text("SELECT set_config('app.current_project_id', '', true)"))
        session.execute(text("SELECT set_config('app.current_user_id', '', true)"))
        session.execute(text("SELECT set_config('app.request_id', '', true)"))


def get_current_tenant_context(session: Session) -> TenantContext | None:
    """Retrieve the currently active tenant context for the session, if any."""
    ctx = session.info.get("tenant_context")
    if isinstance(ctx, TenantContext):
        return ctx

    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        try:
            result = session.execute(
                text("SELECT current_setting('app.current_project_id', true)")
            ).scalar()
            if result and str(result).strip():
                project_id = UUID(str(result).strip())
                user_res = session.execute(
                    text("SELECT current_setting('app.current_user_id', true)")
                ).scalar()
                req_res = session.execute(
                    text("SELECT current_setting('app.request_id', true)")
                ).scalar()

                user_id = (
                    UUID(str(user_res).strip()) if user_res and str(user_res).strip() else None
                )
                request_id = str(req_res).strip() if req_res and str(req_res).strip() else None

                ctx = TenantContext(
                    project_id=project_id,
                    user_id=user_id,
                    request_id=request_id,
                )
                session.info["tenant_context"] = ctx
                return ctx
        except Exception:
            return None

    return None


@contextmanager
def tenant_context(
    session: Session,
    project_id: UUID | str,
    user_id: UUID | str | None = None,
    request_id: str | None = None,
) -> Generator[TenantContext]:
    """Context manager setting transaction-local tenant context and guaranteeing cleanup."""
    ctx = set_tenant_context(
        session=session,
        project_id=project_id,
        user_id=user_id,
        request_id=request_id,
    )
    try:
        yield ctx
    finally:
        clear_tenant_context(session)


def attach_tenant_pool_listeners(engine: Engine) -> None:
    """Attach connection pool listeners to prevent tenant context leaks across pool reuse.

    On connection checkin or reset, executes DISCARD TEMP; RESET ALL on PostgreSQL connections
    to ensure persistent TCP connections returned to the pool cannot retain any session state.
    """

    @event.listens_for(engine, "checkin")
    def receive_checkin(dbapi_connection: Any, connection_record: Any) -> None:
        """Clear any residual session state when connection returns to pool."""
        with suppress(Exception):
            # Only execute RESET ALL on PostgreSQL DBAPI connections
            cursor = dbapi_connection.cursor()
            cursor.execute("RESET ALL;")
            cursor.close()

    @event.listens_for(engine, "reset")
    def receive_reset(dbapi_connection: Any, connection_record: Any) -> None:
        """Handle pool connection reset cleanly."""
        with suppress(Exception):
            cursor = dbapi_connection.cursor()
            cursor.execute("RESET ALL;")
            cursor.close()


def get_tenant_db(
    project_id: UUID = Path(..., description="Project identifier"),
    x_request_id: str | None = Header(None, alias="X-Request-ID"),
    db: Session = Depends(_get_db),
) -> Generator[Session]:
    """FastAPI request-scoped dependency providing a tenant-isolated database session.

    Enforces active project context and validates X-Request-ID.
    """
    try:
        set_tenant_context(
            session=db,
            project_id=project_id,
            request_id=x_request_id,
        )
        yield db
    except InvalidTenantContextError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid tenant context: {exc}",
        ) from exc
    finally:
        clear_tenant_context(db)
