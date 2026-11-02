"""VulnOS database package.

Provides declarative models, session lifecycle, engine management,
and PostgreSQL Row-Level Security (RLS) tenant isolation utilities.
"""

from backend.app.db.base import Base
from backend.app.db.session import SessionLocal, create_db_engine, get_db
from backend.app.db.tenant import (
    InvalidTenantContextError,
    MissingTenantContextError,
    TenantContext,
    TenantSecurityError,
    clear_tenant_context,
    get_current_tenant_context,
    get_tenant_db,
    set_tenant_context,
    tenant_context,
)

__all__ = [
    "Base",
    "InvalidTenantContextError",
    "MissingTenantContextError",
    "SessionLocal",
    "TenantContext",
    "TenantSecurityError",
    "clear_tenant_context",
    "create_db_engine",
    "get_current_tenant_context",
    "get_db",
    "get_tenant_db",
    "set_tenant_context",
    "tenant_context",
]
