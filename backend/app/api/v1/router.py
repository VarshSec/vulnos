"""API v1 root router for VulnOS."""

from typing import Any

from fastapi import APIRouter

from backend.app.api.v1.api_keys import api_keys_router
from backend.app.api.v1.auth import auth_router
from backend.app.api.v1.authorizations import authorizations_router
from backend.app.api.v1.scope import scope_router
from backend.app.api.v1.targets import targets_router

api_v1_router = APIRouter(prefix="/api/v1", tags=["api_v1"])

api_v1_router.include_router(auth_router)
api_v1_router.include_router(api_keys_router)
api_v1_router.include_router(targets_router)
api_v1_router.include_router(authorizations_router)
api_v1_router.include_router(scope_router)


@api_v1_router.get("", summary="API v1 root information")
async def api_v1_root() -> dict[str, Any]:
    """Returns v1 metadata and available service milestones."""
    return {
        "version": "v1",
        "service": "VulnOS API",
        "milestone": "P2.1",
        "status": "operational",
    }
