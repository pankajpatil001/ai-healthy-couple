"""Top-level API router package.

Aggregates the domain routers (auth, users, couples) behind a single
``api_router`` that the app factory mounts. Every sensitive endpoint runs
through the request pipeline: rate limiter -> authentication middleware ->
authorization policy layer -> domain service (design: "Layered request
pipeline"). Individual routers are wired in later tasks (task 12).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.couples import router as couples_router
from app.api.reflections import router as reflections_router
from app.api.users import router as users_router

#: Public API version prefix (Phase 2, Decision A). Every domain route is exposed
#: under ``/api/v1`` so a shipped Android client binds to versioned URLs and a
#: future breaking change can be introduced under a new version without stranding
#: old installs. The prefix is applied here, once, at aggregation time — the
#: individual routers stay version-agnostic.
API_V1_PREFIX = "/api/v1"

# Aggregate router mounted by the app factory. The versioned sub-router carries
# the domain routers: auth (register/login/logout/recovery/reauth), account
# (profile/settings/deletion-request), couples + invitations, and private
# reflections. Each route runs through the request pipeline (rate limit ->
# authentication -> authorization inside the service) and returns the
# {"data": ...} envelope. The liveness probe stays unversioned at the root.
api_router = APIRouter()


@api_router.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Liveness probe. Non-sensitive; requires no authorization; unversioned."""
    return {"status": "ok"}


_v1 = APIRouter(prefix=API_V1_PREFIX)
_v1.include_router(auth_router)
_v1.include_router(users_router)
_v1.include_router(couples_router)
_v1.include_router(reflections_router)

api_router.include_router(_v1)


__all__ = ["api_router", "API_V1_PREFIX"]
