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
from app.api.users import router as users_router

# Aggregate router mounted by the app factory. Domain sub-routers are included
# here (task 12.2): auth (register/login/logout/recovery/reauth), account
# (profile/settings/deletion-request), and couples + invitations. Each route
# runs through the request pipeline (rate limit -> authentication ->
# authorization inside the service) and returns the {"data": ...} envelope.
api_router = APIRouter()


@api_router.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Liveness probe. Non-sensitive; requires no authorization."""
    return {"status": "ok"}


api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(couples_router)


__all__ = ["api_router"]
