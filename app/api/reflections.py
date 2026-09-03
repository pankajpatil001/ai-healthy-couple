"""Private Reflection endpoints (Phase 2).

Owner-only CRUD for a user's private reflections, driven through the request
pipeline (rate limit -> authentication -> authorization inside the service).
Every route requires a resolved :class:`CurrentActor` and returns the
``{"data": ...}`` success envelope. Authorization is decided from server state
alone by :class:`~app.reflections.service.ReflectionService` via the existing
owner-only pipeline: a non-owner — and, identically, a caller naming a
reflection id that does not exist or was deleted — receives a privacy-safe 404,
so a route never confirms a reflection's existence to someone not entitled to
know it (R17.3). No route accepts a client-supplied owner, visibility scope, or
timestamps.

Per the authoritative API contract (03-api-contracts.md §10) there is **no**
collection/list endpoint.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    CurrentActor,
    DbSession,
    RequestId,
    get_reflection_service,
    rate_limit,
)
from app.api.envelope import envelope
from app.reflections.schemas import ReflectionCreate, ReflectionUpdate
from app.reflections.service import ReflectionService

router = APIRouter(prefix="/reflections", tags=["reflections"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_reflection(
    body: ReflectionCreate,
    actor: CurrentActor,
    reflections: Annotated[ReflectionService, Depends(get_reflection_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Create a private reflection owned by the caller.

    The owner is always the authenticated actor; there is no way to name another
    owner. An optional ``couple_id`` is validated as context only (active
    membership required, else privacy-safe 404) and never makes the reflection
    shared. Content is encrypted at rest.
    """
    view = reflections.create_reflection(actor, body, request_id=request_id)
    session.commit()
    return envelope(view)


@router.get(
    "/{reflection_id}",
    dependencies=[Depends(rate_limit("resource-read"))],
)
def get_reflection(
    reflection_id: uuid.UUID,
    actor: CurrentActor,
    reflections: Annotated[ReflectionService, Depends(get_reflection_service)],
    request_id: RequestId,
) -> dict:
    """Return the caller's own reflection (decrypted); else a privacy-safe 404.

    Authorization runs before any decryption: a non-owner or unknown/deleted id
    yields an identical :class:`~app.errors.ResourceNotFoundError`. The
    resource-read rate limit bounds id-enumeration bursts (R17.5).
    """
    view = reflections.get_reflection(actor, reflection_id, request_id=request_id)
    return envelope(view)


@router.patch("/{reflection_id}")
def update_reflection(
    reflection_id: uuid.UUID,
    body: ReflectionUpdate,
    actor: CurrentActor,
    reflections: Annotated[ReflectionService, Depends(get_reflection_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Update the caller's own reflection content; else a privacy-safe 404.

    A non-owner or unknown/deleted reflection yields the identical 404. A deleted
    reflection cannot be resurrected.
    """
    view = reflections.update_reflection(
        actor, reflection_id, body, request_id=request_id
    )
    session.commit()
    return envelope(view)


@router.delete("/{reflection_id}")
def delete_reflection(
    reflection_id: uuid.UUID,
    actor: CurrentActor,
    reflections: Annotated[ReflectionService, Depends(get_reflection_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Delete the caller's own reflection; else a privacy-safe 404.

    Deletion is soft with ciphertext cleared, so the plaintext is unrecoverable
    and the reflection can never be read/updated again. A repeated DELETE yields
    the same privacy-safe 404.
    """
    reflections.delete_reflection(actor, reflection_id, request_id=request_id)
    session.commit()
    return envelope({"status": "deleted"})


__all__ = ["router"]
