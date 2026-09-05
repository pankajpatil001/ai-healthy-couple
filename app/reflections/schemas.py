"""Private Reflection request/response schemas (Pydantic).

Only client-supplied, product-mutable fields are modelled. Everything that is
server-controlled — ``id``, ``user_id`` (owner), ``visibility_scope``
(always PRIVATE_PARTNER), timestamps, ``deleted_at`` — is **never** accepted
from a client and is set server-side. ``extra="forbid"`` turns any attempt to
smuggle such a field into a loud validation error rather than a silent no-op,
mirroring the discipline in :mod:`app.users.schemas` / :mod:`app.couples.schemas`.

The decrypted ``content`` appears **only** in :class:`ReflectionView`, which is
returned exclusively to the authenticated owner (the authorization check in
:class:`~app.reflections.service.ReflectionService` guarantees that).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

#: Upper bound on reflection content length (characters). Generous for a private
#: journal entry while bounding request size and ciphertext growth.
MAX_CONTENT_LENGTH = 50_000


class ReflectionCreate(BaseModel):
    """Payload to create a private reflection (POST /api/v1/reflections).

    The authenticated user is always the owner — there is no ``user_id`` field
    (R6.4 style: a client can never name another owner). ``couple_id`` is
    optional relationship context only; supplying it never makes the reflection
    shared and the content stays PRIVATE_PARTNER (02-database-schema.md §9).
    """

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=MAX_CONTENT_LENGTH)
    couple_id: uuid.UUID | None = None


class ReflectionUpdate(BaseModel):
    """Payload to update a private reflection's content (PATCH).

    Only ``content`` is mutable. ``couple_id``, ``visibility_scope``, ownership,
    and timestamps are not client-settable, so they are absent here and
    ``extra="forbid"`` rejects any attempt to include them.
    """

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=MAX_CONTENT_LENGTH)


class ReflectionView(BaseModel):
    """A private reflection as returned to its owner.

    Carries the **decrypted** ``content`` — returned only after the owner-only
    authorization check passes. ``visibility_scope`` is intentionally omitted
    from the wire view (it is always PRIVATE_PARTNER) to avoid implying it is a
    tunable field; ``couple_id`` is echoed back as context.
    """

    model_config = ConfigDict(from_attributes=False)

    id: uuid.UUID
    couple_id: uuid.UUID | None = None
    content: str
    created_at: datetime
    updated_at: datetime


class ReflectionSummary(BaseModel):
    """Lightweight metadata for a reflection in the owner's list.

    Deliberately **content-free**: the list endpoint returns only identifying
    metadata so it never decrypts every reflection (decryption stays on the
    single-item GET path, after authorization). The full decrypted ``content``
    is fetched per item via ``GET /reflections/{id}``.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    couple_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


__all__ = [
    "ReflectionCreate",
    "ReflectionUpdate",
    "ReflectionView",
    "ReflectionSummary",
    "MAX_CONTENT_LENGTH",
]
