"""Private Reflection domain (Phase 2).

The first genuine product vertical slice. A Private Reflection is a user's
private note:

* It belongs to exactly one user (``user_id`` — the immutable owner).
* It is ``PRIVATE_PARTNER`` and readable/updatable/deletable **only** by its
  owner. Couple membership — current or former — never grants access
  (07-technology/05-authentication-and-authorization.md §12).
* ``couple_id`` is optional relationship context and never makes the content
  shared (02-database-schema.md §9).
* Content is stored **encrypted at rest** (AES-256-GCM) in
  ``content_ciphertext``; plaintext is never persisted or logged.

The module reuses the existing authorization pipeline (Pattern A owner-only via
:class:`~app.authorization.repository.AuthorizedRepository`) and the encryption
boundary (:mod:`app.crypto`); it adds no new authorization concepts.
"""

from __future__ import annotations

from app.reflections.repository import ReflectionRepository
from app.reflections.schemas import (
    ReflectionCreate,
    ReflectionSummary,
    ReflectionUpdate,
    ReflectionView,
)
from app.reflections.service import (
    REFLECTION_CREATED_EVENT,
    REFLECTION_DELETED_EVENT,
    REFLECTION_LISTED_EVENT,
    REFLECTION_READ_EVENT,
    REFLECTION_RESOURCE_TYPE,
    REFLECTION_UPDATED_EVENT,
    ReflectionService,
)

__all__ = [
    "ReflectionRepository",
    "ReflectionService",
    "ReflectionCreate",
    "ReflectionUpdate",
    "ReflectionView",
    "ReflectionSummary",
    "REFLECTION_CREATED_EVENT",
    "REFLECTION_LISTED_EVENT",
    "REFLECTION_READ_EVENT",
    "REFLECTION_UPDATED_EVENT",
    "REFLECTION_DELETED_EVENT",
    "REFLECTION_RESOURCE_TYPE",
]
