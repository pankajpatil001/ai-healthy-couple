"""Private Reflection service — orchestration, authorization, and audit.

The service is the single orchestration point for the reflection lifecycle. It
enforces the critical layering:

    authorize FIRST (owner-only), then decrypt/mutate.

Read/update/delete all resolve the target row through
:meth:`~app.authorization.repository.AuthorizedRepository.get_private_reflection`,
which returns ``None`` for a missing row *and* for a row the actor does not own
— the two are indistinguishable, so ownership/existence never leaks (R17.2,
R17.3). Only after that authorized resolution succeeds does the service ask the
:class:`~app.reflections.repository.ReflectionRepository` to decrypt or mutate
content. An unauthorized caller therefore never causes protected ciphertext to
be decrypted.

Create validates an optional ``couple_id`` as *context only*: if supplied, the
actor must be an active member of that couple (else a privacy-safe not-found),
but the reflection is still PRIVATE_PARTNER and never shared.

Every operation records a content-free audit event (event type + resource id +
outcome); reflection plaintext is never placed in audit metadata.
"""

from __future__ import annotations

import uuid

from app.audit.service import AuditService
from app.authorization.models import Action, AuthenticatedActor
from app.authorization.repository import AuthorizedRepository
from app.couples.repository import CoupleRepository
from app.errors import ResourceNotFoundError
from app.reflections.repository import ReflectionRepository
from app.reflections.schemas import (
    ReflectionCreate,
    ReflectionUpdate,
    ReflectionView,
)

# ---------------------------------------------------------------------------
# Audit vocabulary — content-free event types.
# ---------------------------------------------------------------------------

#: Recorded when a reflection is created.
REFLECTION_CREATED_EVENT = "REFLECTION_CREATED"
#: Recorded when a reflection is read by its owner.
REFLECTION_READ_EVENT = "REFLECTION_READ"
#: Recorded when a reflection's content is updated.
REFLECTION_UPDATED_EVENT = "REFLECTION_UPDATED"
#: Recorded when a reflection is deleted.
REFLECTION_DELETED_EVENT = "REFLECTION_DELETED"

#: Audit resource type label (structural only).
REFLECTION_RESOURCE_TYPE = "PrivateReflection"


class ReflectionService:
    """Own-reflection create/read/update/delete with owner-only authorization.

    Collaborators are injected so the service is decoupled and testable:

    * ``reflection_repository`` — encrypts/decrypts at the persistence boundary
      and owns soft-delete.
    * ``authorized_repository`` — resolves a reflection row for an actor with the
      owner-only decision applied *inside* (defense in depth); returns ``None``
      for missing or unauthorized.
    * ``couple_repository`` — used only to validate an optional ``couple_id`` on
      create (active-membership check). Reflections are never shared.
    * ``audit_service`` — records content-free lifecycle events.
    """

    def __init__(
        self,
        *,
        reflection_repository: ReflectionRepository,
        authorized_repository: AuthorizedRepository,
        couple_repository: CoupleRepository,
        audit_service: AuditService,
    ) -> None:
        self._reflections = reflection_repository
        self._authz_repo = authorized_repository
        self._couples = couple_repository
        self._audit = audit_service

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_reflection(
        self,
        actor: AuthenticatedActor,
        payload: ReflectionCreate,
        *,
        request_id: str | None = None,
    ) -> ReflectionView:
        """Create a private reflection owned by ``actor``.

        The owner is always the server-resolved actor — never a client value. If
        ``couple_id`` is supplied it is validated as context: the actor must be
        an active member of that couple, otherwise a privacy-safe
        :class:`~app.errors.ResourceNotFoundError` is raised (a guessed couple id
        cannot widen anything, and the reflection stays PRIVATE_PARTNER
        regardless). Content is encrypted at the persistence boundary.
        """
        couple_id = payload.couple_id
        if couple_id is not None:
            membership = self._couples.get_active_membership(couple_id, actor.user_id)
            if membership is None:
                # Non-member or non-existent couple — identical privacy-safe 404.
                raise ResourceNotFoundError()

        row = self._reflections.create(
            owner_id=actor.user_id,
            plaintext=payload.content,
            couple_id=couple_id,
        )

        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=REFLECTION_CREATED_EVENT,
            resource_type=REFLECTION_RESOURCE_TYPE,
            resource_id=row.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return ReflectionView(
            id=row.id,
            couple_id=row.couple_id,
            content=payload.content,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_reflection(
        self,
        actor: AuthenticatedActor,
        reflection_id: uuid.UUID,
        *,
        request_id: str | None = None,
    ) -> ReflectionView:
        """Return the actor's own reflection (decrypted), else a privacy-safe 404.

        Authorization runs first: :meth:`AuthorizedRepository.get_private_reflection`
        returns ``None`` for a missing row and for a row owned by anyone else
        (indistinguishable). Only on an authorized hit is the content decrypted.
        """
        row = self._authz_repo.get_private_reflection(
            actor, reflection_id, Action.READ
        )
        if row is None or row.deleted_at is not None:
            # Missing, unauthorized, or soft-deleted are all indistinguishable
            # privacy-safe not-found. The owner-only decision is applied by the
            # authorized repository; the deleted-row check is the domain's
            # (the shared authorization helper is deletion-agnostic).
            raise ResourceNotFoundError()

        content = self._reflections.decrypt_content(row)
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=REFLECTION_READ_EVENT,
            resource_type=REFLECTION_RESOURCE_TYPE,
            resource_id=row.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return ReflectionView(
            id=row.id,
            couple_id=row.couple_id,
            content=content,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_reflection(
        self,
        actor: AuthenticatedActor,
        reflection_id: uuid.UUID,
        payload: ReflectionUpdate,
        *,
        request_id: str | None = None,
    ) -> ReflectionView:
        """Update the actor's own reflection content; else a privacy-safe 404.

        Authorization runs first (owner-only). A soft-deleted reflection resolves
        as absent, so update can never resurrect deleted content. On success the
        new content is re-encrypted at the persistence boundary.
        """
        row = self._authz_repo.get_private_reflection(
            actor, reflection_id, Action.UPDATE
        )
        if row is None or row.deleted_at is not None:
            # A soft-deleted reflection resolves as absent, so update can never
            # resurrect deleted content.
            raise ResourceNotFoundError()

        updated = self._reflections.update_content(row, plaintext=payload.content)
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=REFLECTION_UPDATED_EVENT,
            resource_type=REFLECTION_RESOURCE_TYPE,
            resource_id=updated.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return ReflectionView(
            id=updated.id,
            couple_id=updated.couple_id,
            content=payload.content,
            created_at=updated.created_at,
            updated_at=updated.updated_at,
        )

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_reflection(
        self,
        actor: AuthenticatedActor,
        reflection_id: uuid.UUID,
        *,
        request_id: str | None = None,
    ) -> None:
        """Delete the actor's own reflection; else a privacy-safe 404.

        Authorization runs first (owner-only). Deletion is soft: ``deleted_at``
        is stamped and ciphertext cleared, so the plaintext is unrecoverable and
        the row can never be read/updated again. Because a soft-deleted row
        resolves as absent, a repeated DELETE from the owner yields the same
        privacy-safe 404 — safe and non-resurrecting.
        """
        row = self._authz_repo.get_private_reflection(
            actor, reflection_id, Action.DELETE
        )
        if row is None or row.deleted_at is not None:
            # Already-deleted (or missing/unauthorized) -> identical privacy-safe
            # 404, so a repeated DELETE is safe and non-resurrecting.
            raise ResourceNotFoundError()

        self._reflections.soft_delete(row)
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=REFLECTION_DELETED_EVENT,
            resource_type=REFLECTION_RESOURCE_TYPE,
            resource_id=reflection_id,
            outcome="SUCCESS",
            request_id=request_id,
        )


__all__ = [
    "ReflectionService",
    "REFLECTION_CREATED_EVENT",
    "REFLECTION_READ_EVENT",
    "REFLECTION_UPDATED_EVENT",
    "REFLECTION_DELETED_EVENT",
    "REFLECTION_RESOURCE_TYPE",
]
