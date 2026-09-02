"""Authorized repository scoping (defense in depth) — task 4.2.

The authorization *policy* layer (:class:`~app.authorization.service.
AuthorizationService`) renders the decision, but a mistake at the service layer
must never be able to widen a query. This module is that second line of defense
(design.md "Repository-level scoping (defense in depth)", R14.2): every
sensitive read is parameterized by the *resolved actor* and the
server-resolved relationship, so even a caller that forgets to check the
decision cannot receive another partner's private rows.

It owns no tables of its own; it wraps the domain reads and, crucially, is the
only place that turns a resource *row* into a
:class:`~app.authorization.models.ResourceDescriptor`. Callers never hand-build
descriptors from client input — they hand this layer a row (or an id + the
actor) and get back either an authorized row or nothing. ``visibility_scope``,
``owner_id`` and ``couple_id`` are always read *from the row*, never inferred
from a ``couple_id`` and never taken from the request (R16.4, R17.1).

Nested containers are filtered child-by-child via :meth:`filter_nested`: each
child is evaluated against *its own* zone, so a couple member never receives the
other partner's private reflection merely because it references the shared
couple (R14.4, R16.4).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization.models import (
    Action,
    AuthenticatedActor,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.couples.models import PrivateReflection

T = TypeVar("T")


def descriptor_for_reflection(row: PrivateReflection) -> ResourceDescriptor:
    """Build a descriptor for a :class:`PrivateReflection` from its row.

    All fields are read from server state: ``visibility_scope`` from the row
    (never inferred from ``couple_id`` — R16.4), ``owner_id`` from the immutable
    ``user_id`` (Pattern A key), and ``couple_id`` as context only. The carried
    ``resource_id`` is for auditing and never influences the decision (R17.1).
    """
    return ResourceDescriptor(
        visibility_scope=row.visibility_scope,
        owner_id=row.user_id,
        couple_id=row.couple_id,
        resource_id=row.id,
        resource_type=PrivateReflection.__name__,
    )


class AuthorizedRepository:
    """Defense-in-depth read layer parameterized by the resolved actor.

    Constructed per request with the request-scoped session and the shared
    :class:`AuthorizationService`. Every read method takes the
    :class:`AuthenticatedActor` and applies the authorization decision *inside*
    the repository, after resolving the resource from server state — so a
    service-layer omission cannot widen results (R14.2).
    """

    def __init__(
        self, session: Session, authorization: AuthorizationService
    ) -> None:
        self._session = session
        self._authz = authorization

    # ------------------------------------------------------------------
    # Descriptor construction from rows (never from client input)
    # ------------------------------------------------------------------
    def describe_reflection(self, row: PrivateReflection) -> ResourceDescriptor:
        """Public helper so callers never hand-build a reflection descriptor."""
        return descriptor_for_reflection(row)

    # ------------------------------------------------------------------
    # Scoped single-resource read
    # ------------------------------------------------------------------
    def get_private_reflection(
        self,
        actor: AuthenticatedActor,
        reflection_id: uuid.UUID,
        action: Action = Action.READ,
    ) -> PrivateReflection | None:
        """Return a private reflection only if the actor is authorized for it.

        The row is resolved from server state by id, its descriptor is built
        *from the row* (not from the supplied id), and the decision is applied
        here. A missing row and an unauthorized row are indistinguishable to the
        caller — both yield ``None`` — so ownership/existence never leaks
        (R17.2, R17.3). Passing a different ``reflection_id`` cannot widen access
        because the descriptor is derived from whatever row (if any) that id
        resolves to (R17.1).
        """
        row = self._session.execute(
            select(PrivateReflection).where(PrivateReflection.id == reflection_id)
        ).scalar_one_or_none()
        if row is None:
            return None

        descriptor = descriptor_for_reflection(row)
        if not self._authz.authorize(actor, action, descriptor).allowed:
            return None
        return row

    def list_authorized_private_reflections(
        self,
        actor: AuthenticatedActor,
        rows: list[PrivateReflection],
        action: Action = Action.READ,
    ) -> list[PrivateReflection]:
        """Filter a set of reflection rows to those the actor may access.

        Each row is evaluated against its own descriptor; this is the concrete
        specialization of :meth:`filter_nested` for reflections.
        """
        return self.filter_nested(
            actor, rows, descriptor_for_reflection, action
        )

    # ------------------------------------------------------------------
    # Nested-resource filtering (R14.4)
    # ------------------------------------------------------------------
    def filter_nested(
        self,
        actor: AuthenticatedActor,
        children: list[T],
        describe: Callable[[T], ResourceDescriptor],
        action: Action = Action.READ,
    ) -> list[T]:
        """Filter container children by evaluating each against ITS OWN zone.

        For every child, a descriptor is built from the child row via
        ``describe`` and the child is kept only when
        ``authorize(actor, action, child_descriptor)`` ALLOWs. Each child is
        judged against its own ``visibility_scope`` — never the container's — so
        a couple member does not receive the other partner's PRIVATE_PARTNER
        reflection just because both hang off the shared couple (R14.4, R16.4).
        Order is preserved and denied children are silently dropped (privacy-
        safe: their existence is never signalled to the caller).
        """
        return [
            child
            for child in children
            if self._authz.authorize(actor, action, describe(child)).allowed
        ]


__all__ = [
    "AuthorizedRepository",
    "descriptor_for_reflection",
]
