"""Authorization policy layer.

:class:`AuthorizationService` renders a single ALLOW / DENY :class:`Decision`
per sensitive request by running the pipeline from the design's "Authorization
Design" section (06-authorization-matrix.md §7), fail-closed at every step:

    1. account ACTIVE?                          -> else DENY (R7.2, R7.3, R3.6)
    2. resolve resource + owner + visibility_scope from server state (R14.1, R14.2)
    3. lifecycle check (couple ACTIVE vs DISCONNECTED) (R13.4)
    4. apply the zone rule (Patterns below)
    5. undecidable                              -> DENY (R15.2 default-deny)

Reference patterns (design "Authorization layer" / the four visibility zones):

* **Pattern A — PRIVATE_PARTNER**: ALLOW only if ``actor == owner`` (R15.3,
  R16.1–R16.4). Membership in a couple is explicitly *insufficient* for private
  access (R16.2).
* **Pattern B — SHARED_COUPLE**: ALLOW only if the actor is an *active* member
  of an *ACTIVE* couple (R15.4, R13.4). A former partner of a DISCONNECTED
  couple, or a non-member, is denied.
* **SYSTEM_ONLY** -> DENY for normal users (R15.5).
* **PROFESSIONAL_SHARED** -> DENY in the Foundation; the consent workflow is out
  of scope (R15.6).

Two invariants shape the implementation:

* ``visibility_scope`` is taken from the resource row (carried on the
  :class:`~app.authorization.models.ResourceDescriptor`); the service NEVER
  infers "shared" from the presence of a ``couple_id`` (R16.4).
* All relationship facts (active membership, couple status) are resolved from
  server state via a :class:`RelationshipResolver`; client-supplied identifiers
  and identity claims are untrusted and never influence the decision (R14.2,
  R17.1).

The service is a pure decision function over injected server state, so it is
exhaustively unit- and property-testable without a live database. Wiring the
resolver to the authorized repository / SQLAlchemy is task 4.2; mapping the
Decision's ``http_hint`` to concrete 401/403/404 responses is task 4.3.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from app.authorization.models import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    Action,
    AuthenticatedActor,
    Decision,
    DenyReason,
    ResourceDescriptor,
)
from app.enums import Couple_Status, Member_Status, Visibility_Scope


class RelationshipResolver(Protocol):
    """Server-side source of the relationship facts Pattern B needs.

    The pipeline asks this resolver, never the client, whether an actor is an
    active member of a couple and what that couple's lifecycle status is
    (R14.2). Task 4.2 implements this against the authorized repository /
    PostgreSQL; tests provide an in-memory implementation.
    """

    def get_member_status(
        self, couple_id: uuid.UUID, user_id: uuid.UUID
    ) -> Member_Status | None:
        """Return the actor's membership status in the couple, or ``None``.

        ``None`` means the user has no membership row for that couple (a
        non-member). A returned status is the authoritative, server-side
        membership state.
        """
        ...

    def get_couple_status(self, couple_id: uuid.UUID) -> Couple_Status | None:
        """Return the couple's lifecycle status, or ``None`` if it doesn't exist."""
        ...


class AuthorizationService:
    """Default-deny authorization policy layer (design "Authorization layer").

    Stateless apart from an injected :class:`RelationshipResolver`; every
    :meth:`authorize` call is a pure function of the actor, action, resource
    descriptor and the server-resolved relationship facts. A valid session is
    never sufficient on its own — the pipeline runs on every sensitive request
    (R14.3).
    """

    def __init__(self, resolver: RelationshipResolver) -> None:
        self._resolver = resolver

    # ------------------------------------------------------------------
    # Pipeline entry point
    # ------------------------------------------------------------------
    def authorize(
        self,
        actor: AuthenticatedActor,
        action: Action,
        resource: ResourceDescriptor | None,
    ) -> Decision:
        """Render a single ALLOW / DENY decision for a sensitive request.

        Runs the five-step pipeline fail-closed. ``action`` is carried for
        auditing / future refinement; the Foundation zone rules gate read and
        write identically (R16.1–R16.3). A ``None`` ``resource`` means the
        resource could not be resolved from server state and is treated as a
        privacy-safe not-found (default-deny, R15.2).
        """
        # Step 1 — account ACTIVE? SUSPENDED/DELETED fail closed before any
        # resource is resolved (R7.2, R7.3, R3.6).
        if not actor.is_account_active:
            return Decision.deny(DenyReason.ACCOUNT_NOT_ACTIVE, HTTP_FORBIDDEN)

        # Step 2 — the caller resolves the resource + owner + visibility_scope
        # from server state and passes a descriptor. A missing resource is a
        # privacy-safe not-found (R14.1, R17.3).
        if resource is None:
            return Decision.deny(DenyReason.RESOURCE_NOT_FOUND, HTTP_NOT_FOUND)

        # Steps 3-5 — lifecycle + zone rule, dispatched on the row's own
        # visibility_scope (never inferred from couple_id — R16.4).
        return self._apply_zone_rule(actor, resource)

    # ------------------------------------------------------------------
    # Zone rule dispatch (steps 3-5)
    # ------------------------------------------------------------------
    def _apply_zone_rule(
        self, actor: AuthenticatedActor, resource: ResourceDescriptor
    ) -> Decision:
        """Dispatch on the resource's own visibility_scope; default-deny otherwise."""
        scope = resource.visibility_scope

        if scope == Visibility_Scope.PRIVATE_PARTNER:
            return self._pattern_a_private_partner(actor, resource)
        if scope == Visibility_Scope.SHARED_COUPLE:
            return self._pattern_b_shared_couple(actor, resource)
        if scope == Visibility_Scope.SYSTEM_ONLY:
            # R15.5 — never reachable by a normal user.
            return Decision.deny(DenyReason.SYSTEM_ONLY, HTTP_NOT_FOUND)
        if scope == Visibility_Scope.PROFESSIONAL_SHARED:
            # R15.6 — consent workflow out of scope in the Foundation.
            return Decision.deny(DenyReason.PROFESSIONAL_SHARED, HTTP_NOT_FOUND)

        # Step 5 — unclassifiable / uncertain: default-deny (R15.2).
        return Decision.deny(DenyReason.UNDECIDABLE, HTTP_NOT_FOUND)

    # ------------------------------------------------------------------
    # Reference Pattern A — PRIVATE_PARTNER (R15.3, R16.1-R16.4)
    # ------------------------------------------------------------------
    def _pattern_a_private_partner(
        self, actor: AuthenticatedActor, resource: ResourceDescriptor
    ) -> Decision:
        """ALLOW only if the actor is the resource owner.

        Ownership is the sole gate: couple membership, the presence of a
        ``couple_id``, or any client-supplied id are all irrelevant (R16.2,
        R16.3, R16.4). A non-owner receives a privacy-safe not-found so that
        existence/ownership is never disclosed (R17.2, R17.3).
        """
        if resource.owner_id is not None and resource.owner_id == actor.user_id:
            return Decision.allow()
        return Decision.deny(DenyReason.NOT_OWNER, HTTP_NOT_FOUND)

    # ------------------------------------------------------------------
    # Reference Pattern B — SHARED_COUPLE (R15.4, R13.4)
    # ------------------------------------------------------------------
    def _pattern_b_shared_couple(
        self, actor: AuthenticatedActor, resource: ResourceDescriptor
    ) -> Decision:
        """ALLOW only for an active member of an ACTIVE couple.

        Both conditions are resolved from server state, never from the request
        (R14.2). A resource with no ``couple_id`` cannot satisfy Pattern B and
        is denied as a non-member case. Lifecycle is checked so a former partner
        of a DISCONNECTED couple (or a still-PENDING couple) is denied (R13.4,
        R13.5); a non-member is denied as not-a-member.
        """
        couple_id = resource.couple_id
        if couple_id is None:
            # Shared scope with no couple to anchor membership: cannot be an
            # active member -> privacy-safe not-found.
            return Decision.deny(DenyReason.NOT_ACTIVE_MEMBER, HTTP_NOT_FOUND)

        # Lifecycle (step 3): the couple must be ACTIVE. A missing couple, or one
        # that is PENDING/DISCONNECTED, denies collaborative access (R13.4).
        couple_status = self._resolver.get_couple_status(couple_id)
        if couple_status != Couple_Status.ACTIVE:
            return Decision.deny(DenyReason.COUPLE_NOT_ACTIVE, HTTP_NOT_FOUND)

        # Membership (step 4, Pattern B): the actor must be an ACTIVE member.
        member_status = self._resolver.get_member_status(couple_id, actor.user_id)
        if member_status != Member_Status.ACTIVE:
            return Decision.deny(DenyReason.NOT_ACTIVE_MEMBER, HTTP_NOT_FOUND)

        return Decision.allow()


__all__ = ["AuthorizationService", "RelationshipResolver"]
