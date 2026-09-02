"""Couples module services.

Design "Couples module":
- CoupleService: couple creation and lifecycle, at-most-one-ACTIVE-couple rule,
  disconnect flow. Couple creation + get_couple are task 9.1; the disconnect
  flow (:meth:`CoupleService.disconnect_couple`) is task 9.2.
- InvitationService: single-purpose, time-limited invitations storing only a
  token hash; accept/decline/cancel/expire handled atomically. Implemented in
  task 10.

CoupleService (task 9.1) implements:

* :meth:`CoupleService.create_couple` — R9.1: an actor with no ACTIVE couple
  gets a new :class:`~app.couples.models.Couple` in ``PENDING`` and is enrolled
  as a ``PARTNER_A`` ``ACTIVE`` :class:`~app.couples.models.CoupleMember`, in one
  transaction. R9.2/R9.3: an actor who already has an ACTIVE couple is rejected —
  the authoritative guard is the partial unique index on
  ``couple_members(user_id) WHERE status = 'ACTIVE'``, surfaced by the repository
  as :class:`~app.errors.ActiveCoupleExistsError` (holds even under a concurrent
  create). R9.5: a content-free ``COUPLE_CREATED`` audit event is recorded.
  R9.4: the couple is treated strictly as an authorization relationship, never
  an account identity — this service creates only relationship rows and holds no
  identity semantics.
* :meth:`CoupleService.get_couple` — R17.3: a couple is returned only to an
  active member; a non-member (or a caller naming a couple that does not exist)
  receives an identical :class:`~app.errors.ResourceNotFoundError` (404,
  Privacy_Safe_Response) that never confirms the couple's existence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.audit.service import AuditService
from app.auth.service import (
    AuthenticationService,
    ReauthToken,
    Sensitive_Operation,
)
from app.authorization.models import AuthenticatedActor
from app.config import Settings, get_settings
from app.couples import tokens
from app.couples.models import CoupleInvitation
from app.couples.repository import CoupleRepository
from app.couples.schemas import CoupleView, RawInvitationToken
from app.enums import Couple_Status, Invitation_Status
from app.errors import (
    AuthorizationError,
    ReauthRequiredError,
    ResourceNotFoundError,
)

# ---------------------------------------------------------------------------
# Audit vocabulary (design.md "CoupleService")
# ---------------------------------------------------------------------------

#: Recorded when a couple is created (R9.5). Metadata is content-free.
COUPLE_CREATED_EVENT = "COUPLE_CREATED"

#: Recorded when a couple is disconnected (R13.6). Metadata is content-free.
COUPLE_DISCONNECTED_EVENT = "COUPLE_DISCONNECTED"

#: Recorded when an invitation is created (R10.6). Metadata is content-free.
INVITATION_CREATED_EVENT = "INVITATION_CREATED"

#: Recorded when an invitation is accepted (R11.7). Metadata is content-free.
INVITATION_ACCEPTED_EVENT = "INVITATION_ACCEPTED"

#: Recorded when the invitee declines an invitation (R12.5). Content-free.
INVITATION_DECLINED_EVENT = "INVITATION_DECLINED"

#: Recorded when the inviter cancels an invitation (R12.5). Content-free.
INVITATION_REVOKED_EVENT = "INVITATION_REVOKED"

#: Recorded when a due invitation is lazily expired on access (R12.5).
INVITATION_EXPIRED_EVENT = "INVITATION_EXPIRED"

#: Audit resource type for couple events (structural label only).
COUPLE_RESOURCE_TYPE = "Couple"

#: Audit resource type for invitation events (structural label only).
INVITATION_RESOURCE_TYPE = "CoupleInvitation"


class InviteeIdentifierLookup(Protocol):
    """Server-side map from an authenticated actor to their auth identifier.

    Declining an invitation requires proving the actor *is* the intended
    invitee. The invitee is recorded on the invitation as
    :attr:`~app.couples.models.CoupleInvitation.invitee_identifier` — the same
    coordinate a :class:`~app.users.models.User` is registered under
    (``auth_identifier``). The actor, by contrast, is trusted only as a
    server-resolved ``user_id`` (R14.2/R17.1). To compare the two we resolve the
    actor's own identifier from server state; nothing about the invitee is ever
    taken from the request.

    :class:`~app.users.repository.UserRepository` satisfies this Protocol
    (``get_by_id`` returns a row whose ``auth_identifier`` is the actor's
    identifier), so the service can be wired with the real repository without a
    hard dependency on the users module.
    """

    def get_by_id(self, user_id: uuid.UUID):  # pragma: no cover - structural
        """Return an object exposing ``auth_identifier`` for ``user_id``, or None."""
        ...


class CoupleService:
    """Couple creation, membership resolution, and (later) lifecycle.

    Collaborators are injected so the service is decoupled and testable:

    * ``couple_repository`` — the only path to the ``couples`` /
      ``couple_members`` tables; owns the atomic create + the
      at-most-one-ACTIVE-couple database guard.
    * ``audit_service`` — records the ``COUPLE_CREATED`` event with minimal,
      content-free metadata (R9.5).
    """

    def __init__(
        self,
        *,
        couple_repository: CoupleRepository,
        audit_service: AuditService,
        authentication_service: AuthenticationService | None = None,
    ) -> None:
        self._couples = couple_repository
        self._audit = audit_service
        # Required only for the disconnect flow (a Sensitive_Operation gated by
        # re-authentication, R5.3/R13.2). Creation/reads do not need it, so it is
        # optional at construction and asserted at the point of use.
        self._auth = authentication_service

    # ------------------------------------------------------------------
    # Creation (R9.1, R9.2, R9.3, R9.4, R9.5)
    # ------------------------------------------------------------------

    def create_couple(
        self,
        actor: AuthenticatedActor,
        *,
        request_id: str | None = None,
    ) -> CoupleView:
        """Create a PENDING couple for ``actor`` and enrol them as PARTNER_A.

        R9.1: creates a :class:`~app.couples.models.Couple` with
        ``Couple_Status.PENDING`` and adds the creating user as a
        :class:`~app.couples.models.CoupleMember` with ``role = PARTNER_A`` and
        ``status = ACTIVE`` in a single transaction. R9.2/R9.3: if the actor
        already has an ACTIVE couple the create is rejected — enforcement is the
        partial unique index (the repository raises
        :class:`~app.errors.ActiveCoupleExistsError`), so the rule holds even
        against a concurrent second create where a read-then-write pre-check
        would race. R9.5: a content-free ``COUPLE_CREATED`` audit event is
        recorded on success. R9.4: only relationship rows are written — the
        couple carries no account identity.

        Returns a :class:`CoupleView` of the created couple. The couple id is
        the server-controlled actor identity (``actor.user_id``); no
        client-supplied identifier participates (R14.2).
        """
        couple = self._couples.create_couple_with_creator(actor.user_id)

        # R9.5: audit the creation with content-free metadata only. Raising the
        # audit before the caller commits keeps the event within the same
        # transaction so it cannot be recorded for a couple that never persists.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=COUPLE_CREATED_EVENT,
            resource_type=COUPLE_RESOURCE_TYPE,
            resource_id=couple.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return CoupleView.model_validate(couple)

    # ------------------------------------------------------------------
    # Read (R17.3 — privacy-safe not-found for non-members)
    # ------------------------------------------------------------------

    def get_couple(
        self, actor: AuthenticatedActor, couple_id: uuid.UUID
    ) -> CoupleView:
        """Return a couple only to an active member; else a privacy-safe 404.

        Access is decided from server state alone: the actor must have an ACTIVE
        :class:`~app.couples.models.CoupleMember` row in the requested couple. A
        non-member — and, identically, a caller naming a ``couple_id`` that does
        not exist — receives the same :class:`~app.errors.ResourceNotFoundError`
        (404, Privacy_Safe_Response). The two cases are deliberately
        indistinguishable so the response never confirms whether the couple
        exists (R17.3). The client-supplied ``couple_id`` is untrusted input: it
        only ever *narrows* to a row the actor already actively belongs to, so a
        guessed or swapped id cannot widen access (R17.1).
        """
        membership = self._couples.get_active_membership(couple_id, actor.user_id)
        if membership is None:
            # Non-member or non-existent couple — identical privacy-safe result.
            raise ResourceNotFoundError()

        couple = self._couples.get_couple(couple_id)
        if couple is None:  # pragma: no cover - membership implies existence
            raise ResourceNotFoundError()
        return CoupleView.model_validate(couple)

    # ------------------------------------------------------------------
    # Disconnect (R13.2, R13.3, R13.6, R13.7 — a Sensitive_Operation, R5.3)
    # ------------------------------------------------------------------

    def disconnect_couple(
        self,
        actor: AuthenticatedActor,
        couple_id: uuid.UUID,
        reauth_grant: ReauthToken,
        *,
        request_id: str | None = None,
    ) -> CoupleView:
        """Disconnect an ACTIVE couple after re-authentication (R13.2).

        Disconnect is a :class:`~app.auth.service.Sensitive_Operation`
        (``COUPLE_DISCONNECTION``, R5.3), so two independent server-side gates
        must both pass before anything is written:

        1. **Active membership.** ``actor`` must hold an ACTIVE
           :class:`~app.couples.models.CoupleMember` row in ``couple_id``.
           A non-member — or a caller naming a couple that does not exist —
           receives an identical :class:`~app.errors.ResourceNotFoundError`
           (404, Privacy_Safe_Response) that never confirms the couple's
           existence (R17.3 style). This is checked *first* so the re-auth gate
           can never leak whether a couple exists to a non-member.
        2. **Re-authentication.** A valid, single-use re-auth grant minted for
           ``COUPLE_DISCONNECTION`` and belonging to ``actor`` must be presented;
           :meth:`~app.auth.service.AuthenticationService.consume_reauthentication`
           consumes it. Session possession alone is never sufficient (R5.1); a
           missing, wrong-operation, replayed, or expired grant raises
           :class:`~app.errors.ReauthRequiredError` (403, R5.2/R13.2).

        On success the repository, in one transaction (R13.2), sets
        ``Couple.status = DISCONNECTED`` (with ``disconnected_at``) and both
        :class:`CoupleMember` rows to ``DISCONNECTED`` (with ``left_at``); only
        an ACTIVE couple is eligible. The status transition is server-controlled
        only — this method accepts no client-supplied status (R13.7).

        R13.3 (disable new collaborative writes to the couple's SHARED_COUPLE
        resources) is satisfied *without additional code here*: once the couple
        is DISCONNECTED, the authorization pipeline's Pattern B lifecycle check
        denies every SHARED_COUPLE access whose couple is not ACTIVE
        (:class:`~app.authorization.models.DenyReason.COUPLE_NOT_ACTIVE`). There
        is no write path to a SHARED_COUPLE resource that bypasses that check, so
        flipping the status is the whole enforcement — a former partner's new
        collaborative write fails closed (R13.3, R13.4).

        A content-free ``COUPLE_DISCONNECTED`` audit event is recorded on success
        (R13.6).
        """
        # Gate 1 (first, so re-auth failures cannot leak existence to a
        # non-member): the actor must be an ACTIVE member. Non-member and
        # non-existent couple are the same privacy-safe 404 (R17.3).
        membership = self._couples.get_active_membership(couple_id, actor.user_id)
        if membership is None:
            raise ResourceNotFoundError()

        # Gate 2: consume a fresh re-auth grant for COUPLE_DISCONNECTION. Session
        # possession is never enough for a Sensitive_Operation (R5.1/R5.3); a
        # missing/invalid/replayed grant denies with 403 (R5.2, R13.2).
        if self._auth is None:  # pragma: no cover - misconfiguration guard
            raise ReauthRequiredError()
        reauthenticated = self._auth.consume_reauthentication(
            reauth_grant, actor, Sensitive_Operation.COUPLE_DISCONNECTION
        )
        if not reauthenticated:
            raise ReauthRequiredError()

        # Atomic lifecycle transition (R13.2). Only an ACTIVE couple disconnects;
        # the repository row-locks and re-checks ACTIVE under the lock so a
        # concurrent accept/disconnect cannot leave an inconsistent state.
        couple = self._couples.disconnect_couple_atomic(couple_id)

        # R13.6: content-free audit of the disconnect. Recorded before the caller
        # commits so it lives in the same transaction as the status change.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=COUPLE_DISCONNECTED_EVENT,
            resource_type=COUPLE_RESOURCE_TYPE,
            resource_id=couple.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return CoupleView.model_validate(couple)


class InvitationService:
    """Create single-purpose, time-limited couple invitations (task 10.1).

    This slice implements :meth:`create_invitation` (R10.1, R10.2, R10.4, R10.5,
    R10.6) and :meth:`accept_invitation` (R11.1–R11.7); decline/cancel/expire are
    later tasks.

    Collaborators are injected:

    * ``couple_repository`` — the only path to the ``couples`` /
      ``couple_members`` / ``couple_invitations`` tables; owns the invitation
      insert and the both-roles-filled query.
    * ``audit_service`` — records the content-free ``INVITATION_CREATED`` event
      (R10.6).
    * ``settings`` — supplies the invitation TTL used to compute a future
      ``expires_at`` (R10.2); defaults to the process settings.

    The token primitives live in :mod:`app.couples.tokens` and are reused here so
    the "store only a hash, return the raw value once" invariant (R10.1) is
    enforced in exactly one place.
    """

    def __init__(
        self,
        *,
        couple_repository: CoupleRepository,
        audit_service: AuditService,
        settings: Settings | None = None,
        user_lookup: InviteeIdentifierLookup | None = None,
    ) -> None:
        self._couples = couple_repository
        self._audit = audit_service
        self._settings = settings or get_settings()
        # Required only by decline_invitation, which must confirm the actor is
        # the intended invitee by resolving the actor's own auth identifier from
        # server state (never from the request). Optional at construction so the
        # create/accept slice can be wired without it; asserted at point of use.
        self._user_lookup = user_lookup

    def create_invitation(
        self,
        actor: AuthenticatedActor,
        couple_id: uuid.UUID,
        invitee_ref: str,
        *,
        request_id: str | None = None,
    ) -> RawInvitationToken:
        """Create a PENDING invitation for ``couple_id`` and return the raw token.

        Only an **ACTIVE member of a PENDING couple** may invite (R10.1). Access
        is decided from server state alone and fails closed:

        * A caller who is not an ACTIVE member of the couple — and, identically,
          a caller naming a ``couple_id`` that does not exist — receives a
          privacy-safe :class:`~app.errors.ResourceNotFoundError` (404) that
          never confirms the couple's existence (R17.3 style). The client-
          supplied ``couple_id`` only ever narrows to a couple the actor already
          actively belongs to, so a guessed id cannot widen access (R17.1).
        * If the couple exists and the actor is a member but the couple is not
          PENDING (already ACTIVE or DISCONNECTED), invitation creation is
          forbidden (R10.1): an :class:`~app.errors.AuthorizationError` (403).
          Existence is already established for a member, so 403 (not 404) is the
          honest, privacy-safe signal here.
        * If the couple already has an ACTIVE member in *each* of the two roles,
          a further invitation is rejected (R10.5) with an
          :class:`~app.errors.AuthorizationError` (403). (For a PENDING couple
          this is a belt-and-braces guard; it becomes load-bearing as the
          lifecycle evolves.)

        On success it generates an unpredictable token via
        :func:`app.couples.tokens.new_invitation_token`, persists **only** the
        ``token_hash`` in a PENDING invitation with a future ``expires_at``
        (R10.1, R10.2), records ``invitee_ref`` as the invitee identifier
        (R10.4), writes a content-free ``INVITATION_CREATED`` audit event
        (R10.6), and returns the raw token exactly once (R10.1) — the raw value
        is never persisted.
        """
        # Gate 1 (privacy-safe): the actor must be an ACTIVE member. Non-member
        # and non-existent couple are the same 404 (R17.3 style) so creation
        # never leaks whether a couple exists to an outsider.
        membership = self._couples.get_active_membership(couple_id, actor.user_id)
        if membership is None:
            raise ResourceNotFoundError()

        # Gate 2: the couple must be PENDING (R10.1). A member has already been
        # confirmed, so revealing "forbidden" is safe — 403, not 404.
        couple = self._couples.get_couple(couple_id)
        if couple is None:  # pragma: no cover - membership implies existence
            raise ResourceNotFoundError()
        if couple.status != Couple_Status.PENDING:
            raise AuthorizationError()

        # Gate 3 (R10.5): reject when both roles are already actively filled.
        if self._couples.both_roles_actively_filled(couple_id):
            raise AuthorizationError()

        # Generate an unpredictable token; persist ONLY its hash (R10.1).
        raw_token, token_hash = tokens.new_invitation_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._settings.invitation_ttl_seconds
        )

        invitation = self._couples.create_invitation(
            couple_id=couple_id,
            inviter_user_id=actor.user_id,
            invitee_identifier=invitee_ref,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        # R10.6: content-free audit of the creation. Recorded before the caller
        # commits so it lives in the same transaction as the invitation row.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=INVITATION_CREATED_EVENT,
            resource_type=INVITATION_RESOURCE_TYPE,
            resource_id=invitation.id,
            outcome="SUCCESS",
            request_id=request_id,
        )

        # R10.1: return the raw token exactly once; it is never persisted.
        return RawInvitationToken(
            raw_token=raw_token,
            invitation_id=invitation.id,
            expires_at=invitation.expires_at,
        )

    # ------------------------------------------------------------------
    # Acceptance (R11.1–R11.7; R10.3, R12.3, R12.4)
    # ------------------------------------------------------------------

    def accept_invitation(
        self,
        actor: AuthenticatedActor,
        raw_token: str,
        *,
        request_id: str | None = None,
    ) -> CoupleView:
        """Accept an invitation, joining ``actor`` to the couple as PARTNER_B.

        The invitee presents the raw ``raw_token`` they received out-of-band. The
        System looks the invitation up by the *hash* of that token
        (:func:`app.couples.tokens.hash_invitation_token`) — the raw value is
        never stored (R10.1) — and applies the following, failing closed:

        * **No acceptable match → Privacy_Safe_Response, no membership.** If the
          hash matches no row, or matches a row that is not currently PENDING
          (already ACCEPTED/DECLINED/REVOKED/EXPIRED), the caller receives a
          :class:`~app.errors.ResourceNotFoundError` (404). A bad/forged token
          and a decided-invitation token produce the *identical* response, so
          acceptance never confirms whether a token or invitation exists
          (R11.3/R10.3/R12.3/R12.4). No membership is added.
        * **Lazy expiry.** A PENDING invitation whose ``expires_at`` is at or
          before now is lazily materialised as EXPIRED (with an
          ``INVITATION_EXPIRED`` audit event, R12.3/R12.5) via
          :meth:`expire_if_needed`, then rejected with the same
          Privacy_Safe_Response as any decided token (R12.4) — no membership is
          added.
        * **Already coupled → reject, invitation stays PENDING.** If ``actor``
          already has an ACTIVE couple the acceptance is rejected with
          :class:`~app.errors.ActiveCoupleExistsError` (409) and the invitation
          is left PENDING (R11.2). The authoritative, race-safe guard is the
          partial unique index on ``couple_members(user_id) WHERE
          status = 'ACTIVE'`` (surfaced by the repository), so the rule holds
          even against a concurrent second accept.

        On a valid, unexpired PENDING invitation the repository performs a single
        atomic transaction (R11.1, R11.4): it row-locks the invitation and the
        couple, re-checks both are still PENDING under the lock (so a concurrent
        disconnect cannot interleave into an inconsistent state — design §37),
        adds ``actor`` as a PARTNER_B ACTIVE :class:`~app.couples.models.CoupleMember`,
        sets the invitation ACCEPTED, and sets the couple ACTIVE. A content-free
        ``INVITATION_ACCEPTED`` audit event is then recorded (R11.7).

        **R11.5 / R11.6 hold without any extra work here.** Acceptance changes
        only the *relationship* — it adds a membership row and activates the
        couple. It never copies, reclassifies, or grants anything on individual
        resources. Access to a couple's ``SHARED_COUPLE`` resources follows from
        being an active member and is decided by the AuthorizationService's
        Pattern B (membership + ACTIVE couple), so the new member gains
        SHARED_COUPLE access for *this* couple and nothing else (R11.5). Any
        :class:`~app.couples.models.PrivateReflection` created before acceptance
        remains ``PRIVATE_PARTNER`` and gated on *ownership* (Pattern A), which
        this method does not touch — so the new partner is never granted a
        pre-existing private resource (R11.6). No PrivateReflection is
        reclassified.

        Returns a :class:`CoupleView` of the now-ACTIVE couple. ``raw_token`` is
        untrusted input: it only ever resolves (via its hash) to at most one
        PENDING invitation, so it cannot widen access beyond joining the single
        couple that issued it.
        """
        # Look up strictly by the hash of the presented token (R10.1). A hash
        # with no row is the same Privacy_Safe_Response as a decided invitation.
        token_hash = tokens.hash_invitation_token(raw_token)
        invitation = self._couples.get_invitation_by_token_hash(token_hash)

        # No matching invitation, or one that is not PENDING (bad/forged token,
        # or already accepted/declined/revoked/expired) → privacy-safe 404, add
        # no membership (R11.3/R10.3/R12.3/R12.4).
        if invitation is None or invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()

        # Lazy expiry (R12.3): a PENDING invitation at/past its expiry is
        # materialised as EXPIRED (with an INVITATION_EXPIRED audit, R12.5) and
        # then rejected with the same Privacy_Safe_Response as any non-PENDING
        # token (R12.4) — no membership is added. Sharing one helper keeps the
        # access-path expiry semantics consistent between accept and decline.
        if self.expire_if_needed(invitation, request_id=request_id):
            raise ResourceNotFoundError()

        # Atomic accept (R11.1, R11.4): row-lock + re-check invitation & couple
        # still PENDING under the lock, add PARTNER_B ACTIVE, flip invitation to
        # ACCEPTED and couple to ACTIVE — all in one transaction. If the actor
        # already has an ACTIVE couple, the partial unique index rejects the
        # member insert and the invitation is left PENDING (R11.2, raised as
        # ActiveCoupleExistsError). A racing disconnect/accept that moved the
        # invitation or couple off PENDING surfaces as a privacy-safe 404.
        couple = self._couples.accept_invitation_atomic(
            invitation_id=invitation.id,
            invitee_user_id=actor.user_id,
        )

        # R11.7: content-free audit of the acceptance. Recorded before the caller
        # commits so it lives in the same transaction as the membership + status
        # changes.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=INVITATION_ACCEPTED_EVENT,
            resource_type=INVITATION_RESOURCE_TYPE,
            resource_id=invitation.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return CoupleView.model_validate(couple)

    # ------------------------------------------------------------------
    # Lazy expiry (R12.3, R12.5) — shared by every access path
    # ------------------------------------------------------------------

    def expire_if_needed(
        self,
        invitation: CoupleInvitation,
        *,
        request_id: str | None = None,
    ) -> bool:
        """Materialise a due PENDING invitation as EXPIRED, returning whether it is
        (now) expired and therefore not acceptable (R12.3).

        This is the single place the "expiry is evaluated on access" rule lives.
        Given an invitation already loaded on an access path, it decides:

        * If the invitation is not PENDING, it is already terminal — return
          ``True`` iff it is EXPIRED (so callers uniformly learn "not
          acceptable" from a truthy result) without any write.
        * If it is PENDING but not yet due (``expires_at`` in the future), it is
          still live — return ``False``.
        * If it is PENDING and at/past ``expires_at``, ask the repository to
          transition it to EXPIRED atomically (row-locked, re-checked). On a
          genuine transition, record exactly one content-free
          ``INVITATION_EXPIRED`` audit event (R12.5) and return ``True``. If a
          concurrent accept won the race (the repository returns ``None`` because
          the row is no longer PENDING), fall back to re-reading the row's status
          and return ``True`` only if it ended up EXPIRED — never double-auditing.

        The transition is server-controlled only; no client-supplied status
        participates. Callers treat a ``True`` result as a
        Privacy_Safe_Response condition (the invitation must not be honoured).
        """
        now = datetime.now(timezone.utc)
        if invitation.status != Invitation_Status.PENDING:
            return invitation.status == Invitation_Status.EXPIRED
        if invitation.expires_at > now:
            return False

        expired = self._couples.expire_invitation(invitation.id)
        if expired is None:
            # A concurrent transition beat us to it; audit nothing here. The
            # invitation is unacceptable only if it actually became EXPIRED.
            return invitation.status == Invitation_Status.EXPIRED

        # R12.5: one content-free audit per genuine EXPIRED transition.
        self._audit.record(
            actor_type="SYSTEM",
            actor_id=None,
            event_type=INVITATION_EXPIRED_EVENT,
            resource_type=INVITATION_RESOURCE_TYPE,
            resource_id=expired.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return True

    # ------------------------------------------------------------------
    # Decline (R12.1, R12.5) — the invitee refuses a PENDING invitation
    # ------------------------------------------------------------------

    def decline_invitation(
        self,
        actor: AuthenticatedActor,
        invitation_id: uuid.UUID,
        *,
        request_id: str | None = None,
    ) -> None:
        """Decline a PENDING invitation as its intended invitee (R12.1).

        Only the invitee named on the invitation may decline. Identity is decided
        from server state alone: the invitation records the invitee as
        ``invitee_identifier`` (the coordinate a user registers under), so the
        actor's *own* ``auth_identifier`` is resolved via the injected
        :class:`InviteeIdentifierLookup` and compared. The client-supplied
        ``invitation_id`` is untrusted and only ever narrows to one row; it can
        never widen access. Every failure is a privacy-safe
        :class:`~app.errors.ResourceNotFoundError` (404) so declining never
        confirms whether an invitation exists to someone who is not its invitee:

        * an unknown ``invitation_id`` → 404;
        * an invitation that is not PENDING (already accepted/declined/revoked/
          expired) → 404 (and a due PENDING one is first lazily EXPIRED via
          :meth:`expire_if_needed`, R12.3/R12.5, then treated as 404 — R12.4);
        * an actor who is not the named invitee → the identical 404.

        On success the repository transitions the invitation to ``DECLINED``
        (with ``declined_at``) atomically and **adds no membership** (R12.1); a
        content-free ``INVITATION_DECLINED`` audit event is then recorded
        (R12.5).
        """
        invitation = self._couples.get_invitation(invitation_id)
        if invitation is None:
            raise ResourceNotFoundError()

        # Lazy expiry first (R12.3): a due PENDING invitation becomes EXPIRED
        # (audited) and is then unacceptable — decline is refused like any other
        # non-PENDING invitation, privacy-safe (R12.4).
        if self.expire_if_needed(invitation, request_id=request_id):
            raise ResourceNotFoundError()
        if invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()

        # Confirm the actor IS the named invitee, from server state only. A
        # mismatch — or an unresolvable actor — is the same privacy-safe 404 an
        # unknown invitation yields, so a stranger cannot probe for existence.
        if not self._actor_is_invitee(actor, invitation.invitee_identifier):
            raise ResourceNotFoundError()

        # Atomic PENDING -> DECLINED (row-locked, re-checked). A racing accept/
        # decline/cancel that already moved it off PENDING surfaces as 404.
        declined = self._couples.decline_invitation_atomic(invitation.id)

        # R12.5: content-free audit of the decline, recorded before the caller
        # commits so it lives in the same transaction as the status change.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=INVITATION_DECLINED_EVENT,
            resource_type=INVITATION_RESOURCE_TYPE,
            resource_id=declined.id,
            outcome="SUCCESS",
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Cancel (R12.2, R12.5) — the inviter revokes a PENDING invitation
    # ------------------------------------------------------------------

    def cancel_invitation(
        self,
        actor: AuthenticatedActor,
        invitation_id: uuid.UUID,
        *,
        request_id: str | None = None,
    ) -> None:
        """Cancel a PENDING invitation as its inviter (R12.2).

        Only the inviter may cancel. Identity is decided from server state: the
        invitation records ``inviter_user_id``, which is compared directly to the
        server-resolved ``actor.user_id`` (no lookup needed, and no client-
        supplied identity is trusted — R14.2/R17.1). Every failure is a
        privacy-safe :class:`~app.errors.ResourceNotFoundError` (404) so cancel
        never confirms an invitation's existence to a non-inviter (e.g. the
        invitee or a stranger):

        * an unknown ``invitation_id`` → 404;
        * an invitation that is not PENDING → 404 (a due PENDING one is first
          lazily EXPIRED via :meth:`expire_if_needed`, R12.3/R12.5, then 404);
        * an actor who is not the inviter → the identical 404.

        On success the repository transitions the invitation to ``REVOKED`` (with
        ``revoked_at``) atomically; a content-free ``INVITATION_REVOKED`` audit
        event is then recorded (R12.5).
        """
        invitation = self._couples.get_invitation(invitation_id)
        if invitation is None:
            raise ResourceNotFoundError()

        # Lazy expiry first (R12.3): a due PENDING invitation becomes EXPIRED
        # (audited) and is then unacceptable — cancel is refused privacy-safely.
        if self.expire_if_needed(invitation, request_id=request_id):
            raise ResourceNotFoundError()
        if invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()

        # Only the inviter may cancel; anyone else (invitee, stranger) gets the
        # identical privacy-safe 404.
        if invitation.inviter_user_id != actor.user_id:
            raise ResourceNotFoundError()

        # Atomic PENDING -> REVOKED (row-locked, re-checked).
        revoked = self._couples.revoke_invitation_atomic(invitation.id)

        # R12.5: content-free audit of the revoke.
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=INVITATION_REVOKED_EVENT,
            resource_type=INVITATION_RESOURCE_TYPE,
            resource_id=revoked.id,
            outcome="SUCCESS",
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _actor_is_invitee(
        self, actor: AuthenticatedActor, invitee_identifier: str
    ) -> bool:
        """True iff ``actor`` is the user named by ``invitee_identifier``.

        Resolves the actor's own ``auth_identifier`` from server state via the
        injected :class:`InviteeIdentifierLookup` and compares it to the
        invitation's recorded invitee identifier. Returns ``False`` (never
        raising) when the lookup is unconfigured or the actor's user row cannot
        be resolved, so the caller uniformly produces a privacy-safe 404.
        """
        if self._user_lookup is None:  # pragma: no cover - misconfiguration
            return False
        user = self._user_lookup.get_by_id(actor.user_id)
        if user is None:
            return False
        return getattr(user, "auth_identifier", None) == invitee_identifier


__all__ = [
    "CoupleService",
    "InvitationService",
    "InviteeIdentifierLookup",
    "COUPLE_CREATED_EVENT",
    "COUPLE_DISCONNECTED_EVENT",
    "INVITATION_CREATED_EVENT",
    "INVITATION_ACCEPTED_EVENT",
    "INVITATION_DECLINED_EVENT",
    "INVITATION_REVOKED_EVENT",
    "INVITATION_EXPIRED_EVENT",
    "COUPLE_RESOURCE_TYPE",
    "INVITATION_RESOURCE_TYPE",
]
