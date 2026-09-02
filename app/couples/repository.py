"""Couples module repository — the only path to couple/member persistence.

The repository is the single doorway between the service layer and the
``couples`` / ``couple_members`` tables (design.md "Logical modules": *"an
authorized repository layer (the only path to the database). No route handler
talks to the database directly."*).

For task 9.1 (:class:`~app.couples.service.CoupleService`) the repository must
be able to:

* create a :class:`~app.couples.models.Couple` in ``PENDING`` and enrol its
  creator as a ``PARTNER_A`` ``ACTIVE`` :class:`~app.couples.models.CoupleMember`
  in one atomic step (R9.1);
* have that enrolment fail closed when the actor already has an ACTIVE couple —
  the authoritative guard is the partial unique index
  ``uq_couple_members_active_user`` on ``couple_members(user_id) WHERE
  status = 'ACTIVE'`` (migration ``0002_foundation_schema``), which the
  repository surfaces as :class:`~app.errors.ActiveCoupleExistsError` even under
  a concurrent-create race (R9.2/R9.3);
* answer the membership question ``get_active_membership`` so
  :meth:`~app.couples.service.CoupleService.get_couple` can decide access from
  server state alone (R17.3) — a non-member is indistinguishable from a couple
  that does not exist.

The couple is strictly an authorization relationship, never an account (R9.4):
this module persists relationship rows only and holds no identity semantics.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.couples.models import (
    Couple,
    CoupleInvitation,
    CoupleMember,
)
from app.enums import (
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
)
from app.errors import ActiveCoupleExistsError, ResourceNotFoundError

#: The partial unique index name the initial migration assigns to
#: ``couple_members(user_id) WHERE status = 'ACTIVE'`` (migration
#: ``0002_foundation_schema``). Used to recognise the at-most-one-ACTIVE-couple
#: violation specifically, rather than swallowing every integrity failure.
ACTIVE_MEMBER_UNIQUE_INDEX = "uq_couple_members_active_user"

#: The unique index name the initial migration assigns to
#: ``couple_invitations(token_hash)`` (migration ``0002_foundation_schema``):
#: one invitation per token; only the secure hash is ever stored (R10.1, R10.3).
INVITATION_TOKEN_HASH_UNIQUE_INDEX = "uq_couple_invitations_token_hash"


def _now() -> datetime:
    """Timezone-aware current time (UTC), centralised for deterministic tests."""
    return datetime.now(timezone.utc)


class CoupleRepository:
    """Persistence for :class:`Couple` / :class:`CoupleMember` rows.

    Holds a SQLAlchemy :class:`~sqlalchemy.orm.Session`; committing the
    surrounding transaction is the caller's responsibility (mirrors
    :class:`~app.users.repository.UserRepository` and
    :func:`app.db.get_session`).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- reads ------------------------------------------------------------

    def get_couple(self, couple_id: uuid.UUID) -> Couple | None:
        """Return the :class:`Couple` with ``couple_id`` or ``None`` if absent."""
        return self._session.get(Couple, couple_id)

    def get_membership(
        self, couple_id: uuid.UUID, user_id: uuid.UUID
    ) -> CoupleMember | None:
        """Return the actor's membership row in a couple, or ``None``.

        There is at most one row per ``(couple_id, user_id)`` pair
        (``UNIQUE(couple_id, user_id)``), so this resolves a single membership
        regardless of status.
        """
        return self._session.execute(
            select(CoupleMember).where(
                CoupleMember.couple_id == couple_id,
                CoupleMember.user_id == user_id,
            )
        ).scalar_one_or_none()

    def get_active_membership(
        self, couple_id: uuid.UUID, user_id: uuid.UUID
    ) -> CoupleMember | None:
        """Return the actor's *ACTIVE* membership in a couple, or ``None``.

        Used by :meth:`~app.couples.service.CoupleService.get_couple` to decide
        access: a caller who is not an active member is treated exactly like a
        caller asking about a couple that does not exist (R17.3), so this returns
        ``None`` for non-members and for merely DISCONNECTED members alike.
        """
        membership = self.get_membership(couple_id, user_id)
        if membership is None or membership.status != Member_Status.ACTIVE:
            return None
        return membership

    def get_invitation_by_token_hash(
        self, token_hash: str
    ) -> CoupleInvitation | None:
        """Return the invitation whose stored ``token_hash`` matches, or ``None``.

        Acceptance looks up an invitation by the secure hash of the presented
        raw token (never by the raw value, which is never stored — R10.1). The
        unique index on ``token_hash`` (:data:`INVITATION_TOKEN_HASH_UNIQUE_INDEX`)
        guarantees at most one row, so this resolves a single invitation
        regardless of its current status. Returning ``None`` for a hash with no
        row lets the service produce an identical Privacy_Safe_Response for a
        bad, forged, or unknown token (R11.3/R10.3).
        """
        return self._session.execute(
            select(CoupleInvitation).where(
                CoupleInvitation.token_hash == token_hash
            )
        ).scalar_one_or_none()

    def get_invitation(
        self, invitation_id: uuid.UUID
    ) -> CoupleInvitation | None:
        """Return the :class:`CoupleInvitation` with ``invitation_id`` or ``None``.

        Used by the decline/cancel/expiry access paths, which address an
        invitation by its server-side id rather than by token hash: the service
        decides from server state (invitee vs inviter identity, current status)
        whether the caller may act on it.
        """
        return self._session.get(CoupleInvitation, invitation_id)

    def active_member_roles(self, couple_id: uuid.UUID) -> set[Member_Role]:
        """Return the set of roles currently held by *ACTIVE* members of a couple.

        Used by :meth:`~app.couples.service.InvitationService.create_invitation`
        to decide R10.5: a couple with an ACTIVE member in *each* of the two
        roles (``{PARTNER_A, PARTNER_B}``) is fully filled and may not receive a
        further invitation. Only ACTIVE memberships count — a DISCONNECTED member
        leaves that role vacant.
        """
        rows = (
            self._session.execute(
                select(CoupleMember.role).where(
                    CoupleMember.couple_id == couple_id,
                    CoupleMember.status == Member_Status.ACTIVE,
                )
            )
            .scalars()
            .all()
        )
        return set(rows)

    def both_roles_actively_filled(self, couple_id: uuid.UUID) -> bool:
        """True when a couple has an ACTIVE member in both roles (R10.5).

        A convenience predicate over :meth:`active_member_roles`: the couple is
        fully formed exactly when both ``PARTNER_A`` and ``PARTNER_B`` are held
        by ACTIVE members, in which case no further invitation may be created.
        """
        return {
            Member_Role.PARTNER_A,
            Member_Role.PARTNER_B,
        } <= self.active_member_roles(couple_id)

    # -- writes -----------------------------------------------------------

    def create_invitation(
        self,
        *,
        couple_id: uuid.UUID,
        inviter_user_id: uuid.UUID,
        invitee_identifier: str,
        token_hash: str,
        expires_at: datetime,
    ) -> CoupleInvitation:
        """Persist a PENDING :class:`CoupleInvitation` storing only ``token_hash``.

        Writes a single-purpose invitation (R10.1–R10.4): ``status = PENDING``,
        the future ``expires_at`` assigned by the caller, the invitee reference,
        and **only** the secure hash of the raw token — the raw token itself is
        never handed to this method and never persisted. The insert runs inside a
        SAVEPOINT so that a token-hash collision (the unique index
        :data:`INVITATION_TOKEN_HASH_UNIQUE_INDEX`) rolls back only this insert
        and leaves the surrounding transaction usable; such a collision is
        astronomically unlikely for a 256-bit token but is surfaced as an
        :class:`IntegrityError` rather than silently swallowed so the caller can
        retry with a fresh token.
        """
        invitation = CoupleInvitation(
            id=uuid.uuid4(),
            couple_id=couple_id,
            inviter_user_id=inviter_user_id,
            invitee_identifier=invitee_identifier,
            token_hash=token_hash,
            status=Invitation_Status.PENDING,
            expires_at=expires_at,
        )
        with self._session.begin_nested():
            self._session.add(invitation)
            self._session.flush()
        return invitation

    def create_couple_with_creator(self, creator_user_id: uuid.UUID) -> Couple:
        """Create a PENDING couple and enrol ``creator_user_id`` as PARTNER_A.

        Both rows are written together (R9.1): a new :class:`Couple` with
        ``status = PENDING`` and a :class:`CoupleMember` for the creator with
        ``role = PARTNER_A`` and ``status = ACTIVE``. The insert runs inside a
        SAVEPOINT (nested transaction) so that, if the actor already has an
        ACTIVE membership, the partial unique index
        (:data:`ACTIVE_MEMBER_UNIQUE_INDEX`) rejects the member insert and only
        *this* work is rolled back — the surrounding transaction and session stay
        usable. That database guard is the authoritative check (R9.2/R9.3): it
        holds even under two concurrent ``create_couple`` calls, where a
        pre-check could not. The violation is surfaced as
        :class:`~app.errors.ActiveCoupleExistsError`.
        """
        couple = Couple(id=uuid.uuid4(), status=Couple_Status.PENDING)
        member = CoupleMember(
            id=uuid.uuid4(),
            couple_id=couple.id,
            user_id=creator_user_id,
            role=Member_Role.PARTNER_A,
            status=Member_Status.ACTIVE,
            joined_at=_now(),
        )
        try:
            with self._session.begin_nested():
                self._session.add(couple)
                self._session.add(member)
                self._session.flush()
        except IntegrityError as exc:
            # The SAVEPOINT is rolled back by the context manager; only this
            # couple + member insert is undone.
            if self._is_active_couple_conflict(exc):
                raise ActiveCoupleExistsError() from exc
            raise
        return couple

    def disconnect_couple_atomic(self, couple_id: uuid.UUID) -> Couple:
        """Disconnect an ACTIVE couple and both members in one transaction (R13.2).

        Only an ACTIVE couple may be disconnected: the couple row is loaded
        ``FOR UPDATE`` so that this operation serialises against a concurrent
        accept/disconnect on the same couple (design.md §37, R11.4). If the
        couple does not exist, or is not ACTIVE (still PENDING, or already
        DISCONNECTED), this raises :class:`~app.errors.ResourceNotFoundError`
        without mutating anything — a re-disconnect is not silently retried and
        a PENDING couple cannot be short-circuited to DISCONNECTED.

        On success, inside a single SAVEPOINT:

        * ``Couple.status`` becomes ``DISCONNECTED`` and ``disconnected_at`` is
          stamped, and
        * **both** :class:`CoupleMember` rows of the couple become
          ``DISCONNECTED`` with ``left_at`` stamped.

        The status change is server-controlled only — no client-supplied status
        participates (R13.7). Once persisted, the couple is no longer ACTIVE, so
        the authorization pipeline's Pattern B lifecycle check denies every new
        collaborative write to the couple's SHARED_COUPLE resources (R13.3).
        """
        now = _now()
        with self._session.begin_nested():
            # Row-lock the couple to serialise against a concurrent accept /
            # disconnect (design.md §37). Re-read status under the lock so the
            # ACTIVE precondition is checked at commit, not merely on entry.
            couple = self._session.execute(
                select(Couple).where(Couple.id == couple_id).with_for_update()
            ).scalar_one_or_none()
            if couple is None or couple.status != Couple_Status.ACTIVE:
                # Non-existent, still PENDING, or already DISCONNECTED — nothing
                # to disconnect. Privacy-safe: a non-member never reaches here
                # (the service gates on active membership first).
                raise ResourceNotFoundError()

            couple.status = Couple_Status.DISCONNECTED
            couple.disconnected_at = now

            members = (
                self._session.execute(
                    select(CoupleMember).where(CoupleMember.couple_id == couple_id)
                )
                .scalars()
                .all()
            )
            for member in members:
                member.status = Member_Status.DISCONNECTED
                member.left_at = now

            self._session.flush()
        return couple

    def accept_invitation_atomic(
        self,
        *,
        invitation_id: uuid.UUID,
        invitee_user_id: uuid.UUID,
    ) -> Couple:
        """Accept a PENDING invitation for an eligible invitee in one transaction.

        This is the single atomic write behind
        :meth:`~app.couples.service.InvitationService.accept_invitation` (R11.1,
        R11.4, design §36/§37). Inside one SAVEPOINT it:

        1. Row-locks (``FOR UPDATE``) the invitation and its couple so the whole
           operation serialises against a concurrent accept/disconnect on the
           same couple (design §37), then **re-reads their state under the lock**
           so the PENDING preconditions are checked at commit, not merely on
           entry (R11.4).
        2. Requires the invitation to still be ``PENDING`` and the couple to
           still be ``PENDING``. If either has moved on (accepted/declined/
           revoked/expired invitation, or a couple already ACTIVE/DISCONNECTED by
           a racing operation), it raises :class:`~app.errors.ResourceNotFoundError`
           — the same Privacy_Safe_Response the service uses for a token that
           matches no PENDING invitation (R11.3), and no membership is added.
        3. Adds the invitee as a :class:`CoupleMember` with ``role = PARTNER_B``,
           ``status = ACTIVE`` and a ``joined_at`` stamp; sets the invitation to
           ``ACCEPTED`` (with ``accepted_at``); sets the couple to ``ACTIVE``
           (with ``activated_at``). All three land together or not at all.

        If the invitee already has an ACTIVE couple, the member insert violates
        the partial unique index :data:`ACTIVE_MEMBER_UNIQUE_INDEX`; the SAVEPOINT
        rolls back (so the invitation stays PENDING — R11.2) and the violation is
        surfaced as :class:`~app.errors.ActiveCoupleExistsError`. This database
        guard is the authoritative, race-safe check: it holds even against a
        concurrent second accept where a read-then-write pre-check would not.

        The status transitions are server-controlled only — no client-supplied
        status participates (R13.7).
        """
        now = _now()
        try:
            with self._session.begin_nested():
                # Row-lock the invitation and re-read its status under the lock.
                invitation = self._session.execute(
                    select(CoupleInvitation)
                    .where(CoupleInvitation.id == invitation_id)
                    .with_for_update()
                ).scalar_one_or_none()
                if (
                    invitation is None
                    or invitation.status != Invitation_Status.PENDING
                ):
                    # Decided/expired/absent under the lock — privacy-safe, and
                    # no membership added (R11.3).
                    raise ResourceNotFoundError()

                # Row-lock the couple and re-check it is still PENDING, so a
                # concurrent disconnect/accept cannot leave an inconsistent
                # couple/member state (design §37, R11.4).
                couple = self._session.execute(
                    select(Couple)
                    .where(Couple.id == invitation.couple_id)
                    .with_for_update()
                ).scalar_one_or_none()
                if couple is None or couple.status != Couple_Status.PENDING:
                    raise ResourceNotFoundError()

                # Add the invitee as PARTNER_B (ACTIVE); flip invitation + couple.
                member = CoupleMember(
                    id=uuid.uuid4(),
                    couple_id=couple.id,
                    user_id=invitee_user_id,
                    role=Member_Role.PARTNER_B,
                    status=Member_Status.ACTIVE,
                    joined_at=now,
                )
                self._session.add(member)

                invitation.status = Invitation_Status.ACCEPTED
                invitation.accepted_at = now

                couple.status = Couple_Status.ACTIVE
                couple.activated_at = now

                self._session.flush()
        except IntegrityError as exc:
            # The SAVEPOINT is rolled back by the context manager: the member is
            # not added and the invitation stays PENDING (R11.2).
            if self._is_active_couple_conflict(exc):
                raise ActiveCoupleExistsError() from exc
            raise
        return couple

    def decline_invitation_atomic(
        self, invitation_id: uuid.UUID
    ) -> CoupleInvitation:
        """Transition a PENDING invitation to DECLINED in one transaction (R12.1).

        Inside a single SAVEPOINT this row-locks (``FOR UPDATE``) the invitation
        and **re-reads its status under the lock** so the PENDING precondition is
        checked at commit, not merely on entry — a concurrent accept/decline/
        cancel cannot interleave into an inconsistent terminal state. If the
        invitation is absent or no longer PENDING (already accepted/declined/
        revoked/expired), this raises :class:`~app.errors.ResourceNotFoundError`
        without mutating anything, so a re-decline is not silently retried.

        On success ``status`` becomes ``DECLINED`` and ``declined_at`` is
        stamped. **No membership row is added** — declining changes only the
        invitation, never the couple or its members (R12.1). The transition is
        server-controlled only; no client-supplied status participates.
        """
        now = _now()
        with self._session.begin_nested():
            invitation = self._session.execute(
                select(CoupleInvitation)
                .where(CoupleInvitation.id == invitation_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                invitation is None
                or invitation.status != Invitation_Status.PENDING
            ):
                raise ResourceNotFoundError()
            invitation.status = Invitation_Status.DECLINED
            invitation.declined_at = now
            self._session.flush()
        return invitation

    def revoke_invitation_atomic(
        self, invitation_id: uuid.UUID
    ) -> CoupleInvitation:
        """Transition a PENDING invitation to REVOKED in one transaction (R12.2).

        Symmetric to :meth:`decline_invitation_atomic`: inside one SAVEPOINT the
        invitation is row-locked and its status re-checked under the lock, so the
        PENDING precondition holds at commit against a concurrent transition. An
        absent or non-PENDING invitation raises
        :class:`~app.errors.ResourceNotFoundError` with no mutation.

        On success ``status`` becomes ``REVOKED`` and ``revoked_at`` is stamped.
        The transition is server-controlled only.
        """
        now = _now()
        with self._session.begin_nested():
            invitation = self._session.execute(
                select(CoupleInvitation)
                .where(CoupleInvitation.id == invitation_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                invitation is None
                or invitation.status != Invitation_Status.PENDING
            ):
                raise ResourceNotFoundError()
            invitation.status = Invitation_Status.REVOKED
            invitation.revoked_at = now
            self._session.flush()
        return invitation

    def expire_invitation(
        self, invitation_id: uuid.UUID
    ) -> CoupleInvitation | None:
        """Lazily materialise a due PENDING invitation as EXPIRED (R12.3).

        Called on an access path when a PENDING invitation is found to be at or
        past its ``expires_at``. Inside one SAVEPOINT the invitation is row-locked
        and re-read under the lock; the transition happens **only if** it is still
        PENDING *and* still due (``expires_at <= now``) at commit time. This makes
        the lazy sweep idempotent and race-safe:

        * a concurrent accept that already flipped it to ACCEPTED wins — this
          returns ``None`` and mutates nothing;
        * two concurrent access paths racing to expire the same invitation
          serialise on the lock; the first sets EXPIRED, the second re-reads a
          non-PENDING row and returns ``None``.

        Returns the invitation with ``status = EXPIRED`` and ``expired_at``
        stamped when it performed the transition, or ``None`` when there was
        nothing to do (absent, no longer PENDING, or not yet due). The caller
        audits exactly one INVITATION_EXPIRED event per genuine transition by
        acting only on a non-``None`` return.
        """
        now = _now()
        with self._session.begin_nested():
            invitation = self._session.execute(
                select(CoupleInvitation)
                .where(CoupleInvitation.id == invitation_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                invitation is None
                or invitation.status != Invitation_Status.PENDING
                or invitation.expires_at > now
            ):
                # Absent, already decided by a racing op, or not actually due —
                # nothing to expire.
                return None
            invitation.status = Invitation_Status.EXPIRED
            invitation.expired_at = now
            self._session.flush()
            return invitation

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _is_active_couple_conflict(exc: IntegrityError) -> bool:
        """True when ``exc`` is the at-most-one-ACTIVE-couple index violation.

        Matches on the named partial unique index so an unrelated integrity
        failure is not misreported. Falls back to the ``(user_id) WHERE
        status = 'ACTIVE'`` column signature for engines that don't surface the
        index name.
        """
        text = str(getattr(exc, "orig", exc))
        return ACTIVE_MEMBER_UNIQUE_INDEX in text or (
            "user_id" in text and "couple_members" in text
        )


__all__ = [
    "CoupleRepository",
    "ACTIVE_MEMBER_UNIQUE_INDEX",
    "INVITATION_TOKEN_HASH_UNIQUE_INDEX",
]
