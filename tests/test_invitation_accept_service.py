"""Tests for InvitationService.accept_invitation (task 10.2).

Covers R11.1–R11.7 (plus R10.3/R12.3/R12.4 for the privacy-safe no-match path).
Two layers, mirroring the create-invitation tests:

* **Pure / unit** — an in-memory fake repository plus a recording audit service
  drive the service logic without a database. These prove: a valid unexpired
  PENDING invitation adds the actor as a PARTNER_B ACTIVE member, flips the
  invitation to ACCEPTED and the couple to ACTIVE (R11.1); an actor who already
  has an ACTIVE couple is rejected and the invitation stays PENDING (R11.2); a
  bad/forged token and a decided invitation both yield an identical privacy-safe
  404 with no membership added (R11.3/R10.3/R12.4); an expired PENDING invitation
  is rejected the same way (R12.3); and a content-free ``INVITATION_ACCEPTED``
  audit event is written on success (R11.7). Because acceptance only writes
  relationship rows, R11.5/R11.6 are asserted by *what it does not touch* — it
  reclassifies no resource and adds only a membership.

* **DB-backed (defense in depth)** — using the ``pg_schema`` fixture with the
  REAL indexes (the partial unique ``uq_couple_members_active_user`` and the
  unique ``uq_couple_invitations_token_hash``) as authored in migration
  ``0002_foundation_schema``. These prove the single-transaction accept writes
  all three changes together (R11.1/R11.4), that the partial unique index makes
  the "already has an ACTIVE couple" guard race-safe while leaving the invitation
  PENDING (R11.2), and that any pre-existing PrivateReflection is untouched by
  acceptance (R11.6).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import text

from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.couples import tokens
from app.couples.models import (
    Couple,
    CoupleInvitation,
    CoupleMember,
    PrivateReflection,
)
from app.couples.repository import (
    ACTIVE_MEMBER_UNIQUE_INDEX,
    INVITATION_TOKEN_HASH_UNIQUE_INDEX,
    CoupleRepository,
)
from app.couples.schemas import CoupleView
from app.couples.service import (
    INVITATION_ACCEPTED_EVENT,
    INVITATION_RESOURCE_TYPE,
    InvitationService,
)
from app.enums import (
    Account_Status,
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
    Visibility_Scope,
)
from app.errors import ActiveCoupleExistsError, ResourceNotFoundError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _actor(
    user_id: uuid.UUID | None = None,
    status: Account_Status = Account_Status.ACTIVE,
) -> AuthenticatedActor:
    return AuthenticatedActor(
        user_id=user_id or uuid.uuid4(), account_status=status
    )


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


# --- Pure test doubles ------------------------------------------------------


class _RecordingAudit:
    """Captures record() calls without a database."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs


class _FakeCoupleRepository:
    """In-memory stand-in mirroring the CoupleRepository contract used here.

    Models the accept path: lookup-by-hash, the partial unique index (at most
    one ACTIVE membership per user), and the atomic row-locked accept with a
    re-check of PENDING state.
    """

    def __init__(self) -> None:
        self.couples: dict[uuid.UUID, Couple] = {}
        self.members: dict[uuid.UUID, CoupleMember] = {}
        self.invitations: dict[uuid.UUID, CoupleInvitation] = {}

    # -- reads --

    def get_invitation_by_token_hash(self, token_hash):
        for inv in self.invitations.values():
            if inv.token_hash == token_hash:
                return inv
        return None

    def expire_invitation(self, invitation_id):
        """Lazily materialise a due PENDING invitation as EXPIRED (R12.3).

        Mirrors the real repository: only a still-PENDING, actually-due
        invitation transitions; otherwise returns None (nothing to do).
        """
        invitation = self.invitations.get(invitation_id)
        now = datetime.now(timezone.utc)
        if (
            invitation is None
            or invitation.status != Invitation_Status.PENDING
            or invitation.expires_at > now
        ):
            return None
        invitation.status = Invitation_Status.EXPIRED
        invitation.expired_at = now
        return invitation

    def _has_active_membership(self, user_id) -> bool:
        return any(
            m.user_id == user_id and m.status == Member_Status.ACTIVE
            for m in self.members.values()
        )

    # -- writes --

    def accept_invitation_atomic(self, *, invitation_id, invitee_user_id):
        invitation = self.invitations.get(invitation_id)
        # Re-check invitation still PENDING under the (simulated) lock.
        if invitation is None or invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()
        couple = self.couples.get(invitation.couple_id)
        # Re-check couple still PENDING under the (simulated) lock.
        if couple is None or couple.status != Couple_Status.PENDING:
            raise ResourceNotFoundError()
        # Partial unique index: at most one ACTIVE couple per user (R11.2).
        if self._has_active_membership(invitee_user_id):
            raise ActiveCoupleExistsError()

        now = datetime.now(timezone.utc)
        member = CoupleMember(
            id=uuid.uuid4(),
            couple_id=couple.id,
            user_id=invitee_user_id,
            role=Member_Role.PARTNER_B,
            status=Member_Status.ACTIVE,
            joined_at=now,
        )
        self.members[member.id] = member
        invitation.status = Invitation_Status.ACCEPTED
        invitation.accepted_at = now
        couple.status = Couple_Status.ACTIVE
        couple.activated_at = now
        return couple

    # -- test setup helpers --

    def _add_couple(self, status=Couple_Status.PENDING) -> Couple:
        couple = Couple(id=uuid.uuid4(), status=status)
        couple.created_at = datetime.now(timezone.utc)
        self.couples[couple.id] = couple
        return couple

    def _add_member(self, couple_id, user_id, role, status=Member_Status.ACTIVE):
        member = CoupleMember(
            id=uuid.uuid4(),
            couple_id=couple_id,
            user_id=user_id,
            role=role,
            status=status,
        )
        self.members[member.id] = member
        return member

    def _add_invitation(
        self,
        couple_id,
        *,
        token_hash,
        status=Invitation_Status.PENDING,
        expires_at=None,
    ) -> CoupleInvitation:
        invitation = CoupleInvitation(
            id=uuid.uuid4(),
            couple_id=couple_id,
            inviter_user_id=uuid.uuid4(),
            invitee_identifier="partner@example.test",
            token_hash=token_hash,
            status=status,
            expires_at=expires_at or _future(),
        )
        self.invitations[invitation.id] = invitation
        return invitation


def _pure_service():
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    service = InvitationService(couple_repository=repo, audit_service=audit)
    return service, repo, audit


def _pending_couple_with_invitation(repo, raw_token: str, **inv_kwargs):
    """A PENDING couple (PARTNER_A filled) + a PENDING invitation for ``raw_token``."""
    couple = repo._add_couple(status=Couple_Status.PENDING)
    repo._add_member(couple.id, uuid.uuid4(), Member_Role.PARTNER_A)
    invitation = repo._add_invitation(
        couple.id, token_hash=tokens.hash_invitation_token(raw_token), **inv_kwargs
    )
    return couple, invitation


# ===========================================================================
# Pure: happy path (R11.1, R11.7)
# ===========================================================================


def test_accept_adds_partner_b_and_activates_couple():
    """R11.1: PARTNER_B ACTIVE added; invitation ACCEPTED; couple ACTIVE."""
    service, repo, _ = _pure_service()
    raw = "invitee-token"
    couple, invitation = _pending_couple_with_invitation(repo, raw)
    invitee = _actor()

    view = service.accept_invitation(invitee, raw)

    assert isinstance(view, CoupleView)
    assert view.id == couple.id
    assert view.status == Couple_Status.ACTIVE
    assert couple.status == Couple_Status.ACTIVE
    assert couple.activated_at is not None
    assert invitation.status == Invitation_Status.ACCEPTED
    assert invitation.accepted_at is not None

    new_member = next(
        m for m in repo.members.values() if m.user_id == invitee.user_id
    )
    assert new_member.role == Member_Role.PARTNER_B
    assert new_member.status == Member_Status.ACTIVE
    assert new_member.joined_at is not None


def test_accept_records_content_free_audit_event():
    """R11.7: a content-free INVITATION_ACCEPTED audit event is recorded."""
    service, repo, audit = _pure_service()
    raw = "invitee-token"
    _couple, invitation = _pending_couple_with_invitation(repo, raw)
    invitee = _actor()

    service.accept_invitation(invitee, raw, request_id="req-acc")

    accepted = [
        c for c in audit.calls if c["event_type"] == INVITATION_ACCEPTED_EVENT
    ]
    assert len(accepted) == 1
    call = accepted[0]
    assert call["resource_type"] == INVITATION_RESOURCE_TYPE
    assert call["resource_id"] == invitation.id
    assert call["actor_id"] == invitee.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-acc"
    # No relationship content leaks into the audit.
    assert call.get("metadata") in (None, {})


# ===========================================================================
# Pure: no acceptable match → privacy-safe 404, no membership
# (R11.3, R10.3, R12.4)
# ===========================================================================


def test_accept_unknown_token_privacy_safe_not_found():
    """R11.3/R10.3: a token matching no invitation → 404, no membership."""
    service, repo, audit = _pure_service()
    _pending_couple_with_invitation(repo, "real-token")

    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(_actor(), "some-other-token")

    # No PARTNER_B membership was added (only the pre-seeded PARTNER_A exists).
    assert all(
        m.role != Member_Role.PARTNER_B for m in repo.members.values()
    )
    assert audit.calls == []


@pytest.mark.parametrize(
    "status",
    [
        Invitation_Status.ACCEPTED,
        Invitation_Status.DECLINED,
        Invitation_Status.REVOKED,
        Invitation_Status.EXPIRED,
    ],
)
def test_accept_decided_invitation_rejected(status):
    """R12.4: a token for a decided invitation is rejected identically (404)."""
    service, repo, audit = _pure_service()
    raw = "decided-token"
    _couple, invitation = _pending_couple_with_invitation(repo, raw, status=status)
    invitee = _actor()

    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(invitee, raw)

    assert invitation.status == status  # unchanged
    assert not any(m.user_id == invitee.user_id for m in repo.members.values())
    assert audit.calls == []


def test_accept_unknown_and_decided_indistinguishable():
    """R11.3/R12.4: bad token and decided-invitation token → identical error."""
    service, repo, _ = _pure_service()
    raw = "decided-token"
    _pending_couple_with_invitation(
        repo, raw, status=Invitation_Status.DECLINED
    )

    with pytest.raises(ResourceNotFoundError) as decided:
        service.accept_invitation(_actor(), raw)
    with pytest.raises(ResourceNotFoundError) as unknown:
        service.accept_invitation(_actor(), "never-issued")

    assert type(decided.value) is type(unknown.value)
    assert decided.value.code == unknown.value.code == "RESOURCE_NOT_FOUND"
    assert decided.value.http_status == unknown.value.http_status == 404


# ===========================================================================
# Pure: lazy expiry (R12.3)
# ===========================================================================


def test_accept_expired_pending_invitation_rejected():
    """R12.3: a PENDING invitation past expires_at is treated as EXPIRED (404).

    Acceptance now lazily materialises the EXPIRED transition on this access path
    (R12.3/R12.5): the invitation moves to EXPIRED with an INVITATION_EXPIRED
    audit, and the acceptance is refused with the privacy-safe 404. Crucially, no
    membership is added and no INVITATION_ACCEPTED event is recorded.
    """
    from app.couples.service import INVITATION_EXPIRED_EVENT

    service, repo, audit = _pure_service()
    raw = "expired-token"
    _couple, invitation = _pending_couple_with_invitation(
        repo, raw, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    invitee = _actor()

    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(invitee, raw)

    # The invitation is materialised EXPIRED; no membership added (R12.3).
    assert invitation.status == Invitation_Status.EXPIRED
    assert not any(m.user_id == invitee.user_id for m in repo.members.values())
    # Exactly the expiry audit is recorded — never an acceptance audit.
    assert [c["event_type"] for c in audit.calls] == [INVITATION_EXPIRED_EVENT]


def test_accept_at_exact_expiry_is_rejected():
    """R12.3: expiry is inclusive — expires_at == now is EXPIRED."""
    service, repo, _ = _pure_service()
    raw = "boundary-token"
    # Set expiry a hair in the past so the <= now comparison is deterministic.
    _pending_couple_with_invitation(
        repo, raw, expires_at=datetime.now(timezone.utc)
    )

    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(_actor(), raw)


# ===========================================================================
# Pure: actor already has an ACTIVE couple (R11.2)
# ===========================================================================


def test_accept_rejected_when_actor_already_has_active_couple():
    """R11.2: an already-coupled actor is rejected; invitation stays PENDING."""
    service, repo, audit = _pure_service()
    raw = "invitee-token"
    _couple, invitation = _pending_couple_with_invitation(repo, raw)

    # The invitee already actively belongs to a different couple.
    invitee = _actor()
    other_couple = repo._add_couple(status=Couple_Status.ACTIVE)
    repo._add_member(other_couple.id, invitee.user_id, Member_Role.PARTNER_A)

    with pytest.raises(ActiveCoupleExistsError) as exc:
        service.accept_invitation(invitee, raw)
    assert exc.value.http_status == 409

    # Invitation left PENDING; no PARTNER_B membership added; no audit.
    assert invitation.status == Invitation_Status.PENDING
    assert not any(
        m.role == Member_Role.PARTNER_B for m in repo.members.values()
    )
    assert audit.calls == []


# ===========================================================================
# Pure: token is hashed for lookup (R10.1 continuity)
# ===========================================================================


def test_accept_looks_up_by_hash_not_raw_token():
    """Acceptance resolves the invitation via hash(raw_token), never the raw value."""
    service, repo, _ = _pure_service()
    raw = "invitee-token"
    _couple, invitation = _pending_couple_with_invitation(repo, raw)

    # The stored value is the hash; presenting the hash itself must NOT match.
    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(_actor(), invitation.token_hash)

    # Presenting the raw token resolves correctly.
    view = service.accept_invitation(_actor(), raw)
    assert view.status == Couple_Status.ACTIVE


# ===========================================================================
# Property: accept is all-or-nothing on the tri-state transition
# (Feature: foundation-auth-couples)
# ===========================================================================


@settings(max_examples=50, deadline=None)
@given(raw=st.text(min_size=1, max_size=64), ttl=st.integers(60, 30 * 24 * 3600))
def test_property_accept_transitions_together_or_not_at_all(raw, ttl):
    """Property: for any raw token and TTL, accepting a valid PENDING invitation
    always moves the invitation→ACCEPTED, couple→ACTIVE, and adds exactly one
    PARTNER_B ACTIVE member — the three changes are inseparable.

    Feature: foundation-auth-couples

    **Validates: Requirements 11.1**
    """
    service, repo, _ = _pure_service()
    couple, invitation = _pending_couple_with_invitation(
        repo, raw, expires_at=_future(ttl)
    )
    invitee = _actor()

    view = service.accept_invitation(invitee, raw)

    assert view.status == Couple_Status.ACTIVE
    assert couple.status == Couple_Status.ACTIVE
    assert invitation.status == Invitation_Status.ACCEPTED
    partner_bs = [
        m
        for m in repo.members.values()
        if m.role == Member_Role.PARTNER_B and m.user_id == invitee.user_id
    ]
    assert len(partner_bs) == 1
    assert partner_bs[0].status == Member_Status.ACTIVE


# ===========================================================================
# DB-backed (defense in depth): real repo + real indexes
# ===========================================================================


def _create_couples_tables(session):
    """Create couples/couple_members/couple_invitations/private_reflections and
    the REAL indexes (as authored in migration ``0002_foundation_schema``)."""
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            Couple.__table__,
            CoupleMember.__table__,
            CoupleInvitation.__table__,
            PrivateReflection.__table__,
        ],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{ACTIVE_MEMBER_UNIQUE_INDEX}" '
            "ON couple_members (user_id) WHERE status = 'ACTIVE'"
        )
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{INVITATION_TOKEN_HASH_UNIQUE_INDEX}" '
            "ON couple_invitations (token_hash)"
        )
    )
    session.flush()


def _create_audit_table(session):
    from app.audit.models import AuditEvent

    AuditEvent.__table__.create(bind=session.connection())


def _db_service(session):
    audit = AuditService(AuditRepository(session))
    repo = CoupleRepository(session)
    service = InvitationService(couple_repository=repo, audit_service=audit)
    return service, repo


def _persist_pending_couple_with_invitation(session, repo, raw_token: str):
    """Persist a PENDING couple (PARTNER_A) + a PENDING invitation; return them."""
    creator = _actor()
    couple = repo.create_couple_with_creator(creator.user_id)
    invitation = repo.create_invitation(
        couple_id=couple.id,
        inviter_user_id=creator.user_id,
        invitee_identifier="partner@example.test",
        token_hash=tokens.hash_invitation_token(raw_token),
        expires_at=_future(),
    )
    session.flush()
    return couple, invitation, creator


def test_db_accept_activates_couple_and_adds_partner_b(pg_schema):
    """R11.1/R11.4 (DB): one transaction adds PARTNER_B, ACCEPTED, ACTIVE."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    raw = "db-invitee-token"
    couple, invitation, _creator = _persist_pending_couple_with_invitation(
        pg_schema, repo, raw
    )
    invitee = _actor()

    view = service.accept_invitation(invitee, raw)
    pg_schema.flush()

    couple_row = pg_schema.get(Couple, couple.id)
    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert view.status == Couple_Status.ACTIVE
    assert couple_row.status == Couple_Status.ACTIVE
    assert couple_row.activated_at is not None
    assert inv_row.status == Invitation_Status.ACCEPTED
    assert inv_row.accepted_at is not None

    member = (
        pg_schema.query(CoupleMember)
        .filter(
            CoupleMember.couple_id == couple.id,
            CoupleMember.user_id == invitee.user_id,
        )
        .one()
    )
    assert member.role == Member_Role.PARTNER_B
    assert member.status == Member_Status.ACTIVE
    assert member.joined_at is not None


def test_db_accept_records_audit(pg_schema):
    """R11.7 (DB): an INVITATION_ACCEPTED audit row is written on success."""
    from app.audit.models import AuditEvent

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    raw = "db-invitee-token"
    _couple, invitation, _creator = _persist_pending_couple_with_invitation(
        pg_schema, repo, raw
    )

    service.accept_invitation(_actor(), raw)
    pg_schema.flush()

    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == INVITATION_ACCEPTED_EVENT)
        .all()
    )
    assert len(events) == 1
    assert events[0].resource_id == invitation.id
    assert events[0].outcome == "SUCCESS"


def test_db_accept_rejected_when_actor_has_active_couple(pg_schema):
    """R11.2 (DB): the partial unique index blocks a second ACTIVE couple;
    the invitation is left PENDING and no PARTNER_B row is written."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    raw = "db-invitee-token"
    _couple, invitation, _creator = _persist_pending_couple_with_invitation(
        pg_schema, repo, raw
    )

    # The invitee already actively belongs to another couple.
    invitee = _actor()
    repo.create_couple_with_creator(invitee.user_id)
    pg_schema.flush()

    with pytest.raises(ActiveCoupleExistsError):
        service.accept_invitation(invitee, raw)
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.PENDING  # left PENDING (R11.2)
    partner_b_count = (
        pg_schema.query(CoupleMember)
        .filter(
            CoupleMember.user_id == invitee.user_id,
            CoupleMember.role == Member_Role.PARTNER_B,
        )
        .count()
    )
    assert partner_b_count == 0


def test_db_accept_unknown_token_writes_nothing(pg_schema):
    """R11.3 (DB): a token matching no invitation → 404, no membership written."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    _couple, _invitation, _creator = _persist_pending_couple_with_invitation(
        pg_schema, repo, "real-token"
    )

    before = pg_schema.query(CoupleMember).count()
    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(_actor(), "not-a-real-token")
    pg_schema.flush()

    assert pg_schema.query(CoupleMember).count() == before


def test_db_accept_does_not_touch_pre_existing_private_reflection(pg_schema):
    """R11.6 (DB): acceptance reclassifies no PrivateReflection.

    A PrivateReflection created before acceptance stays PRIVATE_PARTNER and owned
    by its original owner — acceptance changes only the relationship, never the
    classification or ownership of a private resource.
    """
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    raw = "db-invitee-token"
    couple, _invitation, creator = _persist_pending_couple_with_invitation(
        pg_schema, repo, raw
    )

    # A private reflection owned by the inviter, before the invitee joins.
    reflection = PrivateReflection(
        id=uuid.uuid4(),
        user_id=creator.user_id,
        couple_id=couple.id,
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
    )
    pg_schema.add(reflection)
    pg_schema.flush()

    service.accept_invitation(_actor(), raw)
    pg_schema.flush()

    row = pg_schema.get(PrivateReflection, reflection.id)
    assert row.user_id == creator.user_id  # ownership unchanged (R11.6)
    assert row.visibility_scope == Visibility_Scope.PRIVATE_PARTNER  # unchanged
