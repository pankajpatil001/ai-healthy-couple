"""Tests for InvitationService decline / cancel / lazy-expiry (task 10.3).

Covers R12.1–R12.5:

* R12.1 — the invitee declines a PENDING invitation → DECLINED, no membership.
* R12.2 — the inviter cancels a PENDING invitation → REVOKED.
* R12.3 — a PENDING invitation at/past ``expires_at`` is treated as EXPIRED on
  access and rejected.
* R12.4 — a token/invitation that is DECLINED/REVOKED/EXPIRED/ACCEPTED is
  rejected for acceptance (and decline/cancel) identically.
* R12.5 — a content-free Audit_Event is recorded for each DECLINED / REVOKED /
  EXPIRED transition.

Two layers, mirroring the accept-invitation tests:

* **Pure / unit** — an in-memory fake repository, a recording audit service, and
  a tiny user-lookup fake drive the service without a database.
* **DB-backed (defense in depth)** — the ``pg_schema`` fixture with the REAL
  indexes as authored in migration ``0002_foundation_schema`` proves the atomic
  row-locked transitions and privacy-safe semantics against real Postgres.
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
from app.couples.service import (
    INVITATION_DECLINED_EVENT,
    INVITATION_EXPIRED_EVENT,
    INVITATION_REVOKED_EVENT,
    INVITATION_RESOURCE_TYPE,
    InvitationService,
)
from app.enums import (
    Account_Status,
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
)
from app.errors import ResourceNotFoundError
from app.users.models import User
from app.users.repository import UserRepository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INVITEE_IDENTIFIER = "invitee@example.test"


def _actor(
    user_id: uuid.UUID | None = None,
    status: Account_Status = Account_Status.ACTIVE,
) -> AuthenticatedActor:
    return AuthenticatedActor(
        user_id=user_id or uuid.uuid4(), account_status=status
    )


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _past(seconds: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


# --- Pure test doubles ------------------------------------------------------


class _RecordingAudit:
    """Captures record() calls without a database."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs

    def events(self, event_type: str) -> list[dict]:
        return [c for c in self.calls if c["event_type"] == event_type]


class _FakeUser:
    def __init__(self, user_id: uuid.UUID, auth_identifier: str) -> None:
        self.id = user_id
        self.auth_identifier = auth_identifier


class _FakeUserLookup:
    """Minimal InviteeIdentifierLookup: maps user_id -> auth_identifier."""

    def __init__(self) -> None:
        self._by_id: dict[uuid.UUID, _FakeUser] = {}

    def add(self, user_id: uuid.UUID, auth_identifier: str) -> _FakeUser:
        user = _FakeUser(user_id, auth_identifier)
        self._by_id[user_id] = user
        return user

    def get_by_id(self, user_id: uuid.UUID):
        return self._by_id.get(user_id)


class _FakeCoupleRepository:
    """In-memory stand-in mirroring the CoupleRepository contract used here."""

    def __init__(self) -> None:
        self.couples: dict[uuid.UUID, Couple] = {}
        self.members: dict[uuid.UUID, CoupleMember] = {}
        self.invitations: dict[uuid.UUID, CoupleInvitation] = {}

    # -- reads --

    def get_invitation(self, invitation_id):
        return self.invitations.get(invitation_id)

    # -- writes --

    def decline_invitation_atomic(self, invitation_id):
        invitation = self.invitations.get(invitation_id)
        if invitation is None or invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()
        invitation.status = Invitation_Status.DECLINED
        invitation.declined_at = datetime.now(timezone.utc)
        return invitation

    def revoke_invitation_atomic(self, invitation_id):
        invitation = self.invitations.get(invitation_id)
        if invitation is None or invitation.status != Invitation_Status.PENDING:
            raise ResourceNotFoundError()
        invitation.status = Invitation_Status.REVOKED
        invitation.revoked_at = datetime.now(timezone.utc)
        return invitation

    def expire_invitation(self, invitation_id):
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

    # -- test setup helpers --

    def add_invitation(
        self,
        *,
        inviter_user_id,
        invitee_identifier=INVITEE_IDENTIFIER,
        status=Invitation_Status.PENDING,
        expires_at=None,
        token_hash="hash",
    ) -> CoupleInvitation:
        invitation = CoupleInvitation(
            id=uuid.uuid4(),
            couple_id=uuid.uuid4(),
            inviter_user_id=inviter_user_id,
            invitee_identifier=invitee_identifier,
            token_hash=token_hash,
            status=status,
            expires_at=expires_at or _future(),
        )
        self.invitations[invitation.id] = invitation
        return invitation


def _pure_service(*, with_user_lookup=True):
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    lookup = _FakeUserLookup() if with_user_lookup else None
    service = InvitationService(
        couple_repository=repo, audit_service=audit, user_lookup=lookup
    )
    return service, repo, audit, lookup


# ===========================================================================
# Pure: decline (R12.1, R12.5)
# ===========================================================================


def test_decline_by_invitee_sets_declined_and_no_membership():
    """R12.1: the named invitee declines → DECLINED, declined_at, no membership."""
    service, repo, _audit, lookup = _pure_service()
    inviter = uuid.uuid4()
    invitation = repo.add_invitation(inviter_user_id=inviter)
    invitee = _actor()
    lookup.add(invitee.user_id, INVITEE_IDENTIFIER)

    result = service.decline_invitation(invitee, invitation.id)

    assert result is None
    assert invitation.status == Invitation_Status.DECLINED
    assert invitation.declined_at is not None
    # Declining never adds a membership row (R12.1).
    assert repo.members == {}


def test_decline_records_content_free_audit_event():
    """R12.5: a content-free INVITATION_DECLINED audit event is recorded."""
    service, repo, audit, lookup = _pure_service()
    invitation = repo.add_invitation(inviter_user_id=uuid.uuid4())
    invitee = _actor()
    lookup.add(invitee.user_id, INVITEE_IDENTIFIER)

    service.decline_invitation(invitee, invitation.id, request_id="req-dec")

    events = audit.events(INVITATION_DECLINED_EVENT)
    assert len(events) == 1
    call = events[0]
    assert call["resource_type"] == INVITATION_RESOURCE_TYPE
    assert call["resource_id"] == invitation.id
    assert call["actor_id"] == invitee.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-dec"
    assert call.get("metadata") in (None, {})


def test_decline_by_non_invitee_is_privacy_safe_not_found():
    """R12.1/privacy: a non-invitee gets a 404 and cannot decline."""
    service, repo, audit, lookup = _pure_service()
    invitation = repo.add_invitation(inviter_user_id=uuid.uuid4())
    stranger = _actor()
    lookup.add(stranger.user_id, "someone-else@example.test")

    with pytest.raises(ResourceNotFoundError):
        service.decline_invitation(stranger, invitation.id)

    assert invitation.status == Invitation_Status.PENDING  # untouched
    assert audit.calls == []


def test_decline_unknown_invitation_is_not_found():
    """An unknown invitation id → privacy-safe 404, no audit."""
    service, _repo, audit, _lookup = _pure_service()

    with pytest.raises(ResourceNotFoundError):
        service.decline_invitation(_actor(), uuid.uuid4())

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
def test_decline_non_pending_rejected(status):
    """R12.4: declining a non-PENDING invitation → 404, unchanged, no audit."""
    service, repo, audit, lookup = _pure_service()
    invitation = repo.add_invitation(inviter_user_id=uuid.uuid4(), status=status)
    invitee = _actor()
    lookup.add(invitee.user_id, INVITEE_IDENTIFIER)

    with pytest.raises(ResourceNotFoundError):
        service.decline_invitation(invitee, invitation.id)

    assert invitation.status == status
    # No DECLINED audit for a non-PENDING invitation.
    assert audit.events(INVITATION_DECLINED_EVENT) == []


def test_decline_non_invitee_and_unknown_indistinguishable():
    """A non-invitee and an unknown id yield the identical privacy-safe error."""
    service, repo, _audit, lookup = _pure_service()
    invitation = repo.add_invitation(inviter_user_id=uuid.uuid4())
    stranger = _actor()
    lookup.add(stranger.user_id, "not-the-invitee@example.test")

    with pytest.raises(ResourceNotFoundError) as non_invitee:
        service.decline_invitation(stranger, invitation.id)
    with pytest.raises(ResourceNotFoundError) as unknown:
        service.decline_invitation(stranger, uuid.uuid4())

    assert type(non_invitee.value) is type(unknown.value)
    assert (
        non_invitee.value.code == unknown.value.code == "RESOURCE_NOT_FOUND"
    )
    assert non_invitee.value.http_status == unknown.value.http_status == 404


# ===========================================================================
# Pure: cancel (R12.2, R12.5)
# ===========================================================================


def test_cancel_by_inviter_sets_revoked():
    """R12.2: the inviter cancels a PENDING invitation → REVOKED, revoked_at."""
    service, repo, _audit, _lookup = _pure_service()
    inviter = _actor()
    invitation = repo.add_invitation(inviter_user_id=inviter.user_id)

    result = service.cancel_invitation(inviter, invitation.id)

    assert result is None
    assert invitation.status == Invitation_Status.REVOKED
    assert invitation.revoked_at is not None


def test_cancel_records_content_free_audit_event():
    """R12.5: a content-free INVITATION_REVOKED audit event is recorded."""
    service, repo, audit, _lookup = _pure_service()
    inviter = _actor()
    invitation = repo.add_invitation(inviter_user_id=inviter.user_id)

    service.cancel_invitation(inviter, invitation.id, request_id="req-can")

    events = audit.events(INVITATION_REVOKED_EVENT)
    assert len(events) == 1
    call = events[0]
    assert call["resource_type"] == INVITATION_RESOURCE_TYPE
    assert call["resource_id"] == invitation.id
    assert call["actor_id"] == inviter.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-can"
    assert call.get("metadata") in (None, {})


def test_cancel_by_non_inviter_is_privacy_safe_not_found():
    """R12.2/privacy: a non-inviter (e.g. the invitee) cannot cancel → 404."""
    service, repo, audit, _lookup = _pure_service()
    invitation = repo.add_invitation(inviter_user_id=uuid.uuid4())
    not_the_inviter = _actor()

    with pytest.raises(ResourceNotFoundError):
        service.cancel_invitation(not_the_inviter, invitation.id)

    assert invitation.status == Invitation_Status.PENDING  # untouched
    assert audit.calls == []


def test_cancel_unknown_invitation_is_not_found():
    service, _repo, audit, _lookup = _pure_service()

    with pytest.raises(ResourceNotFoundError):
        service.cancel_invitation(_actor(), uuid.uuid4())

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
def test_cancel_non_pending_rejected(status):
    """R12.4: cancelling a non-PENDING invitation → 404, unchanged, no audit."""
    service, repo, audit, _lookup = _pure_service()
    inviter = _actor()
    invitation = repo.add_invitation(
        inviter_user_id=inviter.user_id, status=status
    )

    with pytest.raises(ResourceNotFoundError):
        service.cancel_invitation(inviter, invitation.id)

    assert invitation.status == status
    assert audit.events(INVITATION_REVOKED_EVENT) == []


# ===========================================================================
# Pure: lazy expiry (R12.3, R12.5)
# ===========================================================================


def test_expire_if_needed_materialises_expired_and_audits():
    """R12.3/R12.5: a due PENDING invitation → EXPIRED with one audit event."""
    service, repo, audit, _lookup = _pure_service()
    invitation = repo.add_invitation(
        inviter_user_id=uuid.uuid4(), expires_at=_past()
    )

    expired = service.expire_if_needed(invitation, request_id="req-exp")

    assert expired is True
    assert invitation.status == Invitation_Status.EXPIRED
    assert invitation.expired_at is not None
    events = audit.events(INVITATION_EXPIRED_EVENT)
    assert len(events) == 1
    call = events[0]
    # System-originated (no known actor), content-free.
    assert call["actor_type"] == "SYSTEM"
    assert call["actor_id"] is None
    assert call["resource_type"] == INVITATION_RESOURCE_TYPE
    assert call["resource_id"] == invitation.id
    assert call["outcome"] == "SUCCESS"
    assert call.get("metadata") in (None, {})


def test_expire_if_needed_live_invitation_is_untouched():
    """A not-yet-due PENDING invitation stays PENDING and is not audited."""
    service, repo, audit, _lookup = _pure_service()
    invitation = repo.add_invitation(
        inviter_user_id=uuid.uuid4(), expires_at=_future()
    )

    assert service.expire_if_needed(invitation) is False
    assert invitation.status == Invitation_Status.PENDING
    assert audit.calls == []


def test_expire_if_needed_is_idempotent_and_audits_once():
    """Re-evaluating an already-EXPIRED invitation does not double-audit."""
    service, repo, audit, _lookup = _pure_service()
    invitation = repo.add_invitation(
        inviter_user_id=uuid.uuid4(), expires_at=_past()
    )

    assert service.expire_if_needed(invitation) is True
    # Second call: already EXPIRED — reports not-acceptable, writes no new audit.
    assert service.expire_if_needed(invitation) is True
    assert len(audit.events(INVITATION_EXPIRED_EVENT)) == 1


def test_decline_of_due_pending_expires_then_404():
    """R12.3/R12.4: declining a due PENDING invitation expires it, then 404."""
    service, repo, audit, lookup = _pure_service()
    invitation = repo.add_invitation(
        inviter_user_id=uuid.uuid4(), expires_at=_past()
    )
    invitee = _actor()
    lookup.add(invitee.user_id, INVITEE_IDENTIFIER)

    with pytest.raises(ResourceNotFoundError):
        service.decline_invitation(invitee, invitation.id)

    assert invitation.status == Invitation_Status.EXPIRED
    assert len(audit.events(INVITATION_EXPIRED_EVENT)) == 1
    assert audit.events(INVITATION_DECLINED_EVENT) == []


def test_cancel_of_due_pending_expires_then_404():
    """R12.3/R12.4: cancelling a due PENDING invitation expires it, then 404."""
    service, repo, audit, _lookup = _pure_service()
    inviter = _actor()
    invitation = repo.add_invitation(
        inviter_user_id=inviter.user_id, expires_at=_past()
    )

    with pytest.raises(ResourceNotFoundError):
        service.cancel_invitation(inviter, invitation.id)

    assert invitation.status == Invitation_Status.EXPIRED
    assert len(audit.events(INVITATION_EXPIRED_EVENT)) == 1
    assert audit.events(INVITATION_REVOKED_EVENT) == []


# ===========================================================================
# Property: a terminal transition never adds a membership and audits once
# (Feature: foundation-auth-couples)
# ===========================================================================


@settings(max_examples=50, deadline=None)
@given(
    decision=st.sampled_from(["decline", "cancel", "expire"]),
    ttl=st.integers(60, 30 * 24 * 3600),
)
def test_property_terminal_transition_audits_once_no_membership(decision, ttl):
    """Property: any PENDING invitation driven to a terminal state records exactly
    one matching audit event, never adds a membership, and leaves the invitation
    in the expected terminal status.

    Feature: foundation-auth-couples

    **Validates: Requirements 12.5**
    """
    service, repo, audit, lookup = _pure_service()
    inviter = _actor()
    invitee = _actor()
    lookup.add(invitee.user_id, INVITEE_IDENTIFIER)

    if decision == "expire":
        invitation = repo.add_invitation(
            inviter_user_id=inviter.user_id, expires_at=_past()
        )
        assert service.expire_if_needed(invitation) is True
        expected_status = Invitation_Status.EXPIRED
        expected_event = INVITATION_EXPIRED_EVENT
    elif decision == "decline":
        invitation = repo.add_invitation(
            inviter_user_id=inviter.user_id, expires_at=_future(ttl)
        )
        service.decline_invitation(invitee, invitation.id)
        expected_status = Invitation_Status.DECLINED
        expected_event = INVITATION_DECLINED_EVENT
    else:  # cancel
        invitation = repo.add_invitation(
            inviter_user_id=inviter.user_id, expires_at=_future(ttl)
        )
        service.cancel_invitation(inviter, invitation.id)
        expected_status = Invitation_Status.REVOKED
        expected_event = INVITATION_REVOKED_EVENT

    assert invitation.status == expected_status
    assert len(audit.events(expected_event)) == 1
    assert repo.members == {}


# ===========================================================================
# DB-backed (defense in depth): real repo + real indexes
# ===========================================================================


def _create_couples_tables(session):
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            Couple.__table__,
            CoupleMember.__table__,
            CoupleInvitation.__table__,
            PrivateReflection.__table__,
            User.__table__,
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
    user_repo = UserRepository(session)
    service = InvitationService(
        couple_repository=repo, audit_service=audit, user_lookup=user_repo
    )
    return service, repo, user_repo


def _persist_pending_invitation(
    session, repo, user_repo, *, expires_at=None, invitee_identifier=INVITEE_IDENTIFIER
):
    """Persist a PENDING couple (PARTNER_A) + a PENDING invitation for the invitee.

    Returns (couple, invitation, inviter_user, invitee_user).
    """
    inviter = user_repo.create(auth_identifier="inviter@example.test")
    invitee = user_repo.create(auth_identifier=invitee_identifier)
    couple = repo.create_couple_with_creator(inviter.id)
    invitation = repo.create_invitation(
        couple_id=couple.id,
        inviter_user_id=inviter.id,
        invitee_identifier=invitee_identifier,
        token_hash=tokens.hash_invitation_token(uuid.uuid4().hex),
        expires_at=expires_at or _future(),
    )
    session.flush()
    return couple, invitation, inviter, invitee


def test_db_decline_sets_declined_and_audits(pg_schema):
    """R12.1/R12.5 (DB): invitee declines → DECLINED, no PARTNER_B, audit row."""
    from app.audit.models import AuditEvent

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    couple, invitation, _inviter, invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo
    )

    service.decline_invitation(
        _actor(invitee.id), invitation.id, request_id="req-dec"
    )
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.DECLINED
    assert inv_row.declined_at is not None
    # No PARTNER_B membership added.
    partner_b = (
        pg_schema.query(CoupleMember)
        .filter(
            CoupleMember.couple_id == couple.id,
            CoupleMember.role == Member_Role.PARTNER_B,
        )
        .count()
    )
    assert partner_b == 0
    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == INVITATION_DECLINED_EVENT)
        .all()
    )
    assert len(events) == 1
    assert events[0].resource_id == invitation.id


def test_db_decline_by_non_invitee_privacy_safe(pg_schema):
    """R12.1 (DB): a user who is not the invitee cannot decline → 404, unchanged."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    _couple, invitation, _inviter, _invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo
    )
    stranger = user_repo.create(auth_identifier="stranger@example.test")
    pg_schema.flush()

    with pytest.raises(ResourceNotFoundError):
        service.decline_invitation(_actor(stranger.id), invitation.id)
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.PENDING


def test_db_cancel_sets_revoked_and_audits(pg_schema):
    """R12.2/R12.5 (DB): inviter cancels → REVOKED, audit row."""
    from app.audit.models import AuditEvent

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    _couple, invitation, inviter, _invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo
    )

    service.cancel_invitation(_actor(inviter.id), invitation.id)
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.REVOKED
    assert inv_row.revoked_at is not None
    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == INVITATION_REVOKED_EVENT)
        .all()
    )
    assert len(events) == 1
    assert events[0].resource_id == invitation.id


def test_db_cancel_by_invitee_denied(pg_schema):
    """R12.2 (DB): the invitee is not the inviter and cannot cancel → 404."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    _couple, invitation, _inviter, invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo
    )

    with pytest.raises(ResourceNotFoundError):
        service.cancel_invitation(_actor(invitee.id), invitation.id)
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.PENDING


def test_db_expire_materialises_and_audits(pg_schema):
    """R12.3/R12.5 (DB): a due PENDING invitation → EXPIRED with one audit row."""
    from app.audit.models import AuditEvent

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    _couple, invitation, _inviter, _invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo, expires_at=_past()
    )

    inv = pg_schema.get(CoupleInvitation, invitation.id)
    assert service.expire_if_needed(inv) is True
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.EXPIRED
    assert inv_row.expired_at is not None
    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == INVITATION_EXPIRED_EVENT)
        .all()
    )
    assert len(events) == 1
    assert events[0].resource_id == invitation.id
    assert events[0].actor_type == "SYSTEM"


def test_db_accept_of_expired_invitation_rejected_and_materialises(pg_schema):
    """R12.3/R12.4 (DB): accepting a due invitation expires it then 404."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo, user_repo = _db_service(pg_schema)
    _couple, invitation, _inviter, _invitee = _persist_pending_invitation(
        pg_schema, repo, user_repo, expires_at=_past()
    )
    # We need the raw token to accept; re-create the invitation with a known raw.
    raw = "expired-accept-token"
    invitation.token_hash = tokens.hash_invitation_token(raw)
    pg_schema.flush()

    with pytest.raises(ResourceNotFoundError):
        service.accept_invitation(_actor(), raw)
    pg_schema.flush()

    inv_row = pg_schema.get(CoupleInvitation, invitation.id)
    assert inv_row.status == Invitation_Status.EXPIRED
