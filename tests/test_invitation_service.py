"""Tests for InvitationService.create_invitation (task 10.1).

Covers R10.1, R10.2, R10.4, R10.5, R10.6. Two layers, mirroring the couple
service tests:

* **Pure / unit** — an in-memory fake repository plus a recording audit service
  drive the service logic without a database. These prove: only an ACTIVE member
  of a PENDING couple may invite and non-members get a privacy-safe 404 (R10.1
  / R17.3 style); the raw token is generated, only its hash is stored, and the
  raw value is returned exactly once and never persisted (R10.1); status is
  PENDING with a future ``expires_at`` (R10.2); the invitee reference is recorded
  (R10.4); a further invitation is rejected once both roles are actively filled
  (R10.5); and a content-free ``INVITATION_CREATED`` audit event is written
  (R10.6).

* **DB-backed (defense in depth)** — using the ``pg_schema`` fixture with the
  REAL unique index ``uq_couple_invitations_token_hash`` (as authored in
  migration ``0002_foundation_schema``), real rows are written through
  :class:`CoupleRepository`. These prove only the hash is persisted, the raw
  token is absent from every column, and the unique ``token_hash`` index is
  exercised (a duplicate hash is rejected at the database).
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
from app.config import Settings
from app.couples import tokens
from app.couples.models import Couple, CoupleInvitation, CoupleMember
from app.couples.repository import (
    ACTIVE_MEMBER_UNIQUE_INDEX,
    INVITATION_TOKEN_HASH_UNIQUE_INDEX,
    CoupleRepository,
)
from app.couples.schemas import InvitationCreate, RawInvitationToken
from app.couples.service import (
    INVITATION_CREATED_EVENT,
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
from app.errors import AuthorizationError, ResourceNotFoundError


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


# --- Pure test doubles ------------------------------------------------------


class _RecordingAudit:
    """Captures record() calls without a database."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs


class _FakeCoupleRepository:
    """In-memory stand-in mirroring the CoupleRepository contract used here."""

    def __init__(self) -> None:
        self.couples: dict[uuid.UUID, Couple] = {}
        self.members: dict[tuple[uuid.UUID, uuid.UUID], CoupleMember] = {}
        self.invitations: dict[uuid.UUID, CoupleInvitation] = {}

    # -- reads --

    def get_couple(self, couple_id):
        return self.couples.get(couple_id)

    def get_membership(self, couple_id, user_id):
        return self.members.get((couple_id, user_id))

    def get_active_membership(self, couple_id, user_id):
        member = self.members.get((couple_id, user_id))
        if member is None or member.status != Member_Status.ACTIVE:
            return None
        return member

    def active_member_roles(self, couple_id):
        return {
            m.role
            for (c_id, _u_id), m in self.members.items()
            if c_id == couple_id and m.status == Member_Status.ACTIVE
        }

    def both_roles_actively_filled(self, couple_id):
        return {
            Member_Role.PARTNER_A,
            Member_Role.PARTNER_B,
        } <= self.active_member_roles(couple_id)

    # -- writes --

    def create_invitation(
        self,
        *,
        couple_id,
        inviter_user_id,
        invitee_identifier,
        token_hash,
        expires_at,
    ):
        # Enforce the unique-token_hash invariant the real DB index enforces.
        if any(inv.token_hash == token_hash for inv in self.invitations.values()):
            raise ValueError("duplicate token_hash")
        invitation = CoupleInvitation(
            id=uuid.uuid4(),
            couple_id=couple_id,
            inviter_user_id=inviter_user_id,
            invitee_identifier=invitee_identifier,
            token_hash=token_hash,
            status=Invitation_Status.PENDING,
            expires_at=expires_at,
        )
        self.invitations[invitation.id] = invitation
        return invitation

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
        self.members[(couple_id, user_id)] = member
        return member


def _pure_service(ttl_seconds: int = 7 * 24 * 3600):
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    settings = Settings(invitation_ttl_seconds=ttl_seconds)
    service = InvitationService(
        couple_repository=repo, audit_service=audit, settings=settings
    )
    return service, repo, audit


def _pending_couple_with_creator(repo):
    """Return (couple, inviter_actor) — a PENDING couple with an ACTIVE PARTNER_A."""
    inviter = _actor()
    couple = repo._add_couple(status=Couple_Status.PENDING)
    repo._add_member(couple.id, inviter.user_id, Member_Role.PARTNER_A)
    return couple, inviter


# ===========================================================================
# Pure: happy path (R10.1, R10.2, R10.4, R10.6)
# ===========================================================================


def test_create_invitation_returns_raw_token_and_stores_only_hash():
    """R10.1: raw token returned once; only its hash is persisted."""
    service, repo, _ = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)

    result = service.create_invitation(inviter, couple.id, "partner@example.test")

    assert isinstance(result, RawInvitationToken)
    assert result.raw_token  # non-empty raw token returned to the inviter

    invitation = repo.invitations[result.invitation_id]
    # The stored value is the HASH of the raw token, never the raw token itself.
    assert invitation.token_hash == tokens.hash_invitation_token(result.raw_token)
    assert invitation.token_hash != result.raw_token
    # No attribute anywhere on the persisted row holds the raw value.
    assert result.raw_token not in vars(invitation).values()


def test_create_invitation_token_is_unpredictable_and_unique_per_call():
    """R10.1: two invitations yield distinct, high-entropy raw tokens/hashes."""
    service, repo, _ = _pure_service()
    couple_a, inviter_a = _pending_couple_with_creator(repo)
    couple_b, inviter_b = _pending_couple_with_creator(repo)

    first = service.create_invitation(inviter_a, couple_a.id, "a@example.test")
    second = service.create_invitation(inviter_b, couple_b.id, "b@example.test")

    assert first.raw_token != second.raw_token
    assert (
        repo.invitations[first.invitation_id].token_hash
        != repo.invitations[second.invitation_id].token_hash
    )
    # token_urlsafe(32) => 43 chars of URL-safe base64: plenty of entropy.
    assert len(first.raw_token) >= 40


def test_create_invitation_sets_pending_status_and_future_expiry():
    """R10.2: status is PENDING and expires_at is in the future."""
    service, repo, _ = _pure_service(ttl_seconds=3600)
    couple, inviter = _pending_couple_with_creator(repo)

    before = datetime.now(timezone.utc)
    result = service.create_invitation(inviter, couple.id, "partner@example.test")
    invitation = repo.invitations[result.invitation_id]

    assert invitation.status == Invitation_Status.PENDING
    assert invitation.expires_at > before
    assert result.expires_at == invitation.expires_at
    # Roughly one hour out (allow slack for execution time).
    assert invitation.expires_at <= before + timedelta(seconds=3600 + 60)


def test_create_invitation_records_invitee_reference():
    """R10.4: the invitee reference is recorded on the invitation."""
    service, repo, _ = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)

    result = service.create_invitation(inviter, couple.id, "chosen@example.test")

    invitation = repo.invitations[result.invitation_id]
    assert invitation.invitee_identifier == "chosen@example.test"
    assert invitation.inviter_user_id == inviter.user_id
    assert invitation.couple_id == couple.id


def test_create_invitation_records_content_free_audit_event():
    """R10.6: a content-free INVITATION_CREATED audit event is recorded."""
    service, repo, audit = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)

    result = service.create_invitation(
        inviter, couple.id, "partner@example.test", request_id="req-inv"
    )

    created = [c for c in audit.calls if c["event_type"] == INVITATION_CREATED_EVENT]
    assert len(created) == 1
    call = created[0]
    assert call["resource_type"] == INVITATION_RESOURCE_TYPE
    assert call["resource_id"] == result.invitation_id
    assert call["actor_id"] == inviter.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-inv"
    # No relationship content (e.g. the invitee identifier) leaks into the audit.
    assert call.get("metadata") in (None, {})


# ===========================================================================
# Pure: authorization gates (R10.1 — active member of a PENDING couple only)
# ===========================================================================


def test_create_invitation_non_member_gets_privacy_safe_not_found():
    """R10.1/R17.3: a non-member gets 404 and no invitation is created."""
    service, repo, audit = _pure_service()
    couple, _inviter = _pending_couple_with_creator(repo)
    stranger = _actor()

    with pytest.raises(ResourceNotFoundError):
        service.create_invitation(stranger, couple.id, "partner@example.test")

    assert repo.invitations == {}
    assert audit.calls == []


def test_create_invitation_missing_couple_and_non_member_indistinguishable():
    """R17.3: an unknown couple raises the SAME error as a non-member."""
    service, repo, _ = _pure_service()
    couple, _inviter = _pending_couple_with_creator(repo)
    stranger = _actor()

    with pytest.raises(ResourceNotFoundError) as forbidden:
        service.create_invitation(stranger, couple.id, "p@example.test")
    with pytest.raises(ResourceNotFoundError) as missing:
        service.create_invitation(stranger, uuid.uuid4(), "p@example.test")

    assert type(forbidden.value) is type(missing.value)
    assert forbidden.value.code == missing.value.code == "RESOURCE_NOT_FOUND"
    assert forbidden.value.http_status == missing.value.http_status == 404


def test_create_invitation_disconnected_member_treated_as_non_member():
    """A merely-DISCONNECTED member cannot invite (R10.1/R17.3)."""
    service, repo, _ = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)
    repo.members[(couple.id, inviter.user_id)].status = Member_Status.DISCONNECTED

    with pytest.raises(ResourceNotFoundError):
        service.create_invitation(inviter, couple.id, "partner@example.test")
    assert repo.invitations == {}


@pytest.mark.parametrize(
    "status", [Couple_Status.ACTIVE, Couple_Status.DISCONNECTED]
)
def test_create_invitation_rejected_when_couple_not_pending(status):
    """R10.1: only a PENDING couple may receive an invitation.

    A member of a non-PENDING couple is forbidden (403) — existence is already
    known to a member, so 403 rather than a privacy-safe 404 is honest here.
    """
    service, repo, audit = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)
    couple.status = status

    with pytest.raises(AuthorizationError) as exc:
        service.create_invitation(inviter, couple.id, "partner@example.test")
    assert exc.value.http_status == 403
    assert repo.invitations == {}
    assert audit.calls == []


# ===========================================================================
# Pure: both-roles-filled rejection (R10.5)
# ===========================================================================


def test_create_invitation_rejected_when_both_roles_actively_filled():
    """R10.5: no further invitation once both roles have ACTIVE members."""
    service, repo, audit = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)
    # Add an ACTIVE PARTNER_B so both roles are filled.
    repo._add_member(couple.id, uuid.uuid4(), Member_Role.PARTNER_B)

    with pytest.raises(AuthorizationError) as exc:
        service.create_invitation(inviter, couple.id, "partner@example.test")
    assert exc.value.http_status == 403
    assert repo.invitations == {}
    assert audit.calls == []


def test_create_invitation_allowed_when_partner_b_only_disconnected():
    """R10.5: a DISCONNECTED PARTNER_B leaves that role vacant — invite allowed."""
    service, repo, _ = _pure_service()
    couple, inviter = _pending_couple_with_creator(repo)
    repo._add_member(
        couple.id,
        uuid.uuid4(),
        Member_Role.PARTNER_B,
        status=Member_Status.DISCONNECTED,
    )
    # Couple must still be PENDING for the invite gate; it is by construction.

    result = service.create_invitation(inviter, couple.id, "partner@example.test")
    assert result.invitation_id in repo.invitations


# ===========================================================================
# Pure: server-controlled fields never accepted from the client (R10.1/R10.2)
# ===========================================================================


def test_invitation_create_schema_carries_only_invitee_reference():
    """InvitationCreate models only the invitee ref — no status/token/expiry."""
    assert set(InvitationCreate.model_fields) == {"invitee_identifier"}


def test_invitation_create_schema_rejects_client_supplied_server_fields():
    """A client cannot smuggle status/token_hash/expires_at into the request."""
    with pytest.raises(Exception):
        InvitationCreate(
            invitee_identifier="p@example.test",
            status="ACCEPTED",  # type: ignore[call-arg]
        )
    with pytest.raises(Exception):
        InvitationCreate(
            invitee_identifier="p@example.test",
            token_hash="deadbeef",  # type: ignore[call-arg]
        )


# ===========================================================================
# Property: created invitations are always PENDING, hash-only, future-dated,
# and never leak the raw token (Feature: foundation-auth-couples)
# ===========================================================================


@settings(max_examples=50, deadline=None)
@given(
    invitee=st.text(min_size=1, max_size=64),
    ttl=st.integers(min_value=60, max_value=30 * 24 * 3600),
)
def test_property_created_invitation_invariants(invitee, ttl):
    """Property: for any invitee reference and TTL, a created invitation is
    PENDING, stores only the token hash (never the raw token), expires in the
    future, and returns the raw token exactly once.

    Feature: foundation-auth-couples

    **Validates: Requirements 10.1, 10.2**
    """
    service, repo, _ = _pure_service(ttl_seconds=ttl)
    couple, inviter = _pending_couple_with_creator(repo)

    before = datetime.now(timezone.utc)
    result = service.create_invitation(inviter, couple.id, invitee)
    invitation = repo.invitations[result.invitation_id]

    # Server-controlled status and expiry (R10.2).
    assert invitation.status == Invitation_Status.PENDING
    assert invitation.expires_at > before
    # Only the hash is stored; the raw token round-trips through the hash (R10.1).
    assert invitation.token_hash == tokens.hash_invitation_token(result.raw_token)
    assert invitation.token_hash != result.raw_token
    # The invitee reference is recorded verbatim (R10.4).
    assert invitation.invitee_identifier == invitee


# ===========================================================================
# DB-backed (defense in depth): real repo + real token_hash unique index
# ===========================================================================


def _create_couples_tables(session):
    """Create couples/couple_members/couple_invitations and the REAL indexes.

    ``Base.metadata.create_all`` produces the tables but NOT the partial/unique
    indexes (those live in the migration). We add the two that matter here:
    the at-most-one-ACTIVE-couple index and the unique ``token_hash`` index, so
    DB-level invariants are exercised as authored in ``0002_foundation_schema``.
    """
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            Couple.__table__,
            CoupleMember.__table__,
            CoupleInvitation.__table__,
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


def _persist_pending_couple(session, repo):
    """Persist a PENDING couple + ACTIVE PARTNER_A; return (couple, inviter)."""
    inviter = _actor()
    couple = repo.create_couple_with_creator(inviter.user_id)
    session.flush()
    return couple, inviter


def test_db_create_invitation_persists_hash_only(pg_schema):
    """R10.1 (DB): only the token hash is stored; raw token absent everywhere."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    couple, inviter = _persist_pending_couple(pg_schema, repo)

    result = service.create_invitation(inviter, couple.id, "partner@example.test")
    pg_schema.flush()

    row = pg_schema.get(CoupleInvitation, result.invitation_id)
    assert row is not None
    assert row.status == Invitation_Status.PENDING
    assert row.token_hash == tokens.hash_invitation_token(result.raw_token)
    assert row.expires_at > datetime.now(timezone.utc)
    assert row.invitee_identifier == "partner@example.test"

    # The raw token appears in NO column of the persisted row (R10.1).
    stored_values = [
        getattr(row, col.name) for col in CoupleInvitation.__table__.columns
    ]
    assert result.raw_token not in stored_values


def test_db_create_invitation_unique_token_hash_index_enforced(pg_schema):
    """The unique token_hash index rejects a duplicate hash at the database.

    Two invitations that (by construction) carry the same ``token_hash`` cannot
    both persist — the second insert violates
    ``uq_couple_invitations_token_hash`` (R10.1/R10.3). This proves the index is
    real and load-bearing, independent of the CSPRNG's collision resistance.
    """
    from sqlalchemy.exc import IntegrityError

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    _service, repo = _db_service(pg_schema)
    couple, inviter = _persist_pending_couple(pg_schema, repo)

    shared_hash = tokens.hash_invitation_token("collision-seed")
    expires = datetime.now(timezone.utc) + timedelta(days=1)

    repo.create_invitation(
        couple_id=couple.id,
        inviter_user_id=inviter.user_id,
        invitee_identifier="a@example.test",
        token_hash=shared_hash,
        expires_at=expires,
    )
    pg_schema.flush()

    with pytest.raises(IntegrityError):
        repo.create_invitation(
            couple_id=couple.id,
            inviter_user_id=inviter.user_id,
            invitee_identifier="b@example.test",
            token_hash=shared_hash,
            expires_at=expires,
        )
        pg_schema.flush()


def test_db_create_invitation_records_audit(pg_schema):
    """R10.6 (DB): an INVITATION_CREATED audit row is written on success."""
    from app.audit.models import AuditEvent

    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    couple, inviter = _persist_pending_couple(pg_schema, repo)

    result = service.create_invitation(inviter, couple.id, "partner@example.test")
    pg_schema.flush()

    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == INVITATION_CREATED_EVENT)
        .all()
    )
    assert len(events) == 1
    event = events[0]
    assert event.resource_type == INVITATION_RESOURCE_TYPE
    assert event.resource_id == result.invitation_id
    assert event.actor_id == inviter.user_id
    assert event.outcome == "SUCCESS"


def test_db_create_invitation_non_member_gets_not_found(pg_schema):
    """R10.1/R17.3 (DB): a non-member gets 404 and writes no invitation."""
    _create_couples_tables(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    couple, _inviter = _persist_pending_couple(pg_schema, repo)

    with pytest.raises(ResourceNotFoundError):
        service.create_invitation(_actor(), couple.id, "partner@example.test")

    assert pg_schema.query(CoupleInvitation).count() == 0
