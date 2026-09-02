"""Tests for CoupleService creation + get_couple (task 9.1).

Two layers are exercised:

* **Pure / unit** — an in-memory fake repository and a recording audit service
  drive the service logic without a database. These prove the create-and-enrol
  behaviour (R9.1), the ``COUPLE_CREATED`` audit (R9.5), the conflict rejection
  path (R9.2/R9.3), and the privacy-safe not-found for non-members (R17.3),
  including that a non-member and a non-existent couple are indistinguishable.

* **DB-backed (defense in depth)** — using the ``pg_schema`` fixture with the
  REAL partial unique index ``uq_couple_members_active_user`` (as authored in
  migration ``0002_foundation_schema``), real rows are written through
  :class:`CoupleRepository`. These prove the at-most-one-ACTIVE-couple rule is
  enforced by the database index itself, so it holds even where a
  read-then-write pre-check would race (R9.2/R9.3), and that ``get_couple``
  resolves membership from real state (R17.3).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import text

from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.couples.models import Couple, CoupleMember
from app.couples.repository import (
    ACTIVE_MEMBER_UNIQUE_INDEX,
    CoupleRepository,
)
from app.couples.schemas import CoupleView
from app.couples.service import (
    COUPLE_CREATED_EVENT,
    COUPLE_RESOURCE_TYPE,
    CoupleService,
)
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Role,
    Member_Status,
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


# --- Pure test doubles ------------------------------------------------------


class _RecordingAudit:
    """Captures record() calls without a database."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs


class _FakeCoupleRepository:
    """In-memory stand-in mirroring CoupleRepository's contract.

    Enforces the same at-most-one-ACTIVE-couple rule the real partial unique
    index enforces, so the service logic can be exercised without Postgres.
    """

    def __init__(self) -> None:
        self.couples: dict[uuid.UUID, Couple] = {}
        # (couple_id, user_id) -> CoupleMember
        self.members: dict[tuple[uuid.UUID, uuid.UUID], CoupleMember] = {}

    def _has_active_membership(self, user_id: uuid.UUID) -> bool:
        return any(
            m.user_id == user_id and m.status == Member_Status.ACTIVE
            for m in self.members.values()
        )

    def create_couple_with_creator(self, creator_user_id: uuid.UUID) -> Couple:
        if self._has_active_membership(creator_user_id):
            raise ActiveCoupleExistsError()
        couple = Couple(id=uuid.uuid4(), status=Couple_Status.PENDING)
        # The real DB populates created_at via a server default on flush; the
        # fake mirrors that so the CoupleView projection validates.
        couple.created_at = datetime.now(timezone.utc)
        member = CoupleMember(
            id=uuid.uuid4(),
            couple_id=couple.id,
            user_id=creator_user_id,
            role=Member_Role.PARTNER_A,
            status=Member_Status.ACTIVE,
        )
        self.couples[couple.id] = couple
        self.members[(couple.id, creator_user_id)] = member
        return couple

    def get_couple(self, couple_id: uuid.UUID) -> Couple | None:
        return self.couples.get(couple_id)

    def get_membership(self, couple_id, user_id):
        return self.members.get((couple_id, user_id))

    def get_active_membership(self, couple_id, user_id):
        member = self.members.get((couple_id, user_id))
        if member is None or member.status != Member_Status.ACTIVE:
            return None
        return member


def _pure_service():
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    return CoupleService(couple_repository=repo, audit_service=audit), repo, audit


# ---------------------------------------------------------------------------
# Pure: create_couple (R9.1, R9.5)
# ---------------------------------------------------------------------------

def test_create_couple_creates_pending_couple_and_partner_a_member():
    """R9.1: new PENDING couple + creator enrolled as ACTIVE PARTNER_A."""
    service, repo, _ = _pure_service()
    actor = _actor()

    view = service.create_couple(actor)

    assert isinstance(view, CoupleView)
    assert view.status == Couple_Status.PENDING

    couple = repo.get_couple(view.id)
    assert couple is not None
    assert couple.status == Couple_Status.PENDING

    member = repo.get_membership(view.id, actor.user_id)
    assert member is not None
    assert member.role == Member_Role.PARTNER_A
    assert member.status == Member_Status.ACTIVE


def test_create_couple_records_couple_created_audit():
    """R9.5: a content-free COUPLE_CREATED audit event is recorded."""
    service, _, audit = _pure_service()
    actor = _actor()

    view = service.create_couple(actor, request_id="req-1")

    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["event_type"] == COUPLE_CREATED_EVENT
    assert call["resource_type"] == COUPLE_RESOURCE_TYPE
    assert call["resource_id"] == view.id
    assert call["actor_id"] == actor.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-1"
    # No relationship content in the audit call.
    assert call.get("metadata") in (None, {})


def test_create_couple_rejects_actor_with_active_couple():
    """R9.2/R9.3: a second create by the same actor is rejected, no audit."""
    service, _, audit = _pure_service()
    actor = _actor()

    service.create_couple(actor)
    with pytest.raises(ActiveCoupleExistsError):
        service.create_couple(actor)

    # Only the first (successful) create emitted an audit event.
    assert len(audit.calls) == 1


def test_create_couple_view_has_no_client_writable_status_input():
    """R13.7: CoupleView is a read-only response projection.

    There is no request schema that accepts a client-supplied status; the view
    surfaces the server-controlled status only for rendering. Constructing the
    view from arbitrary keyword input must not let a caller override the
    server-set status through a hidden field.
    """
    # CoupleView exposes exactly the server-controlled read fields.
    assert set(CoupleView.model_fields) == {
        "id",
        "status",
        "created_at",
        "activated_at",
        "disconnected_at",
    }


# ---------------------------------------------------------------------------
# Pure: get_couple (R17.3)
# ---------------------------------------------------------------------------

def test_get_couple_returns_view_for_active_member():
    service, _, _ = _pure_service()
    actor = _actor()
    created = service.create_couple(actor)

    view = service.get_couple(actor, created.id)
    assert view.id == created.id
    assert view.status == Couple_Status.PENDING


def test_get_couple_non_member_gets_privacy_safe_not_found():
    """R17.3: a non-member gets 404, never confirming the couple exists."""
    service, _, _ = _pure_service()
    owner = _actor()
    created = service.create_couple(owner)

    stranger = _actor()
    with pytest.raises(ResourceNotFoundError):
        service.get_couple(stranger, created.id)


def test_get_couple_missing_couple_and_non_member_are_indistinguishable():
    """R17.3: a non-existent couple raises the SAME error as a forbidden one."""
    service, _, _ = _pure_service()
    owner = _actor()
    created = service.create_couple(owner)
    stranger = _actor()

    # Existing couple, non-member.
    with pytest.raises(ResourceNotFoundError) as forbidden:
        service.get_couple(stranger, created.id)
    # Couple that does not exist at all.
    with pytest.raises(ResourceNotFoundError) as missing:
        service.get_couple(stranger, uuid.uuid4())

    assert type(forbidden.value) is type(missing.value)
    assert forbidden.value.code == missing.value.code == "RESOURCE_NOT_FOUND"
    assert forbidden.value.http_status == missing.value.http_status == 404


def test_get_couple_disconnected_member_treated_as_non_member():
    """A merely-DISCONNECTED member is not an active member (R17.3)."""
    service, repo, _ = _pure_service()
    actor = _actor()
    created = service.create_couple(actor)

    # Simulate disconnection.
    repo.members[(created.id, actor.user_id)].status = Member_Status.DISCONNECTED

    with pytest.raises(ResourceNotFoundError):
        service.get_couple(actor, created.id)


# ---------------------------------------------------------------------------
# DB-backed helpers (defense in depth) — pg_schema fixture with the REAL index
# ---------------------------------------------------------------------------

def _create_tables_with_active_index(session):
    """Create couples/couple_members and the REAL partial unique index.

    ``Base.metadata.create_all`` produces the tables but NOT the partial unique
    index (that lives in the migration, not the ORM model). We add it here so
    the at-most-one-ACTIVE-couple rule is enforced by the same
    ``user_id WHERE status = 'ACTIVE'`` index the migration authors.
    """
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[Couple.__table__, CoupleMember.__table__],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{ACTIVE_MEMBER_UNIQUE_INDEX}" '
            "ON couple_members (user_id) WHERE status = 'ACTIVE'"
        )
    )
    session.flush()


def _create_audit_table(session):
    from app.audit.models import AuditEvent

    AuditEvent.__table__.create(bind=session.connection())


def _db_service(session):
    audit = AuditService(AuditRepository(session))
    repo = CoupleRepository(session)
    return CoupleService(couple_repository=repo, audit_service=audit), repo


# ---------------------------------------------------------------------------
# DB-backed: creation persists rows + at-most-one-ACTIVE via the real index
# ---------------------------------------------------------------------------

def test_db_create_couple_persists_pending_couple_and_member(pg_schema):
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    actor = _actor()

    view = service.create_couple(actor)
    pg_schema.flush()

    couple = repo.get_couple(view.id)
    assert couple is not None
    assert couple.status == Couple_Status.PENDING

    member = repo.get_active_membership(view.id, actor.user_id)
    assert member is not None
    assert member.role == Member_Role.PARTNER_A
    assert member.status == Member_Status.ACTIVE
    assert member.joined_at is not None


def test_db_create_couple_rejected_by_real_partial_unique_index(pg_schema):
    """R9.2/R9.3: the DB index rejects a second ACTIVE membership for the actor.

    This is the authoritative enforcement: the second create is blocked by the
    real ``uq_couple_members_active_user`` partial unique index, surfaced as
    ActiveCoupleExistsError — the guard that holds under concurrency.
    """
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    actor = _actor()

    first = service.create_couple(actor)
    pg_schema.flush()

    with pytest.raises(ActiveCoupleExistsError):
        service.create_couple(actor)

    # The session is still usable and the first couple is intact (only the
    # rejected insert was rolled back via the SAVEPOINT).
    assert repo.get_couple(first.id) is not None
    active_members = (
        pg_schema.query(CoupleMember)
        .filter(
            CoupleMember.user_id == actor.user_id,
            CoupleMember.status == Member_Status.ACTIVE,
        )
        .count()
    )
    assert active_members == 1


def test_db_disconnected_membership_allows_new_active_couple(pg_schema):
    """The partial index only constrains ACTIVE rows: once a prior membership is
    DISCONNECTED, the actor may hold a new ACTIVE membership."""
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    service, repo = _db_service(pg_schema)
    actor = _actor()

    first = service.create_couple(actor)
    pg_schema.flush()

    # Disconnect the first membership.
    member = repo.get_membership(first.id, actor.user_id)
    member.status = Member_Status.DISCONNECTED
    pg_schema.flush()

    # A new couple can now be created for the same actor.
    second = service.create_couple(actor)
    pg_schema.flush()
    assert second.id != first.id
    assert repo.get_active_membership(second.id, actor.user_id) is not None


def test_db_two_different_users_can_each_create_a_couple(pg_schema):
    """The index is per-user: distinct actors are unaffected by each other."""
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    service, _ = _db_service(pg_schema)

    a = service.create_couple(_actor())
    b = service.create_couple(_actor())
    pg_schema.flush()
    assert a.id != b.id


def test_db_get_couple_membership_resolved_from_state(pg_schema):
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    service, _ = _db_service(pg_schema)
    actor = _actor()

    created = service.create_couple(actor)
    pg_schema.flush()

    # Active member sees the couple.
    view = service.get_couple(actor, created.id)
    assert view.id == created.id

    # Non-member gets a privacy-safe not-found (R17.3).
    with pytest.raises(ResourceNotFoundError):
        service.get_couple(_actor(), created.id)


# ---------------------------------------------------------------------------
# Property: at most one ACTIVE couple per actor, regardless of create attempts
# (Feature: foundation-auth-couples)
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(attempts=st.integers(min_value=1, max_value=6))
def test_property_actor_has_at_most_one_active_couple(attempts):
    """Property: however many times an actor calls create_couple, they end up an
    ACTIVE member of at most one couple; every attempt after the first is
    rejected (R9.2/R9.3).

    Uses the in-memory repository whose invariant mirrors the real partial
    unique index, so the property holds over many create sequences without a
    database.

    Feature: foundation-auth-couples

    **Validates: Requirements 9.2, 9.3**
    """
    service, repo, _ = _pure_service()
    actor = _actor()

    successes = 0
    rejections = 0
    for _ in range(attempts):
        try:
            service.create_couple(actor)
            successes += 1
        except ActiveCoupleExistsError:
            rejections += 1

    active = [
        m
        for m in repo.members.values()
        if m.user_id == actor.user_id and m.status == Member_Status.ACTIVE
    ]
    assert len(active) <= 1
    assert successes == 1
    assert rejections == attempts - 1


# ===========================================================================
# Disconnect flow (task 9.2) — R13.2, R13.3, R13.6, R13.7, R5.3
# ===========================================================================
#
# Two layers, mirroring the create/get tests:
#
# * Pure/unit — the in-memory fake repository (extended with the atomic
#   disconnect) and a fake AuthenticationService drive the service gates: active
#   membership first (privacy-safe 404 for non-members, R17.3-style), then the
#   re-auth gate for COUPLE_DISCONNECTION (R5.3/R13.2), then the atomic status
#   transition (R13.2) and the content-free COUPLE_DISCONNECTED audit (R13.6).
#   R13.7 is covered by the method taking no client status.
#
# * DB-backed — using the REAL CoupleRepository + a REAL AuthenticationService
#   over an ephemeral schema, disconnect flips the couple + both members to
#   DISCONNECTED in one transaction, only an ACTIVE couple is eligible, and — as
#   the enforcement of R13.3 — a SHARED_COUPLE authorization decision that was
#   ALLOW while ACTIVE becomes DENY (COUPLE_NOT_ACTIVE) once disconnected.

from app.auth.service import ReauthToken, Sensitive_Operation
from app.couples.service import COUPLE_DISCONNECTED_EVENT
from app.errors import ReauthRequiredError


# --- Pure test doubles for the disconnect flow ------------------------------


class _FakeAuth:
    """Records consume_reauthentication calls; returns a configurable result.

    Mirrors the one method CoupleService.disconnect_couple depends on. ``ok``
    controls whether the (single) grant is accepted; ``calls`` captures the
    (grant, actor, operation) tuples so tests can assert the correct operation
    type was demanded (R5.3).
    """

    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.calls: list[tuple] = []

    def consume_reauthentication(self, grant, actor, operation_type):
        self.calls.append((grant, actor, operation_type))
        return self.ok


def _grant(user_id: uuid.UUID | None = None) -> ReauthToken:
    return ReauthToken(
        grant_id=uuid.uuid4().hex,
        token="reauth-secret",
        operation_type=Sensitive_Operation.COUPLE_DISCONNECTION,
    )


# Extend the in-memory fake repository with the atomic disconnect so the pure
# service tests exercise the same contract as the real repository.
def _fake_disconnect_couple_atomic(self, couple_id):
    couple = self.couples.get(couple_id)
    if couple is None or couple.status != Couple_Status.ACTIVE:
        raise ResourceNotFoundError()
    couple.status = Couple_Status.DISCONNECTED
    couple.disconnected_at = datetime.now(timezone.utc)
    for (c_id, _u_id), member in self.members.items():
        if c_id == couple_id:
            member.status = Member_Status.DISCONNECTED
            member.left_at = datetime.now(timezone.utc)
    return couple


_FakeCoupleRepository.disconnect_couple_atomic = _fake_disconnect_couple_atomic


def _active_couple_with_two_members(repo):
    """Build an ACTIVE couple in the fake repo with two ACTIVE members.

    Returns (couple, actor_a, actor_b). create_couple_with_creator only adds
    PARTNER_A, so PARTNER_B (the accepted invitee) is added directly to model a
    fully-formed ACTIVE couple ready to disconnect.
    """
    actor_a = _actor()
    actor_b = _actor()
    couple = repo.create_couple_with_creator(actor_a.user_id)
    couple.status = Couple_Status.ACTIVE
    couple.activated_at = datetime.now(timezone.utc)
    repo.members[(couple.id, actor_b.user_id)] = CoupleMember(
        id=uuid.uuid4(),
        couple_id=couple.id,
        user_id=actor_b.user_id,
        role=Member_Role.PARTNER_B,
        status=Member_Status.ACTIVE,
    )
    return couple, actor_a, actor_b


def _pure_disconnect_service(auth_ok: bool = True):
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    auth = _FakeAuth(ok=auth_ok)
    service = CoupleService(
        couple_repository=repo,
        audit_service=audit,
        authentication_service=auth,
    )
    return service, repo, audit, auth


# --- Pure: happy path (R13.2, R13.6) ---------------------------------------


def test_disconnect_sets_couple_and_both_members_disconnected():
    """R13.2: active member + re-auth -> couple + both members DISCONNECTED."""
    service, repo, _, _ = _pure_disconnect_service()
    couple, actor_a, actor_b = _active_couple_with_two_members(repo)

    view = service.disconnect_couple(actor_a, couple.id, _grant())

    assert view.status == Couple_Status.DISCONNECTED
    assert view.disconnected_at is not None
    assert repo.get_couple(couple.id).status == Couple_Status.DISCONNECTED
    for member in (
        repo.get_membership(couple.id, actor_a.user_id),
        repo.get_membership(couple.id, actor_b.user_id),
    ):
        assert member.status == Member_Status.DISCONNECTED
        assert member.left_at is not None


def test_disconnect_requires_reauth_for_couple_disconnection_operation():
    """R5.3/R13.2: the re-auth gate is consumed for COUPLE_DISCONNECTION."""
    service, repo, _, auth = _pure_disconnect_service()
    couple, actor_a, _ = _active_couple_with_two_members(repo)

    service.disconnect_couple(actor_a, couple.id, _grant())

    assert len(auth.calls) == 1
    _grant_arg, actor_arg, operation = auth.calls[0]
    assert operation == Sensitive_Operation.COUPLE_DISCONNECTION
    assert actor_arg is actor_a


def test_disconnect_records_content_free_audit_event():
    """R13.6: a content-free COUPLE_DISCONNECTED audit event is recorded."""
    service, repo, audit, _ = _pure_disconnect_service()
    couple, actor_a, _ = _active_couple_with_two_members(repo)

    service.disconnect_couple(actor_a, couple.id, _grant(), request_id="req-9")

    disconnect_calls = [
        c for c in audit.calls if c["event_type"] == COUPLE_DISCONNECTED_EVENT
    ]
    assert len(disconnect_calls) == 1
    call = disconnect_calls[0]
    assert call["resource_type"] == COUPLE_RESOURCE_TYPE
    assert call["resource_id"] == couple.id
    assert call["actor_id"] == actor_a.user_id
    assert call["outcome"] == "SUCCESS"
    assert call["request_id"] == "req-9"
    assert call.get("metadata") in (None, {})


# --- Pure: re-auth gate (R5.2/R13.2) ---------------------------------------


def test_disconnect_denied_when_reauth_fails():
    """R5.2/R13.2: a failing re-auth grant raises ReauthRequiredError (403)."""
    service, repo, audit, _ = _pure_disconnect_service(auth_ok=False)
    couple, actor_a, _ = _active_couple_with_two_members(repo)

    with pytest.raises(ReauthRequiredError) as exc:
        service.disconnect_couple(actor_a, couple.id, _grant())
    assert exc.value.http_status == 403

    # Nothing changed and no disconnect audit recorded.
    assert repo.get_couple(couple.id).status == Couple_Status.ACTIVE
    assert not any(
        c["event_type"] == COUPLE_DISCONNECTED_EVENT for c in audit.calls
    )


def test_disconnect_denied_when_no_authentication_service_wired():
    """Misconfiguration guard: no auth service -> denied, never disconnects."""
    audit = _RecordingAudit()
    repo = _FakeCoupleRepository()
    service = CoupleService(couple_repository=repo, audit_service=audit)
    couple, actor_a, _ = _active_couple_with_two_members(repo)

    with pytest.raises(ReauthRequiredError):
        service.disconnect_couple(actor_a, couple.id, _grant())
    assert repo.get_couple(couple.id).status == Couple_Status.ACTIVE


# --- Pure: membership gate is checked first (R17.3-style privacy safety) ----


def test_disconnect_non_member_gets_privacy_safe_not_found_before_reauth():
    """A non-member gets 404 and the re-auth gate is never consulted (R17.3).

    Checking membership first ensures the re-auth path cannot leak whether a
    couple exists to someone who is not a member.
    """
    service, repo, _, auth = _pure_disconnect_service()
    couple, _actor_a, _ = _active_couple_with_two_members(repo)
    stranger = _actor()

    with pytest.raises(ResourceNotFoundError):
        service.disconnect_couple(stranger, couple.id, _grant())

    # Re-auth was never attempted for the non-member, and nothing changed.
    assert auth.calls == []
    assert repo.get_couple(couple.id).status == Couple_Status.ACTIVE


def test_disconnect_missing_couple_and_non_member_indistinguishable():
    """R17.3: an unknown couple raises the SAME error as a non-member."""
    service, repo, _, _ = _pure_disconnect_service()
    couple, _actor_a, _ = _active_couple_with_two_members(repo)
    stranger = _actor()

    with pytest.raises(ResourceNotFoundError) as forbidden:
        service.disconnect_couple(stranger, couple.id, _grant())
    with pytest.raises(ResourceNotFoundError) as missing:
        service.disconnect_couple(stranger, uuid.uuid4(), _grant())

    assert type(forbidden.value) is type(missing.value)
    assert forbidden.value.code == missing.value.code == "RESOURCE_NOT_FOUND"


def test_disconnect_disconnected_member_treated_as_non_member():
    """A former (DISCONNECTED) member can no longer initiate a disconnect (R17.3)."""
    service, repo, _, _ = _pure_disconnect_service()
    couple, actor_a, _ = _active_couple_with_two_members(repo)
    repo.members[(couple.id, actor_a.user_id)].status = Member_Status.DISCONNECTED

    with pytest.raises(ResourceNotFoundError):
        service.disconnect_couple(actor_a, couple.id, _grant())


# --- Pure: only an ACTIVE couple disconnects; idempotency guard -------------


def test_disconnect_non_active_couple_rejected():
    """Only an ACTIVE couple is disconnected; a re-disconnect is not silent.

    After a successful disconnect the member is DISCONNECTED, so a second
    attempt is rejected at the membership gate (privacy-safe 404) — the couple
    is never disconnected twice.
    """
    service, repo, _, _ = _pure_disconnect_service()
    couple, actor_a, _ = _active_couple_with_two_members(repo)

    service.disconnect_couple(actor_a, couple.id, _grant())
    assert repo.get_couple(couple.id).status == Couple_Status.DISCONNECTED

    with pytest.raises(ResourceNotFoundError):
        service.disconnect_couple(actor_a, couple.id, _grant())


def test_disconnect_takes_no_client_supplied_status(monkeypatch):
    """R13.7: the disconnect API accepts no client-supplied Couple_Status.

    The method signature carries (actor, couple_id, reauth_grant) only — there
    is no parameter through which a client could set or influence the target
    status; the server always sets DISCONNECTED.
    """
    import inspect

    params = set(inspect.signature(CoupleService.disconnect_couple).parameters)
    # Only server-controlled inputs; no "status"-like client field.
    assert params == {"self", "actor", "couple_id", "reauth_grant", "request_id"}


# ---------------------------------------------------------------------------
# DB-backed disconnect (defense in depth) — real repo + real auth + real index
# ---------------------------------------------------------------------------


def _build_db_auth_service(session):
    """A real AuthenticationService wired over in-memory auth stores + DB audit.

    Reuses the auth-service test doubles (user repository, identity provider,
    session store, re-auth grant store) so we can mint and consume a REAL grant
    for COUPLE_DISCONNECTION, while auditing to the ephemeral schema. Returns
    ``(auth, users, audit)``.
    """
    from tests.test_authentication_service import (
        _FakeUserRepository,
        _InMemoryReauthStore,
        _InMemoryRecoveryStore,
        _InMemorySessionStore,
    )
    from app.auth.service import (
        AuthenticationService,
        InMemoryIdentityProvider,
        SessionService,
    )

    users = _FakeUserRepository()
    audit = AuditService(AuditRepository(session))
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    auth = AuthenticationService(
        user_repository=users,
        identity_provider=InMemoryIdentityProvider(),
        session_service=sessions,
        audit_service=audit,
        recovery_store=_InMemoryRecoveryStore(),
        reauth_store=_InMemoryReauthStore(),
    )
    return auth, users, audit


def _register_actor(auth, identifier: str, password: str = "pw") -> AuthenticatedActor:
    """Register a real credentialed user via the auth service; return its actor.

    Registration seeds both the user repository row and the identity provider
    credential, so ``require_reauthentication`` can verify a fresh proof for this
    actor and mint a real COUPLE_DISCONNECTION grant.
    """
    user = auth.register(identifier, password)
    return AuthenticatedActor(
        user_id=user.id, account_status=Account_Status.ACTIVE
    )


def _make_active_couple_db(session, repo, actor_a, actor_b):
    """Persist an ACTIVE couple with two ACTIVE members; return the couple."""
    couple = repo.create_couple_with_creator(actor_a.user_id)
    session.flush()
    # Promote to a fully ACTIVE couple with PARTNER_B (accepted invitee).
    couple.status = Couple_Status.ACTIVE
    couple.activated_at = datetime.now(timezone.utc)
    session.add(
        CoupleMember(
            id=uuid.uuid4(),
            couple_id=couple.id,
            user_id=actor_b.user_id,
            role=Member_Role.PARTNER_B,
            status=Member_Status.ACTIVE,
            joined_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return couple


def test_db_disconnect_flips_couple_and_both_members(pg_schema):
    """R13.2 (DB): couple + both members become DISCONNECTED in one go."""
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    repo = CoupleRepository(pg_schema)
    auth, users, audit = _build_db_auth_service(pg_schema)
    service = CoupleService(
        couple_repository=repo,
        audit_service=audit,
        authentication_service=auth,
    )
    actor_a = _register_actor(auth, "a1@example.test")
    actor_b = _register_actor(auth, "b1@example.test")
    couple = _make_active_couple_db(pg_schema, repo, actor_a, actor_b)

    # Mint a REAL re-auth grant for COUPLE_DISCONNECTION for actor_a.
    grant = auth.require_reauthentication(
        actor_a, "pw", Sensitive_Operation.COUPLE_DISCONNECTION
    )

    view = service.disconnect_couple(actor_a, couple.id, grant)
    pg_schema.flush()

    assert view.status == Couple_Status.DISCONNECTED
    assert repo.get_couple(couple.id).status == Couple_Status.DISCONNECTED
    for uid in (actor_a.user_id, actor_b.user_id):
        member = repo.get_membership(couple.id, uid)
        assert member.status == Member_Status.DISCONNECTED
        assert member.left_at is not None


def test_db_disconnect_disables_shared_couple_writes(pg_schema):
    """R13.3 (DB): a SHARED_COUPLE decision that was ALLOW becomes DENY.

    This proves the disconnect enforces R13.3 through the real authorization
    pipeline: while ACTIVE, an active member is allowed to write the couple's
    SHARED_COUPLE resource; once disconnected, Pattern B's lifecycle check
    (COUPLE_NOT_ACTIVE) denies the same write.
    """
    from app.authorization.models import (
        Action,
        AuthenticatedActor,
        DenyReason,
        ResourceDescriptor,
    )
    from app.authorization.service import AuthorizationService
    from app.authorization.resolver import SqlAlchemyRelationshipResolver
    from app.enums import Visibility_Scope

    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    repo = CoupleRepository(pg_schema)
    auth, users, audit = _build_db_auth_service(pg_schema)
    service = CoupleService(
        couple_repository=repo,
        audit_service=audit,
        authentication_service=auth,
    )
    actor_a = _register_actor(auth, "a2@example.test")
    actor_b = _register_actor(auth, "b2@example.test")
    couple = _make_active_couple_db(pg_schema, repo, actor_a, actor_b)

    authz = AuthorizationService(SqlAlchemyRelationshipResolver(pg_schema))
    shared_resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE,
        couple_id=couple.id,
        resource_id=uuid.uuid4(),
        resource_type="SharedCoupleNote",
    )
    member_actor = AuthenticatedActor(
        user_id=actor_a.user_id, account_status=Account_Status.ACTIVE
    )

    # While ACTIVE, the member may perform a collaborative write.
    allowed = authz.authorize(member_actor, Action.CREATE, shared_resource)
    assert allowed.allowed is True

    # Disconnect (with a real re-auth grant), then re-check.
    grant = auth.require_reauthentication(
        actor_a, "pw", Sensitive_Operation.COUPLE_DISCONNECTION
    )
    service.disconnect_couple(actor_a, couple.id, grant)
    pg_schema.flush()

    denied = authz.authorize(member_actor, Action.CREATE, shared_resource)
    assert denied.allowed is False
    assert denied.reason == DenyReason.COUPLE_NOT_ACTIVE


def test_db_disconnect_non_active_couple_rejected(pg_schema):
    """R13.2 (DB): a PENDING (not-yet-ACTIVE) couple cannot be disconnected."""
    _create_tables_with_active_index(pg_schema)
    _create_audit_table(pg_schema)
    repo = CoupleRepository(pg_schema)
    auth, users, audit = _build_db_auth_service(pg_schema)
    service = CoupleService(
        couple_repository=repo,
        audit_service=audit,
        authentication_service=auth,
    )
    # PENDING couple (creator only); actor is an ACTIVE member but couple isn't ACTIVE.
    actor = _register_actor(auth, "solo@example.test")
    couple = repo.create_couple_with_creator(actor.user_id)
    pg_schema.flush()

    grant = auth.require_reauthentication(
        actor, "pw", Sensitive_Operation.COUPLE_DISCONNECTION
    )
    with pytest.raises(ResourceNotFoundError):
        service.disconnect_couple(actor, couple.id, grant)

    assert repo.get_couple(couple.id).status == Couple_Status.PENDING
