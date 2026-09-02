"""Tests for the Users module :class:`AccountService` (tasks 7.1–7.3).

Covers the design's "AccountService" contract and its requirements:

  * R6.1 — ``get_own_profile`` returns only the actor's own profile; the
    auth_identifier is never exposed (R1.5).
  * R6.2 — ``update_own_settings`` applies product-rule fields and refreshes
    ``updated_at``.
  * R7.4 — a client-supplied ``account_status`` / ``status`` is rejected by the
    settings path; ``transition_status`` constrains values to the Account_Status
    set and is the only lifecycle write path (R7.1).
  * R8.1 — ``request_account_deletion`` requires a prior successful
    Re_Authentication (a consumed re-auth grant) and creates a REQUESTED
    DataDeletionRequest; without it, nothing is created (R5.1/R5.2).
  * R8.4 — the deletion request records a content-free audit event.
  * R8.5 — the actor's CoupleMember records are evaluated during processing.
  * R8.2/R8.3 — ``finalize_deletion`` revokes all sessions and transitions to
    DELETED so no active authorization path remains.
  * R7.2/R7.3 (task 7.3) — SUSPENDED denies sensitive-resource requests and
    DELETED denies all authenticated requests, enforced across SessionService
    (fail-closed) and the authorization pipeline step 1. These are proven here
    against the *existing* pipeline, with no new logic.

Pure unit tests use in-memory fakes and run everywhere. A parallel set of
DB-backed tests uses the ``pg_schema`` fixture to exercise the real
``UserRepository`` / ``DataDeletionRequestRepository`` and the R8.5 CoupleMember
evaluation against real rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository
from app.audit.service import ALLOWED_METADATA_KEYS, AuditService
from app.authorization.models import (
    Action,
    AuthenticatedActor,
    DenyReason,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Role,
    Member_Status,
    Visibility_Scope,
)
from app.errors import (
    ReauthRequiredError,
    ResourceNotFoundError,
    ValidationError,
)
from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    ReauthToken,
    Sensitive_Operation,
    SessionService,
    SessionRecord,
    SessionStore,
)
from app.users.models import User
from app.users.repository import DataDeletionRequestRepository, UserRepository
from app.users.schemas import ProfileView, SettingsUpdate
from app.users.service import (
    ACCOUNT_DELETED_EVENT,
    DATA_DELETION_REQUESTED_EVENT,
    SETTINGS_UPDATED_EVENT,
    STATUS_TRANSITION_EVENT,
    AccountService,
)


# ---------------------------------------------------------------------------
# Test doubles (mirroring the auth-service test conventions)
# ---------------------------------------------------------------------------


class _RecordingSession:
    """In-memory Session stand-in capturing appended AuditEvents (append-only)."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def add(self, obj: AuditEvent) -> None:
        self.events.append(obj)

    def flush(self) -> None:
        for event in self.events:
            if event.id is None:
                event.id = uuid.uuid4()


class _FakeUserRepository:
    """In-memory UserRepository faithful to the real write/read contract."""

    def __init__(self) -> None:
        self._by_id: dict[uuid.UUID, User] = {}

    def add_user(self, user: User) -> User:
        self._by_id[user.id] = user
        return user

    def get_by_id(self, user_id):
        return self._by_id.get(user_id)

    def get_account_status(self, user_id):
        user = self._by_id.get(user_id)
        return user.status if user is not None else None

    def set_status(self, user_id, status, *, deleted_at=None):
        user = self._by_id.get(user_id)
        if user is None:
            return None
        user.status = status
        if deleted_at is not None:
            user.deleted_at = deleted_at
        return user


class _FakeDeletionRepository:
    """In-memory DataDeletionRequest store; records created requests."""

    def __init__(self) -> None:
        self.created: list = []

    def create(self, *, user_id, scope, status=None):
        from app.enums import Deletion_Status
        from app.users.models import DataDeletionRequest

        req = DataDeletionRequest(
            id=uuid.uuid4(),
            user_id=user_id,
            scope=scope,
            status=status or Deletion_Status.REQUESTED,
        )
        self.created.append(req)
        return req


class _InMemorySessionStore(SessionStore):
    """Minimal in-memory SessionStore (records + per-user index), no TTL eviction."""

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}
        self._index: dict[uuid.UUID, set[str]] = {}

    def save(self, record: SessionRecord, *, ttl_seconds: int) -> None:
        self._records[record.session_id] = record
        self._index.setdefault(record.user_id, set()).add(record.session_id)

    def get(self, session_id: str):
        return self._records.get(session_id)

    def delete(self, session_id: str, user_id) -> None:
        self._records.pop(session_id, None)
        if user_id in self._index:
            self._index[user_id].discard(session_id)

    def ids_for_user(self, user_id):
        return list(self._index.get(user_id, set()))


class _StubAuth:
    """Stub AuthenticationService.consume_reauthentication for the deletion gate.

    ``ok`` controls whether the re-auth grant is accepted; ``calls`` records the
    (grant, actor, operation) it was invoked with so the test can assert the gate
    was consulted with the ACCOUNT_DELETION_REQUEST operation.
    """

    def __init__(self, ok: bool) -> None:
        self.ok = ok
        self.calls: list = []

    def consume_reauthentication(self, grant, actor, operation_type) -> bool:
        self.calls.append((grant, actor, operation_type))
        return self.ok


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_user(status: Account_Status = Account_Status.ACTIVE, **kw) -> User:
    now = _now()
    return User(
        id=uuid.uuid4(),
        auth_identifier=kw.get("auth_identifier", f"{uuid.uuid4().hex}@example.test"),
        display_name=kw.get("display_name"),
        locale=kw.get("locale"),
        timezone=kw.get("timezone"),
        status=status,
        created_at=now,
        updated_at=now,
    )


def _actor(user: User) -> AuthenticatedActor:
    return AuthenticatedActor(user_id=user.id, account_status=user.status)


def _audit():
    session = _RecordingSession()
    return AuditService(AuditRepository(session)), session


def _service(
    *,
    users: _FakeUserRepository | None = None,
    deletions: _FakeDeletionRepository | None = None,
    auth_ok: bool = True,
    session=None,
):
    users = users or _FakeUserRepository()
    deletions = deletions or _FakeDeletionRepository()
    audit, audit_session = _audit()
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    svc = AccountService(
        user_repository=users,
        deletion_repository=deletions,
        session_service=sessions,
        authentication_service=_StubAuth(auth_ok),
        audit_service=audit,
        session=session,
    )
    return svc, users, deletions, sessions, audit_session


def _event_types(audit_session: _RecordingSession) -> list[str]:
    return [e.event_type for e in audit_session.events]


# ===========================================================================
# 7.1 — get_own_profile (R6.1)
# ===========================================================================


def test_get_own_profile_returns_owner_profile_without_identifier():
    """R6.1: the actor gets their own profile; auth_identifier is never in it (R1.5)."""
    users = _FakeUserRepository()
    user = users.add_user(
        _make_user(display_name="Alex", locale="en", timezone="UTC")
    )
    svc, *_ = _service(users=users)

    profile = svc.get_own_profile(_actor(user))

    assert isinstance(profile, ProfileView)
    assert profile.id == user.id
    assert profile.display_name == "Alex"
    # Sensitive identifier is not part of the profile view (R1.5).
    assert "auth_identifier" not in profile.model_dump()


def test_get_own_profile_missing_user_is_privacy_safe_not_found():
    """A session that resolves to a vanished user fails closed (privacy-safe)."""
    svc, *_ = _service()
    ghost = AuthenticatedActor(user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE)

    with pytest.raises(ResourceNotFoundError):
        svc.get_own_profile(ghost)


# ===========================================================================
# 7.1 — update_own_settings (R6.2, R7.4)
# ===========================================================================


def test_update_own_settings_applies_fields_and_bumps_updated_at():
    """R6.2: product-rule fields are applied and updated_at moves forward."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user(display_name="Old"))
    original_updated = user.updated_at
    svc, *_ = _service(users=users)

    profile = svc.update_own_settings(
        _actor(user), {"display_name": "New", "locale": "fr"}
    )

    assert profile.display_name == "New"
    assert profile.locale == "fr"
    assert user.display_name == "New"
    assert user.updated_at >= original_updated
    assert user.updated_at is not None


def test_update_own_settings_records_audit_event():
    """R6.2: applying a settings update records a settings-updated audit event."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, _d, _s, audit_session = _service(users=users)

    svc.update_own_settings(_actor(user), {"display_name": "X"})

    assert SETTINGS_UPDATED_EVENT in _event_types(audit_session)


@pytest.mark.parametrize("field", ["account_status", "status"])
def test_update_own_settings_rejects_client_supplied_status(field):
    """R7.4: a client cannot change lifecycle status through settings."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, *_ = _service(users=users)

    with pytest.raises(ValidationError):
        svc.update_own_settings(_actor(user), {field: "DELETED"})

    # Status is unchanged — the smuggled field never took effect.
    assert user.status == Account_Status.ACTIVE


def test_update_own_settings_rejects_unknown_field():
    """extra='forbid': an unknown field is a validation error, not a silent drop."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, *_ = _service(users=users)

    with pytest.raises(ValidationError):
        svc.update_own_settings(_actor(user), {"is_admin": True})


def test_settings_update_schema_forbids_status_field():
    """The SettingsUpdate schema itself rejects account_status (defense at the edge)."""
    with pytest.raises(Exception):
        SettingsUpdate.model_validate({"account_status": "SUSPENDED"})


def test_update_own_settings_accepts_validated_schema_instance():
    """A pre-validated SettingsUpdate is applied the same as a dict."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, *_ = _service(users=users)

    profile = svc.update_own_settings(
        _actor(user), SettingsUpdate(display_name="Schema")
    )
    assert profile.display_name == "Schema"


# ===========================================================================
# 7.2 — transition_status (R7.1, R7.4)
# ===========================================================================


@pytest.mark.parametrize(
    "status", [Account_Status.SUSPENDED, Account_Status.DELETED, Account_Status.ACTIVE]
)
def test_transition_status_sets_each_valid_status(status):
    """R7.1: transition_status is the server-side write for every valid status."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, _d, _s, audit_session = _service(users=users)

    svc.transition_status(user.id, status, reason="admin_action")

    assert user.status == status
    if status == Account_Status.DELETED:
        assert user.deleted_at is not None
    assert STATUS_TRANSITION_EVENT in _event_types(audit_session)


def test_transition_status_rejects_invalid_value():
    """R7.1/R7.4: a value outside the Account_Status set is rejected."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, *_ = _service(users=users)

    with pytest.raises(ValidationError):
        svc.transition_status(user.id, "PENDING", reason="bad")  # type: ignore[arg-type]


def test_transition_status_unknown_user_is_not_found():
    svc, *_ = _service()
    with pytest.raises(ResourceNotFoundError):
        svc.transition_status(uuid.uuid4(), Account_Status.SUSPENDED, reason="x")


# ===========================================================================
# 7.2 — request_account_deletion (R8.1, R8.4, R8.5)
# ===========================================================================


def _grant() -> ReauthToken:
    return ReauthToken(
        grant_id="g-" + uuid.uuid4().hex,
        token="t-" + uuid.uuid4().hex,
        operation_type=Sensitive_Operation.ACCOUNT_DELETION_REQUEST,
    )


def test_request_account_deletion_requires_prior_reauth():
    """R8.1/R5.2: without a valid consumed re-auth grant, nothing is created."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, deletions, _s, audit_session = _service(users=users, auth_ok=False)

    with pytest.raises(ReauthRequiredError):
        svc.request_account_deletion(_actor(user), _grant())

    assert deletions.created == []
    assert DATA_DELETION_REQUESTED_EVENT not in _event_types(audit_session)


def test_request_account_deletion_creates_requested_record_and_audit():
    """R8.1: creates a REQUESTED record; R8.4: records a content-free audit event."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, deletions, _s, audit_session = _service(users=users, auth_ok=True)

    req = svc.request_account_deletion(_actor(user), _grant())

    from app.enums import Deletion_Status

    assert req.status == Deletion_Status.REQUESTED
    assert req.user_id == user.id
    assert len(deletions.created) == 1
    assert DATA_DELETION_REQUESTED_EVENT in _event_types(audit_session)


def test_request_account_deletion_gate_uses_deletion_operation():
    """The re-auth gate is consulted for the ACCOUNT_DELETION_REQUEST operation."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    stub = _StubAuth(True)
    audit, _ = _audit()
    svc = AccountService(
        user_repository=users,
        deletion_repository=_FakeDeletionRepository(),
        session_service=SessionService(
            store=_InMemorySessionStore(), audit_service=audit, user_status_lookup=users
        ),
        authentication_service=stub,
        audit_service=audit,
    )
    svc.request_account_deletion(_actor(user), _grant())

    assert stub.calls
    _grant_arg, _actor_arg, op = stub.calls[0]
    assert op == Sensitive_Operation.ACCOUNT_DELETION_REQUEST


def test_deletion_audit_metadata_is_content_free():
    """R8.4: the deletion audit event carries only whitelisted, content-free keys."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, _d, _s, audit_session = _service(users=users, auth_ok=True)

    svc.request_account_deletion(_actor(user), _grant())

    event = next(
        e for e in audit_session.events if e.event_type == DATA_DELETION_REQUESTED_EVENT
    )
    assert event.event_metadata is not None
    assert set(event.event_metadata).issubset(ALLOWED_METADATA_KEYS)


# ===========================================================================
# 7.2 — finalize_deletion (R8.2, R8.3)
# ===========================================================================


def test_finalize_deletion_revokes_sessions_and_transitions_to_deleted():
    """R8.2: all sessions revoked; R8.3: status becomes DELETED with deleted_at."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, _d, sessions, audit_session = _service(users=users)

    # Give the user two live sessions.
    sessions.create_session(user.id)
    sessions.create_session(user.id)
    assert len(sessions.list_active_sessions(user.id)) == 2

    svc.finalize_deletion(user.id)

    assert sessions.list_active_sessions(user.id) == []  # R8.2
    assert user.status == Account_Status.DELETED  # R8.3
    assert user.deleted_at is not None
    assert ACCOUNT_DELETED_EVENT in _event_types(audit_session)


def test_finalize_deletion_leaves_no_authenticating_token():
    """R8.3: after finalize, a previously issued token no longer authenticates."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user())
    svc, _u, _d, sessions, _a = _service(users=users)

    token = sessions.create_session(user.id)
    assert sessions.authenticate(token) is not None  # active before

    svc.finalize_deletion(user.id)

    # Session record is gone (R8.2) AND status is DELETED (R8.3) — both fail closed.
    assert sessions.authenticate(token) is None


# ===========================================================================
# 7.3 — SUSPENDED / DELETED denial across the two fail-closed layers
# ===========================================================================


class _FixedResolver:
    """Trivial RelationshipResolver — never needed for the lifecycle-step-1 tests."""

    def get_member_status(self, couple_id, user_id):
        return None

    def get_couple_status(self, couple_id):
        return None


@pytest.mark.parametrize("status", [Account_Status.SUSPENDED, Account_Status.DELETED])
def test_authorization_step1_denies_non_active_account(status):
    """R7.2/R7.3: pipeline step 1 denies any non-ACTIVE actor before resolving a resource."""
    authz = AuthorizationService(_FixedResolver())
    actor = AuthenticatedActor(user_id=uuid.uuid4(), account_status=status)
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER, owner_id=actor.user_id
    )

    decision = authz.authorize(actor, Action.READ, resource)

    # Even though the actor "owns" the resource, a non-ACTIVE account is denied
    # at step 1 (R7.2 for SUSPENDED, R7.3 for DELETED).
    assert not decision.allowed
    assert decision.reason == DenyReason.ACCOUNT_NOT_ACTIVE


@pytest.mark.parametrize("status", [Account_Status.SUSPENDED, Account_Status.DELETED])
def test_session_fail_closed_for_non_active_account(status):
    """R7.2/R7.3: SessionService never resolves a non-ACTIVE account to an actor."""
    users = _FakeUserRepository()
    user = users.add_user(_make_user(status=Account_Status.ACTIVE))
    audit, _ = _audit()
    sessions = SessionService(
        store=_InMemorySessionStore(), audit_service=audit, user_status_lookup=users
    )
    token = sessions.create_session(user.id)
    assert sessions.authenticate(token) is not None  # ACTIVE authenticates

    # Flip the authoritative status; the same live token now fails closed.
    users.set_status(user.id, status)
    assert sessions.authenticate(token) is None


# ===========================================================================
# DB-backed tests (real repositories + real CoupleMember evaluation, R8.5)
# ===========================================================================


def _create_account_tables(session) -> None:
    """Create users, data_deletion_requests, couples and couple_members tables."""
    from app.couples.models import Couple, CoupleMember
    from app.db import Base
    from app.users.models import DataDeletionRequest

    Base.metadata.create_all(
        bind=session.connection(),
        tables=[
            User.__table__,
            DataDeletionRequest.__table__,
            Couple.__table__,
            CoupleMember.__table__,
            AuditEvent.__table__,
        ],
    )


def _db_service(session, *, auth_ok: bool = True):
    users = UserRepository(session)
    deletions = DataDeletionRequestRepository(session)
    audit = AuditService(AuditRepository(session))
    sessions = SessionService(
        store=_InMemorySessionStore(), audit_service=audit, user_status_lookup=users
    )
    svc = AccountService(
        user_repository=users,
        deletion_repository=deletions,
        session_service=sessions,
        authentication_service=_StubAuth(auth_ok),
        audit_service=audit,
        session=session,
    )
    return svc, users, deletions, sessions


def test_db_get_and_update_profile_round_trip(pg_schema):
    """R6.1/R6.2 against real Postgres: profile reads and settings updates persist."""
    _create_account_tables(pg_schema)
    svc, users, *_ = _db_service(pg_schema)

    user = users.create(auth_identifier="dana@example.test")
    pg_schema.flush()
    actor = AuthenticatedActor(user_id=user.id, account_status=Account_Status.ACTIVE)

    svc.update_own_settings(actor, {"display_name": "Dana", "timezone": "UTC"})
    profile = svc.get_own_profile(actor)

    assert profile.display_name == "Dana"
    assert profile.timezone == "UTC"

    fetched = pg_schema.get(User, user.id)
    assert fetched.display_name == "Dana"


def test_db_transition_status_persists(pg_schema):
    """R7.1 against real Postgres: a server-side transition persists the new status."""
    _create_account_tables(pg_schema)
    svc, users, *_ = _db_service(pg_schema)

    user = users.create(auth_identifier="eve@example.test")
    pg_schema.flush()

    svc.transition_status(user.id, Account_Status.SUSPENDED, reason="policy")

    fetched = pg_schema.get(User, user.id)
    assert fetched.status == Account_Status.SUSPENDED


def test_db_request_deletion_creates_record_and_evaluates_memberships(pg_schema):
    """R8.1 + R8.5: a REQUESTED record is created and CoupleMember rows are evaluated."""
    from app.couples.models import Couple, CoupleMember

    _create_account_tables(pg_schema)
    svc, users, deletions, _s = _db_service(pg_schema, auth_ok=True)

    user = users.create(auth_identifier="finn@example.test")
    pg_schema.flush()

    # Make the user an ACTIVE member of an ACTIVE couple (R8.5 must see it).
    couple = Couple(status=Couple_Status.ACTIVE)
    pg_schema.add(couple)
    pg_schema.flush()
    pg_schema.add(
        CoupleMember(
            couple_id=couple.id,
            user_id=user.id,
            role=Member_Role.PARTNER_A,
            status=Member_Status.ACTIVE,
        )
    )
    pg_schema.flush()

    actor = AuthenticatedActor(user_id=user.id, account_status=Account_Status.ACTIVE)
    req = svc.request_account_deletion(actor, _grant())

    from app.enums import Deletion_Status

    assert req.status == Deletion_Status.REQUESTED
    # The record is persisted and re-readable through the repository.
    stored = deletions.list_for_user(user.id)
    assert len(stored) == 1

    # R8.5: the audit event's structural count reflects the one active membership.
    events = (
        pg_schema.query(AuditEvent)
        .filter(AuditEvent.event_type == DATA_DELETION_REQUESTED_EVENT)
        .all()
    )
    assert len(events) == 1
    assert events[0].event_metadata.get("attempt_count") == 1


def test_db_finalize_deletion_transitions_and_revokes(pg_schema):
    """R8.2/R8.3 against real Postgres: sessions revoked, status DELETED."""
    _create_account_tables(pg_schema)
    svc, users, _d, sessions = _db_service(pg_schema)

    user = users.create(auth_identifier="gus@example.test")
    pg_schema.flush()
    sessions.create_session(user.id)

    svc.finalize_deletion(user.id)

    fetched = pg_schema.get(User, user.id)
    assert fetched.status == Account_Status.DELETED
    assert fetched.deleted_at is not None
    assert sessions.list_active_sessions(user.id) == []
