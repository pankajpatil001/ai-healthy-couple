"""Tests for the AuthenticationService and IdentityProvider abstraction (task 6.2).

Covers the design's "AuthenticationService" contract and its requirements:

  * register — R1.1 (create ACTIVE + created_at), R1.2 (duplicate rejected),
    R1.3 (malformed/missing identifier → ValidationError), R1.5 (credential
    material never stored on the User row).
  * login — R2.1 (session issued for a valid ACTIVE account), R2.2 (generic
    failure that does not disclose identifier existence), R2.3 (identity resolved
    server-side; only a SessionToken returned).
  * initiate_recovery / complete_recovery — R4.1 (single-purpose, time-limited
    challenge), R4.2 (identical result whether or not the identifier exists),
    R4.3 (credentials re-established), R4.4 (single-use; expired/used rejected),
    R4.5 (all sessions revoked), R4.6 (CREDENTIAL_CHANGE audit).
  * require_reauthentication — R5.1 (fresh proof required, single-operation
    grant), R5.2 (missing/failed proof → ReauthRequiredError/403), R5.3 (the
    Sensitive_Operation set), R5.4 (REAUTH_SUCCESS audit with operation_type and
    no relationship content).

Most tests use in-memory fakes (a fake UserRepository, in-memory recovery/re-auth
stores, an in-memory SessionStore, and a recording audit session) so they run
everywhere deterministically. A parallel set of tests runs the recovery and
re-auth stores against a real, ephemeral Redis namespace (``redis_ns``) to prove
TTL + single-use for real, and the register-uniqueness path is exercised against
a real, ephemeral PostgreSQL schema (``pg_schema``) so the UNIQUE constraint is
enforced by Postgres itself (R1.2).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.enums import Account_Status
from app.errors import (
    AuthenticationFailedError,
    IdentifierInUseError,
    ReauthRequiredError,
    ValidationError,
)
from app.auth.service import (
    CREDENTIAL_CHANGE_EVENT,
    LOGIN_EVENT,
    REAUTH_SUCCESS_EVENT,
    USER_REGISTERED_EVENT,
    AuthenticationService,
    InMemoryIdentityProvider,
    ReauthGrantStore,
    ReauthToken,
    RecoveryChallengeStore,
    RedisReauthGrantStore,
    RedisRecoveryChallengeStore,
    SessionService,
    SessionStore,
    SessionRecord,
    Sensitive_Operation,
)
from app.users.models import User


# ---------------------------------------------------------------------------
# Test doubles
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
    """In-memory stand-in for UserRepository.

    Faithful to the real contract: ``create`` enforces auth_identifier
    uniqueness by raising :class:`IdentifierInUseError` (as the DB UNIQUE
    constraint does, R1.2); lookups are by id / identifier; ``get_account_status``
    satisfies the SessionService status-lookup protocol.
    """

    def __init__(self) -> None:
        self._by_id: dict[uuid.UUID, User] = {}
        self._by_identifier: dict[str, uuid.UUID] = {}

    def create(self, *, auth_identifier, status=Account_Status.ACTIVE, **_) -> User:
        if auth_identifier in self._by_identifier:
            raise IdentifierInUseError()
        user = User(id=uuid.uuid4(), auth_identifier=auth_identifier, status=status)
        self._by_id[user.id] = user
        self._by_identifier[auth_identifier] = user.id
        return user

    def get_by_id(self, user_id):
        return self._by_id.get(user_id)

    def get_by_auth_identifier(self, auth_identifier):
        uid = self._by_identifier.get(auth_identifier)
        return self._by_id.get(uid) if uid is not None else None

    def get_account_status(self, user_id):
        user = self._by_id.get(user_id)
        return user.status if user is not None else None

    def set_status(self, user_id, status) -> None:
        self._by_id[user_id].status = status


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


class _InMemoryRecoveryStore(RecoveryChallengeStore):
    """In-memory recovery-challenge store; single-use via pop, no TTL eviction."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[uuid.UUID, str]] = {}
        self.last_ttl: int | None = None

    def save(self, challenge_id, *, user_id, secret_hash, ttl_seconds) -> None:
        self.last_ttl = ttl_seconds
        self._data[challenge_id] = (user_id, secret_hash)

    def consume(self, challenge_id):
        return self._data.pop(challenge_id, None)


class _InMemoryReauthStore(ReauthGrantStore):
    """In-memory re-auth grant store; single-use via pop, no TTL eviction."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[uuid.UUID, str, str]] = {}
        self.last_ttl: int | None = None

    def save(self, grant_id, *, user_id, operation_type, token_hash, ttl_seconds) -> None:
        self.last_ttl = ttl_seconds
        self._data[grant_id] = (user_id, operation_type, token_hash)

    def consume(self, grant_id):
        return self._data.pop(grant_id, None)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _build_service(
    *,
    users=None,
    idp=None,
    recovery=None,
    reauth=None,
    audit_session=None,
):
    """Wire an AuthenticationService over in-memory fakes and return the parts."""
    users = users or _FakeUserRepository()
    idp = idp or InMemoryIdentityProvider()
    recovery = recovery or _InMemoryRecoveryStore()
    reauth = reauth or _InMemoryReauthStore()
    audit_session = audit_session or _RecordingSession()
    audit = AuditService(AuditRepository(audit_session))
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    svc = AuthenticationService(
        user_repository=users,
        identity_provider=idp,
        session_service=sessions,
        audit_service=audit,
        recovery_store=recovery,
        reauth_store=reauth,
    )
    return svc, users, idp, sessions, recovery, reauth, audit_session


def _events(session, event_type):
    return [e for e in session.events if e.event_type == event_type]


# ===========================================================================
# register (R1)
# ===========================================================================


def test_register_creates_active_user_and_records_audit():
    """A valid, unused identifier creates an ACTIVE User with created_at (R1.1/R1.4)."""
    svc, users, _, _, _, _, audit = _build_service()

    user = svc.register("Alice@Example.test", "s3cret")

    assert user.status == Account_Status.ACTIVE
    # created_at is populated on real DB via server_default; the fake leaves it
    # to the DB, so we assert the account exists and is ACTIVE via lookup.
    assert users.get_by_id(user.id) is user
    # Identifier is normalised (lower-cased/trimmed).
    assert user.auth_identifier == "alice@example.test"
    assert len(_events(audit, USER_REGISTERED_EVENT)) == 1


def test_register_rejects_duplicate_identifier():
    """A second registration with the same identifier is rejected (R1.2)."""
    svc, _, _, _, _, _, _ = _build_service()

    svc.register("bob@example.test", "pw1")
    with pytest.raises(IdentifierInUseError):
        svc.register("bob@example.test", "pw2")


@pytest.mark.parametrize(
    "identifier",
    ["", "   ", "no-at-sign", "two@@example.test", "@example.test", "local@", "a b@x.test", None, 123],
)
def test_register_rejects_malformed_or_missing_identifier(identifier):
    """A malformed/missing identifier raises ValidationError (R1.3)."""
    svc, _, _, _, _, _, _ = _build_service()
    with pytest.raises(ValidationError):
        svc.register(identifier, "pw")


def test_register_rejects_missing_credential():
    """Missing credential material is a validation error (R1.3-adjacent)."""
    svc, _, _, _, _, _, _ = _build_service()
    with pytest.raises(ValidationError):
        svc.register("carol@example.test", "")


def test_register_does_not_store_credential_on_user_row():
    """Credential material is delegated to the IdP, never on the User (R1.5, §9)."""
    svc, users, idp, _, _, _, _ = _build_service()

    user = svc.register("dan@example.test", "super-secret-pw")

    # No attribute nor value of the User row equals the credential.
    values = [v for v in vars(user).values() if isinstance(v, str)]
    assert "super-secret-pw" not in values
    # The IdP, however, can verify it.
    assert idp.verify_credentials("dan@example.test", "super-secret-pw")


# ===========================================================================
# login (R2)
# ===========================================================================


def test_login_valid_active_account_issues_session():
    """Valid credentials for an ACTIVE account issue a SessionToken (R2.1)."""
    svc, _, _, sessions, _, _, audit = _build_service()
    svc.register("erin@example.test", "pw")

    token = svc.login("erin@example.test", "pw")

    # The returned token authenticates server-side (R2.3).
    actor = sessions.authenticate(token)
    assert actor is not None
    assert actor.account_status == Account_Status.ACTIVE
    assert len(_events(audit, LOGIN_EVENT)) == 1
    assert _events(audit, LOGIN_EVENT)[0].outcome == "SUCCESS"


def test_login_wrong_credential_raises_generic_error():
    """A wrong credential fails with a generic auth error (R2.2)."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("frank@example.test", "right-pw")

    with pytest.raises(AuthenticationFailedError):
        svc.login("frank@example.test", "wrong-pw")


def test_login_unknown_identifier_raises_same_generic_error():
    """An unknown identifier raises the SAME error type as a wrong credential (R2.2)."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("gina@example.test", "pw")

    with pytest.raises(AuthenticationFailedError):
        svc.login("does-not-exist@example.test", "pw")


def test_login_unknown_and_wrong_are_indistinguishable():
    """Failure for unknown vs wrong-credential is indistinguishable (R2.2)."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("hank@example.test", "pw")

    unknown = wrong = None
    try:
        svc.login("nobody@example.test", "pw")
    except AuthenticationFailedError as exc:
        unknown = (type(exc), exc.code, exc.http_status, str(exc))
    try:
        svc.login("hank@example.test", "nope")
    except AuthenticationFailedError as exc:
        wrong = (type(exc), exc.code, exc.http_status, str(exc))

    assert unknown == wrong


@pytest.mark.parametrize("status", [Account_Status.SUSPENDED, Account_Status.DELETED])
def test_login_non_active_account_fails_generically(status):
    """A non-ACTIVE account cannot log in and fails generically (R2.1/R2.2)."""
    svc, users, _, _, _, _, _ = _build_service()
    user = svc.register("ivan@example.test", "pw")
    users.set_status(user.id, status)

    with pytest.raises(AuthenticationFailedError):
        svc.login("ivan@example.test", "pw")


def test_login_records_failure_audit_without_disclosing_identifier():
    """A failed login records a FAILURE audit event with content-free metadata."""
    svc, _, _, _, _, _, audit = _build_service()
    svc.register("judy@example.test", "pw")

    with pytest.raises(AuthenticationFailedError):
        svc.login("judy@example.test", "bad")

    fails = [e for e in _events(audit, LOGIN_EVENT) if e.outcome == "FAILURE"]
    assert len(fails) == 1


# ===========================================================================
# initiate_recovery / complete_recovery (R4)
# ===========================================================================


def test_initiate_recovery_existing_identifier_issues_challenge():
    """Recovery for a real account issues a single-purpose, time-limited challenge (R4.1)."""
    svc, _, _, _, recovery, _, _ = _build_service()
    svc.register("kim@example.test", "pw")

    challenge = svc.initiate_recovery("kim@example.test")

    assert challenge is not None
    assert challenge.challenge_id and challenge.secret
    # A TTL was applied (time-limited, R4.1).
    assert recovery.last_ttl and recovery.last_ttl > 0


def test_initiate_recovery_unknown_identifier_returns_no_challenge():
    """Recovery for an unknown identifier issues no challenge but is not an error (R4.2)."""
    svc, _, _, _, _, _, _ = _build_service()
    # No registration.
    assert svc.initiate_recovery("ghost@example.test") is None


def test_complete_recovery_valid_challenge_resets_credentials_and_revokes_sessions():
    """A valid challenge re-establishes credentials (R4.3) and revokes sessions (R4.5)."""
    svc, _, idp, sessions, _, _, audit = _build_service()
    svc.register("leo@example.test", "old-pw")
    token = svc.login("leo@example.test", "old-pw")
    assert sessions.authenticate(token) is not None

    challenge = svc.initiate_recovery("leo@example.test")
    svc.complete_recovery(challenge.challenge_id, challenge.secret, "new-pw")

    # Old session revoked (R4.5), old credential invalid, new one works (R4.3).
    assert sessions.authenticate(token) is None
    assert not idp.verify_credentials("leo@example.test", "old-pw")
    assert idp.verify_credentials("leo@example.test", "new-pw")
    # CREDENTIAL_CHANGE audit recorded (R4.6).
    assert len(_events(audit, CREDENTIAL_CHANGE_EVENT)) == 1


def test_complete_recovery_is_single_use():
    """A challenge cannot be used twice (single-use, R4.4)."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("mona@example.test", "pw")
    challenge = svc.initiate_recovery("mona@example.test")

    svc.complete_recovery(challenge.challenge_id, challenge.secret, "new-pw")
    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery(challenge.challenge_id, challenge.secret, "newer-pw")


def test_complete_recovery_rejects_unknown_or_wrong_challenge():
    """An unknown challenge id or wrong secret is rejected (R4.4)."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("nate@example.test", "pw")
    challenge = svc.initiate_recovery("nate@example.test")

    # Unknown challenge id.
    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery("does-not-exist", "whatever", "new-pw")

    # Wrong secret for a real challenge (still consumes it — single-use).
    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery(challenge.challenge_id, "wrong-secret", "new-pw")


def test_complete_recovery_requires_new_credential():
    """A missing new credential is a validation error."""
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("olga@example.test", "pw")
    challenge = svc.initiate_recovery("olga@example.test")

    with pytest.raises(ValidationError):
        svc.complete_recovery(challenge.challenge_id, challenge.secret, "")


# ===========================================================================
# require_reauthentication / consume_reauthentication (R5)
# ===========================================================================


def _actor_for(user) -> AuthenticatedActor:
    return AuthenticatedActor(user_id=user.id, account_status=Account_Status.ACTIVE)


@pytest.mark.parametrize("operation", list(Sensitive_Operation))
def test_require_reauthentication_success_mints_single_operation_grant(operation):
    """A fresh proof mints a short-lived, single-operation grant + audit (R5.1/R5.4)."""
    svc, _, _, _, _, reauth, audit = _build_service()
    user = svc.register("pat@example.test", "pw")
    actor = _actor_for(user)

    grant = svc.require_reauthentication(actor, "pw", operation)

    assert grant.operation_type == operation
    assert reauth.last_ttl and reauth.last_ttl > 0
    successes = [e for e in _events(audit, REAUTH_SUCCESS_EVENT) if e.outcome == "SUCCESS"]
    assert len(successes) == 1
    # Audit carries only the operation type (no relationship content) (R5.4).
    assert successes[0].event_metadata == {"operation_type": operation.value}

    # The grant validates and is single-use.
    assert svc.consume_reauthentication(grant, actor, operation) is True
    assert svc.consume_reauthentication(grant, actor, operation) is False


def test_require_reauthentication_missing_or_wrong_proof_denies():
    """A missing/failed proof raises ReauthRequiredError (403) (R5.2)."""
    svc, _, _, _, _, _, audit = _build_service()
    user = svc.register("quinn@example.test", "pw")
    actor = _actor_for(user)
    op = Sensitive_Operation.COUPLE_DISCONNECTION

    with pytest.raises(ReauthRequiredError):
        svc.require_reauthentication(actor, "", op)
    with pytest.raises(ReauthRequiredError):
        svc.require_reauthentication(actor, "wrong-pw", op)

    # The error maps to 403 (R5.2).
    try:
        svc.require_reauthentication(actor, "wrong-pw", op)
    except ReauthRequiredError as exc:
        assert exc.http_status == 403


def test_consume_reauthentication_rejects_wrong_actor_or_operation():
    """A grant is bound to one actor and one operation (R5.1)."""
    svc, _, _, _, _, _, _ = _build_service()
    user = svc.register("rita@example.test", "pw")
    actor = _actor_for(user)
    other = AuthenticatedActor(user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE)

    grant = svc.require_reauthentication(
        actor, "pw", Sensitive_Operation.ACCOUNT_DELETION_REQUEST
    )

    # Wrong actor is rejected (and consumes nothing usable afterwards either).
    assert svc.consume_reauthentication(grant, other, Sensitive_Operation.ACCOUNT_DELETION_REQUEST) is False

    grant2 = svc.require_reauthentication(
        actor, "pw", Sensitive_Operation.ACCOUNT_DELETION_REQUEST
    )
    # Wrong operation is rejected.
    assert svc.consume_reauthentication(grant2, actor, Sensitive_Operation.COUPLE_DISCONNECTION) is False


def test_consume_reauthentication_rejects_forged_token():
    """A grant with a forged token secret does not validate."""
    svc, _, _, _, _, _, _ = _build_service()
    user = svc.register("sam@example.test", "pw")
    actor = _actor_for(user)
    grant = svc.require_reauthentication(
        actor, "pw", Sensitive_Operation.ACCOUNT_SECURITY_SETTING_CHANGE
    )
    forged = ReauthToken(grant_id=grant.grant_id, token="forged", operation_type=grant.operation_type)
    assert svc.consume_reauthentication(forged, actor, grant.operation_type) is False


# ===========================================================================
# Redis-backed store behaviour (real Redis via redis_ns)
# ===========================================================================


def test_redis_recovery_store_single_use_and_ttl(redis_ns):
    """Against real Redis: a recovery challenge is single-use and TTL'd (R4.1/R4.4)."""
    from app.redis import recovery_key

    users = _FakeUserRepository()
    store = RedisRecoveryChallengeStore(redis_ns)
    svc, _, idp, sessions, _, _, _ = _build_service(users=users, recovery=store)

    svc.register("tom@example.test", "pw")
    challenge = svc.initiate_recovery("tom@example.test")

    # A live TTL exists on the Redis key (time-limited, R4.1).
    ttl = redis_ns.ttl(recovery_key(challenge.challenge_id))
    assert 0 < ttl <= 60 * 15

    svc.complete_recovery(challenge.challenge_id, challenge.secret, "new-pw")
    # Consumed: the key is gone and a replay fails (single-use, R4.4).
    assert not redis_ns.exists(recovery_key(challenge.challenge_id))
    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery(challenge.challenge_id, challenge.secret, "again")


def test_redis_reauth_store_single_use_and_ttl(redis_ns):
    """Against real Redis: a re-auth grant is single-use and short-lived (R5.1)."""
    from app.redis import reauth_key

    users = _FakeUserRepository()
    store = RedisReauthGrantStore(redis_ns)
    svc, _, _, _, _, _, _ = _build_service(users=users, reauth=store)

    user = svc.register("uma@example.test", "pw")
    actor = _actor_for(user)
    op = Sensitive_Operation.COUPLE_DISCONNECTION
    grant = svc.require_reauthentication(actor, "pw", op)

    ttl = redis_ns.ttl(reauth_key(grant.grant_id))
    assert 0 < ttl <= 60 * 5

    assert svc.consume_reauthentication(grant, actor, op) is True
    assert not redis_ns.exists(reauth_key(grant.grant_id))
    assert svc.consume_reauthentication(grant, actor, op) is False


# ===========================================================================
# Register against real PostgreSQL (UNIQUE constraint enforced by Postgres)
# ===========================================================================


def _create_users_table(session) -> None:
    """Create the users table with the production UNIQUE constraint in the schema.

    The ``auth_identifier`` UNIQUE constraint lives in the initial migration, not
    the ORM model (see :mod:`app.users.models` and migration task 2.3). It is
    therefore added here with an explicit ``CREATE UNIQUE INDEX`` scoped to the
    per-test ephemeral schema — never by mutating the shared ``User.__table__``
    metadata, which would leak the constraint into every other test's
    ``Base.metadata.create_all`` for the whole process and collide with harnesses
    that create the same index explicitly.
    """
    from app.users.repository import AUTH_IDENTIFIER_UNIQUE_CONSTRAINT

    User.__table__.create(bind=session.connection())
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{AUTH_IDENTIFIER_UNIQUE_CONSTRAINT}" '
            "ON users (auth_identifier)"
        )
    )
    session.flush()


def test_register_against_real_postgres_enforces_uniqueness(pg_schema):
    """register creates a User and a duplicate is rejected by Postgres (R1.1/R1.2)."""
    from app.users.repository import UserRepository

    _create_users_table(pg_schema)

    users = UserRepository(pg_schema)
    audit_session = _RecordingSession()
    audit = AuditService(AuditRepository(audit_session))
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    svc = AuthenticationService(
        user_repository=users,
        identity_provider=InMemoryIdentityProvider(),
        session_service=sessions,
        audit_service=audit,
        recovery_store=_InMemoryRecoveryStore(),
        reauth_store=_InMemoryReauthStore(),
    )

    user = svc.register("vera@example.test", "pw")
    assert user.status == Account_Status.ACTIVE
    # created_at is populated by the server default after flush (R1.4).
    assert user.created_at is not None

    # A duplicate registration is rejected via the DB UNIQUE constraint (R1.2).
    with pytest.raises(IdentifierInUseError):
        svc.register("vera@example.test", "pw2")

    # Login round-trips through the real repository (R2.1/R2.3).
    token = svc.login("vera@example.test", "pw")
    assert sessions.authenticate(token) is not None
