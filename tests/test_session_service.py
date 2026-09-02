"""Tests for the Redis-backed SessionService (task 6.1).

Covers the design's "SessionService" contract and its requirements:

  * R3.1 — a created session is assigned an expiry and stored with a TTL that
    mirrors that expiry (verified against real Redis via ``redis_ns``).
  * R2.4 — the issued Session_Token is opaque and unpredictable and carries no
    account data; the user is only resolvable via the server-side record (R2.3).
  * R2.5 — session creation records a SESSION_CREATED audit event.
  * R3.2 — an expired session authenticates as unauthenticated.
  * R3.3/R3.4 — a revoked session can no longer authenticate.
  * R3.6 — a SUSPENDED/DELETED (or vanished) account fails closed even with a
    live session token.
  * R3.5 — a user can list only their own active sessions (no token exposed).
  * R3.7 — revocation records a SESSION_REVOKED audit event.
  * R4.5/R8.2 — revoke_all_sessions clears every session for a user.

The fast tests use an in-memory :class:`SessionStore` fake and a recording audit
session so they run everywhere with deterministic expiry control. A parallel set
of tests runs against a real, ephemeral Redis namespace (``redis_ns``) to prove
the TTL-mirrors-expiry behaviour (R3.1) for real.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.config import get_settings
from app.enums import Account_Status
from app.auth.service import (
    SESSION_CREATED_EVENT,
    SESSION_REVOKED_EVENT,
    RedisSessionStore,
    SessionRecord,
    SessionService,
    SessionStore,
    SessionToken,
)


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


class _FakeStatusLookup:
    """A mutable :class:`UserStatusLookup` fake for lifecycle tests (R3.6)."""

    def __init__(self, statuses: dict[uuid.UUID, Account_Status] | None = None) -> None:
        self._statuses: dict[uuid.UUID, Account_Status] = statuses or {}

    def set(self, user_id: uuid.UUID, status: Account_Status | None) -> None:
        if status is None:
            self._statuses.pop(user_id, None)
        else:
            self._statuses[user_id] = status

    def get_account_status(self, user_id: uuid.UUID) -> Account_Status | None:
        return self._statuses.get(user_id)


class _InMemorySessionStore(SessionStore):
    """A minimal in-memory :class:`SessionStore` for fast, deterministic tests.

    Faithful to the Redis store's contract (records + per-user index) but with no
    TTL eviction, so tests control expiry purely through ``expires_at``.
    """

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}
        self._index: dict[uuid.UUID, set[str]] = {}
        self.last_ttl: int | None = None

    def save(self, record: SessionRecord, *, ttl_seconds: int) -> None:
        self.last_ttl = ttl_seconds
        self._records[record.session_id] = record
        self._index.setdefault(record.user_id, set()).add(record.session_id)

    def get(self, session_id: str) -> SessionRecord | None:
        return self._records.get(session_id)

    def delete(self, session_id: str, user_id: uuid.UUID) -> None:
        self._records.pop(session_id, None)
        if user_id in self._index:
            self._index[user_id].discard(session_id)

    def ids_for_user(self, user_id: uuid.UUID) -> list[str]:
        return list(self._index.get(user_id, set()))

    # test helper: overwrite a record to simulate expiry/revocation
    def put(self, record: SessionRecord) -> None:
        self._records[record.session_id] = record
        self._index.setdefault(record.user_id, set()).add(record.session_id)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _audit(session: _RecordingSession) -> AuditService:
    return AuditService(AuditRepository(session))


def _service(store, statuses, session):
    return SessionService(
        store=store,
        audit_service=_audit(session),
        user_status_lookup=statuses,
    )


def _active_user() -> tuple[uuid.UUID, _FakeStatusLookup]:
    uid = uuid.uuid4()
    return uid, _FakeStatusLookup({uid: Account_Status.ACTIVE})


# ---------------------------------------------------------------------------
# create_session: opaque token, expiry, TTL, audit (R2.4, R2.5, R3.1)
# ---------------------------------------------------------------------------


def test_create_session_issues_opaque_unpredictable_token():
    """The token is unpredictable and opaque — user only resolvable server-side."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    audit = _RecordingSession()
    svc = _service(store, statuses, audit)

    t1 = svc.create_session(uid)
    t2 = svc.create_session(uid)

    # Unpredictable + unique across generations, high entropy.
    assert t1.token != t2.token
    assert t1.session_id != t2.session_id
    assert len(t1.token) >= 32

    # Opaque: the token/session id do not embed the user id (R2.4).
    assert str(uid) not in t1.token
    assert str(uid) not in t1.session_id


def test_create_session_assigns_expiry_and_records_audit():
    """create_session assigns expires_at (R3.1) and emits SESSION_CREATED (R2.5)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    audit = _RecordingSession()
    svc = _service(store, statuses, audit)

    token = svc.create_session(uid)
    record = store.get(token.session_id)

    assert record is not None
    assert record.expires_at > record.created_at
    # TTL passed to the store mirrors the configured session lifetime (R3.1).
    assert store.last_ttl == get_settings().session_ttl_seconds

    created = [e for e in audit.events if e.event_type == SESSION_CREATED_EVENT]
    assert len(created) == 1
    assert created[0].actor_id == uid
    assert created[0].outcome == "SUCCESS"


# ---------------------------------------------------------------------------
# authenticate: server-side resolution, expiry, revocation, lifecycle
# ---------------------------------------------------------------------------


def test_authenticate_resolves_user_from_server_side_session():
    """A valid token resolves to the server-side user (R2.3)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    actor = svc.authenticate(token)

    assert actor == AuthenticatedActor(uid, Account_Status.ACTIVE)


def test_authenticate_rejects_unknown_session():
    """An unknown session id is unauthenticated."""
    _, statuses = _active_user()
    svc = _service(_InMemorySessionStore(), statuses, _RecordingSession())
    assert svc.authenticate(SessionToken("nope", "nope")) is None


def test_authenticate_rejects_wrong_token_for_known_session():
    """A tampered token that matches a session id but not its secret is rejected."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    forged = SessionToken(session_id=token.session_id, token="forged-token")
    assert svc.authenticate(forged) is None


def test_authenticate_rejects_expired_session():
    """An expired session authenticates as unauthenticated (R3.2)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    rec = store.get(token.session_id)
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    store.put(
        SessionRecord(
            session_id=rec.session_id,
            user_id=rec.user_id,
            token=rec.token,
            created_at=rec.created_at,
            expires_at=past,
            revoked=False,
        )
    )
    assert svc.authenticate(token) is None


def test_authenticate_rejects_revoked_session():
    """A revoked session can no longer authenticate (R3.3/R3.4)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    actor = svc.authenticate(token)
    assert actor is not None

    svc.revoke_session(token.session_id, actor)
    assert svc.authenticate(token) is None


@pytest.mark.parametrize("status", [Account_Status.SUSPENDED, Account_Status.DELETED])
def test_authenticate_fails_closed_for_non_active_account(status):
    """SUSPENDED/DELETED accounts fail closed even with a live token (R3.6)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    assert svc.authenticate(token) is not None  # ACTIVE: ok

    statuses.set(uid, status)  # account status changes server-side
    assert svc.authenticate(token) is None


def test_authenticate_fails_closed_for_vanished_user():
    """A token for a user with no resolvable status is rejected (R3.6)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)
    statuses.set(uid, None)  # user no longer exists
    assert svc.authenticate(token) is None


# ---------------------------------------------------------------------------
# revoke_session / revoke_all_sessions audit (R3.7, R4.5, R8.2)
# ---------------------------------------------------------------------------


def test_revoke_session_records_audit_and_disables_token():
    """revoke_session emits SESSION_REVOKED (R3.7) and disables the token."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    audit = _RecordingSession()
    svc = _service(store, statuses, audit)

    token = svc.create_session(uid)
    actor = svc.authenticate(token)
    svc.revoke_session(token.session_id, actor, reason="LOGOUT")

    revoked = [e for e in audit.events if e.event_type == SESSION_REVOKED_EVENT]
    assert len(revoked) == 1
    assert revoked[0].actor_id == uid
    assert store.get(token.session_id) is None


def test_revoke_all_sessions_clears_every_session():
    """revoke_all_sessions revokes all of a user's sessions (R4.5/R8.2)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    audit = _RecordingSession()
    svc = _service(store, statuses, audit)

    tokens = [svc.create_session(uid) for _ in range(3)]
    svc.revoke_all_sessions(uid, reason="RECOVERY")

    for t in tokens:
        assert svc.authenticate(t) is None
    revoked = [e for e in audit.events if e.event_type == SESSION_REVOKED_EVENT]
    assert len(revoked) == 3
    assert store.ids_for_user(uid) == []


def test_revoke_all_sessions_is_safe_with_no_sessions():
    """Bulk revoke with no sessions records nothing and does not error."""
    uid, statuses = _active_user()
    audit = _RecordingSession()
    svc = _service(_InMemorySessionStore(), statuses, audit)

    svc.revoke_all_sessions(uid, reason="DELETION")
    assert [e for e in audit.events if e.event_type == SESSION_REVOKED_EVENT] == []


# ---------------------------------------------------------------------------
# list_active_sessions (R3.5)
# ---------------------------------------------------------------------------


def test_list_active_sessions_returns_only_active_and_no_token():
    """Only active sessions are listed and no token/secret is exposed (R3.5)."""
    uid, statuses = _active_user()
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    active = svc.create_session(uid)
    stale = svc.create_session(uid)

    # Expire the second session in place.
    rec = store.get(stale.session_id)
    store.put(
        SessionRecord(
            session_id=rec.session_id,
            user_id=rec.user_id,
            token=rec.token,
            created_at=rec.created_at,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            revoked=False,
        )
    )

    summaries = svc.list_active_sessions(uid)
    assert [s.session_id for s in summaries] == [active.session_id]
    # SessionSummary carries no token attribute.
    assert not hasattr(summaries[0], "token")


def test_list_active_sessions_scoped_to_the_user():
    """A user's listing never includes another user's sessions (R3.5)."""
    uid_a, statuses = _active_user()
    uid_b = uuid.uuid4()
    statuses.set(uid_b, Account_Status.ACTIVE)
    store = _InMemorySessionStore()
    svc = _service(store, statuses, _RecordingSession())

    a = svc.create_session(uid_a)
    svc.create_session(uid_b)

    summaries = svc.list_active_sessions(uid_a)
    assert [s.session_id for s in summaries] == [a.session_id]


# ---------------------------------------------------------------------------
# Property: issued tokens are unpredictable and opaque (R2.4)
# ---------------------------------------------------------------------------


@given(user_ids=st.lists(st.uuids(), min_size=2, max_size=25, unique=True))
def test_property_tokens_are_unique_and_opaque(user_ids):
    """For any batch of session creations, tokens are unique and carry no user id.

    Models R2.4: a Session_Token is an opaque, unpredictable reference. Across
    many creations no two tokens or session ids collide, and neither embeds the
    account identifier — the user is resolvable only via the server-side record.
    """
    store = _InMemorySessionStore()
    statuses = _FakeStatusLookup({u: Account_Status.ACTIVE for u in user_ids})
    svc = _service(store, statuses, _RecordingSession())

    tokens = [svc.create_session(u) for u in user_ids]

    all_tokens = [t.token for t in tokens]
    all_ids = [t.session_id for t in tokens]
    assert len(set(all_tokens)) == len(all_tokens)
    assert len(set(all_ids)) == len(all_ids)
    for uid, tok in zip(user_ids, tokens):
        assert str(uid) not in tok.token
        assert str(uid) not in tok.session_id


# ---------------------------------------------------------------------------
# Redis-backed: TTL mirrors expiry for real (R3.1)
# ---------------------------------------------------------------------------


def test_redis_store_ttl_mirrors_expiry(redis_ns):
    """Against real Redis, a session key gets a TTL mirroring session lifetime (R3.1)."""
    uid, statuses = _active_user()
    store = RedisSessionStore(redis_ns)
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(uid)

    from app.redis import session_key

    ttl = redis_ns.ttl(session_key(token.session_id))
    configured = get_settings().session_ttl_seconds
    assert 0 < ttl <= configured
    # And the session authenticates through the real store round-trip.
    assert svc.authenticate(token) == AuthenticatedActor(uid, Account_Status.ACTIVE)


def test_redis_store_roundtrip_revocation_and_listing(redis_ns):
    """End-to-end against Redis: create → list → revoke → gone (R3.3/R3.4/R3.5)."""
    uid, statuses = _active_user()
    store = RedisSessionStore(redis_ns)
    svc = _service(store, statuses, _RecordingSession())

    t1 = svc.create_session(uid)
    t2 = svc.create_session(uid)

    listed = {s.session_id for s in svc.list_active_sessions(uid)}
    assert listed == {t1.session_id, t2.session_id}

    actor = svc.authenticate(t1)
    svc.revoke_session(t1.session_id, actor)
    assert svc.authenticate(t1) is None
    assert svc.authenticate(t2) is not None

    remaining = {s.session_id for s in svc.list_active_sessions(uid)}
    assert remaining == {t2.session_id}

    svc.revoke_all_sessions(uid, reason="DELETION")
    assert svc.list_active_sessions(uid) == []


# ---------------------------------------------------------------------------
# Property 17: Session tokens carry no sensitive account data (R2.4)
# Feature: foundation-auth-couples, Property 17
# ---------------------------------------------------------------------------


class _NonResolvingStore(_InMemorySessionStore):
    """A store whose ``get`` fails if asked for anything but a saved session id.

    Used to prove that :meth:`SessionService.authenticate` resolves the user
    *only* via the opaque server-side session id it was handed — never by trying
    to derive identity from the token's contents. If authentication ever probed
    the token bytes as a lookup key, this store would surface it.
    """

    def get(self, session_id: str) -> SessionRecord | None:  # type: ignore[override]
        if session_id not in self._records:
            raise AssertionError(
                "authenticate() looked up a session id that was never issued — "
                "it must resolve identity only via the opaque server-side "
                "session reference, not by decoding the token"
            )
        return self._records[session_id]


# Sensitive account attributes a token must never embed. auth_identifier stands
# in for an email/phone/username; status is the account lifecycle state.
_ACCOUNT_STATUSES = [
    Account_Status.ACTIVE,
    Account_Status.SUSPENDED,
    Account_Status.DELETED,
]

# Realistic auth identifiers (emails / phone-or-username-like strings). A
# meaningful lower bound on length matters: the opaque token is a ~43-char
# base64url string, so a 1–2 char identifier can appear inside it by pure chance
# without any leak. Constraining to identifiers of a realistic length keeps the
# substring check probing for a genuine leak (the whole identifier embedded)
# rather than incidental single-character collisions.
_auth_identifiers = st.emails() | st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=8,
    max_size=40,
)


@given(
    user_id=st.uuids(),
    auth_identifier=_auth_identifiers,
    status=st.sampled_from(_ACCOUNT_STATUSES),
)
def test_property_session_tokens_carry_no_sensitive_account_data(
    user_id, auth_identifier, status
):
    """Property 17 — an issued Session_Token embeds no sensitive account data.

    *For any* user id and arbitrary account attributes (an auth identifier such
    as an email/phone, and an Account_Status), the issued ``SessionToken`` is an
    opaque reference: neither ``session_id`` nor ``token`` embeds the user id,
    the auth identifier, or the account status. The token resolves to the user
    *only* through the server-side session record — authentication never derives
    identity from the token's contents (R2.4, complementing R2.3).

    Feature: foundation-auth-couples, Property 17
    **Validates: Requirements 2.4**
    """
    store = _NonResolvingStore()
    statuses = _FakeStatusLookup({user_id: status})
    svc = _service(store, statuses, _RecordingSession())

    issued = svc.create_session(user_id)

    # The opaque reference must not leak any sensitive account attribute. Check
    # both the session id and the token against every attribute's string form.
    sensitive_values = {
        str(user_id),
        user_id.hex,
        auth_identifier,
        status.value,
        status.name,
    }
    for surface in (issued.session_id, issued.token):
        for secret_value in sensitive_values:
            assert secret_value not in surface, (
                f"opaque token surface leaked sensitive account data: {secret_value!r}"
            )

    # Resolution happens purely via the server-side record. With an ACTIVE
    # account the token authenticates back to exactly this user; the
    # _NonResolvingStore guarantees the lookup used only the issued session id,
    # never the token contents.
    resolved = svc.authenticate(issued)
    if status == Account_Status.ACTIVE:
        assert resolved == AuthenticatedActor(user_id, Account_Status.ACTIVE)
    else:
        # Non-ACTIVE accounts fail closed, but the point stands: any resolution
        # attempt still went only through the opaque server-side session id.
        assert resolved is None
