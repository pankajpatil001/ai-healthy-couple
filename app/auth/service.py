"""Auth module services.

Design "Auth module":
- AuthenticationService: verify identity via the identity provider; drive
  registration, login, recovery, and re-authentication. Never trusts
  client-supplied identity; issues sessions only through SessionService.
- SessionService: create, resolve, expire, and revoke sessions. Sessions live
  in Redis with an explicit expiry; account status is re-checked against
  PostgreSQL on each authentication so SUSPENDED/DELETED accounts fail closed.

Implemented in tasks 6.1 and 6.2. This module currently implements task 6.1:
the :class:`SessionService`.

SessionService (design.md "SessionService")
-------------------------------------------
Sessions live in **Redis** as the fast lookup / revocation store with an
explicit expiry. Redis is *not* the source of truth for the account's lifecycle
status: on every authentication the account's :class:`~app.enums.Account_Status`
is re-read from the authoritative store (PostgreSQL) so that a SUSPENDED or
DELETED account fails closed even if a live session token is presented (R3.6).

Session state model (Redis), keyed by ``session_id``::

    { user_id, created_at, expires_at, revoked }

with a matching **TTL so expiry is enforced even if the app misses a check**
(R3.1/R3.2). Revocation flips ``revoked`` (and the record is short-lived anyway
because the TTL mirrors expiry), so a revoked token can never authenticate again
(R3.3/R3.4).

The Session_Token issued to the client is an **opaque, unpredictable** reference
generated with :mod:`secrets`; it carries *no* account data (R2.4). All state
lives server-side, resolved from the session record — never from client claims
(R2.3).
"""

from __future__ import annotations

import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.config import Settings, get_settings
from app.enums import Account_Status
from app.redis import session_key

# ---------------------------------------------------------------------------
# Audit vocabulary (design.md "SessionService"; R2.5, R3.7)
# ---------------------------------------------------------------------------

#: Event type recorded when a session is created (R2.5).
SESSION_CREATED_EVENT = "SESSION_CREATED"
#: Event type recorded when a session is revoked (R3.7).
SESSION_REVOKED_EVENT = "SESSION_REVOKED"

#: Audit resource type for session events.
SESSION_RESOURCE_TYPE = "Session"

#: Number of random bytes behind an opaque Session_Token. 32 bytes = 256 bits of
#: entropy, rendered URL-safe; far beyond any feasible guessing attack. The token
#: is opaque: it is *only* a lookup key, never a container of account data (R2.4).
_TOKEN_ENTROPY_BYTES = 32


def _now() -> datetime:
    """Timezone-aware current time (UTC).

    Centralised so tests can reason about expiry deterministically and so every
    timestamp stored/compared is tz-aware (avoids naive/aware comparison bugs).
    """
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionToken:
    """The opaque reference handed to the client after a session is created.

    ``session_id`` is the server-side identifier of the session record and
    ``token`` is the unpredictable secret the client presents on later requests.
    Neither carries account data — resolving a token to a user requires the
    server-side session record (R2.3, R2.4).
    """

    session_id: str
    token: str


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """The server-side session state stored in Redis.

    Mirrors the design's Redis model: ``session_id -> { user_id, created_at,
    expires_at, revoked }``. ``token`` is stored so a presented token can be
    matched against the record; it is never returned to any other user.
    """

    session_id: str
    user_id: uuid.UUID
    token: str
    created_at: datetime
    expires_at: datetime
    revoked: bool

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True once the session has passed its expiry time (R3.2)."""
        return (now or _now()) >= self.expires_at

    def is_active(self, *, now: datetime | None = None) -> bool:
        """True only for a session that is neither revoked nor expired."""
        return not self.revoked and not self.is_expired(now=now)


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """A privacy-safe summary of one active session for own-session management (R3.5).

    Deliberately excludes the token/secret — listing sessions must never re-expose
    a credential that could be replayed.
    """

    session_id: str
    created_at: datetime
    expires_at: datetime


# ---------------------------------------------------------------------------
# User-status lookup abstraction
# ---------------------------------------------------------------------------


class UserStatusLookup(Protocol):
    """Resolves a user's authoritative :class:`~app.enums.Account_Status`.

    :meth:`SessionService.authenticate` re-reads the account status from the
    authoritative store (PostgreSQL) on every request so SUSPENDED/DELETED
    accounts fail closed (R3.6) — Redis is only the session cache, never the
    source of truth for lifecycle. Injecting this narrow lookup keeps the
    session service decoupled from the users module and trivially testable.

    Returns ``None`` when the user no longer exists (e.g. hard-deleted), which
    the caller treats as unauthenticated.
    """

    def get_account_status(self, user_id: uuid.UUID) -> Account_Status | None:
        """Return the user's current account status, or ``None`` if unknown."""
        ...


# ---------------------------------------------------------------------------
# Session store abstraction (Redis-backed)
# ---------------------------------------------------------------------------


class SessionStore(ABC):
    """Persistence boundary for session records.

    Kept behind an abstraction so :class:`SessionService` depends on a small,
    intention-revealing interface rather than on Redis command details, and so
    tests can exercise either a real Redis namespace or an in-memory fake. The
    store owns TTL/expiry mechanics (R3.1) and the per-user index that backs
    :meth:`list_ids_for_user` (R3.5) / bulk revocation (R4.5, R8.2).
    """

    @abstractmethod
    def save(self, record: SessionRecord, *, ttl_seconds: int) -> None:
        """Persist ``record`` with a TTL of ``ttl_seconds`` mirroring its expiry."""

    @abstractmethod
    def get(self, session_id: str) -> SessionRecord | None:
        """Return the record for ``session_id`` or ``None`` if absent/expired."""

    @abstractmethod
    def delete(self, session_id: str, user_id: uuid.UUID) -> None:
        """Remove a session record and drop it from its user's index."""

    @abstractmethod
    def ids_for_user(self, user_id: uuid.UUID) -> list[str]:
        """Return the session ids currently indexed for ``user_id``."""


class RedisSessionStore(SessionStore):
    """A :class:`SessionStore` backed by Redis.

    Each session is a small hash at ``session_key(session_id)`` with a TTL equal
    to the remaining session lifetime, so Redis evicts an expired session even if
    no application check runs (R3.1/R3.2 defence in depth). A per-user index set
    at ``{prefix}:session:user:{user_id}`` records the user's session ids so we
    can list/bulk-revoke without scanning the keyspace.

    The client only needs a tiny slice of the Redis API (``hset``, ``hgetall``,
    ``delete``, ``expire``, ``sadd``, ``srem``, ``smembers``); both a real
    ``redis.Redis`` and the test's namespaced wrapper satisfy it.
    """

    def __init__(self, client, settings: Settings | None = None) -> None:
        self._client = client
        self._settings = settings or get_settings()

    # -- key helpers ------------------------------------------------------

    def _session_key(self, session_id: str) -> str:
        return session_key(session_id, self._settings)

    def _user_index_key(self, user_id: uuid.UUID) -> str:
        # Namespaced alongside sessions but under a distinct sub-namespace so it
        # never collides with a session id.
        return session_key(f"user:{user_id}", self._settings)

    # -- SessionStore -----------------------------------------------------

    def save(self, record: SessionRecord, *, ttl_seconds: int) -> None:
        key = self._session_key(record.session_id)
        self._client.hset(
            key,
            mapping={
                "user_id": str(record.user_id),
                "token": record.token,
                "created_at": record.created_at.isoformat(),
                "expires_at": record.expires_at.isoformat(),
                "revoked": "1" if record.revoked else "0",
            },
        )
        # TTL mirrors expiry so Redis enforces it independently of the app (R3.1).
        # Guard against a non-positive TTL (Redis would treat <=0 as immediate
        # delete / error); a session that is already expired is simply not stored
        # with a live TTL.
        self._client.expire(key, max(ttl_seconds, 1))

        index_key = self._user_index_key(record.user_id)
        self._client.sadd(index_key, record.session_id)
        # Keep the index from outliving every session it points at.
        self._client.expire(index_key, max(ttl_seconds, 1))

    def get(self, session_id: str) -> SessionRecord | None:
        raw = self._client.hgetall(self._session_key(session_id))
        if not raw:
            return None
        return SessionRecord(
            session_id=session_id,
            user_id=uuid.UUID(raw["user_id"]),
            token=raw["token"],
            created_at=datetime.fromisoformat(raw["created_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            revoked=raw["revoked"] == "1",
        )

    def delete(self, session_id: str, user_id: uuid.UUID) -> None:
        self._client.delete(self._session_key(session_id))
        self._client.srem(self._user_index_key(user_id), session_id)

    def ids_for_user(self, user_id: uuid.UUID) -> list[str]:
        members = self._client.smembers(self._user_index_key(user_id))
        return list(members)


# ---------------------------------------------------------------------------
# SessionService
# ---------------------------------------------------------------------------


class SessionService:
    """Create, resolve, expire, and revoke sessions (design.md "SessionService").

    Responsibilities and the requirements they satisfy:

    * :meth:`create_session` — issue an opaque, unpredictable Session_Token and
      assign an expiry; TTL in Redis mirrors that expiry (R3.1); emit a
      ``SESSION_CREATED`` audit event (R2.5).
    * :meth:`authenticate` — resolve the user from the *server-side* session, not
      client claims (R2.3); treat expired (R3.2) or revoked (R3.4) sessions as
      unauthenticated; re-read account status so SUSPENDED/DELETED fail closed
      (R3.6).
    * :meth:`revoke_session` — make a token unusable (R3.3/R3.4) and emit a
      ``SESSION_REVOKED`` audit event (R3.7).
    * :meth:`list_active_sessions` — a user's own active sessions (R3.5).
    * :meth:`revoke_all_sessions` — bulk revoke, used by recovery (R4.5) and
      account deletion (R8.2).
    """

    def __init__(
        self,
        *,
        store: SessionStore,
        audit_service: AuditService,
        user_status_lookup: UserStatusLookup,
        settings: Settings | None = None,
    ) -> None:
        self._store = store
        self._audit = audit_service
        self._user_status = user_status_lookup
        self._settings = settings or get_settings()

    # -- creation ---------------------------------------------------------

    def create_session(
        self, user_id: uuid.UUID, *, request_id: str | None = None
    ) -> SessionToken:
        """Create a session for ``user_id`` and return its opaque token.

        The session id and token are independent, unpredictable secrets
        (:mod:`secrets`); the token is opaque and carries no account data (R2.4).
        The record is stored with a TTL equal to ``session_ttl_seconds`` so its
        Redis expiry mirrors ``expires_at`` (R3.1). A ``SESSION_CREATED`` audit
        event is recorded with only minimal, structural metadata (R2.5).
        """
        ttl_seconds = self._settings.session_ttl_seconds
        now = _now()
        session_id = secrets.token_urlsafe(_TOKEN_ENTROPY_BYTES)
        token = secrets.token_urlsafe(_TOKEN_ENTROPY_BYTES)

        record = SessionRecord(
            session_id=session_id,
            user_id=user_id,
            token=token,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            revoked=False,
        )
        self._store.save(record, ttl_seconds=ttl_seconds)

        self._audit.record(
            actor_type="USER",
            actor_id=user_id,
            event_type=SESSION_CREATED_EVENT,
            resource_type=SESSION_RESOURCE_TYPE,
            resource_id=None,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={"session_id": session_id},
        )
        return SessionToken(session_id=session_id, token=token)

    # -- resolution -------------------------------------------------------

    def authenticate(self, session_token: SessionToken) -> AuthenticatedActor | None:
        """Resolve a presented token to an :class:`AuthenticatedActor`, or ``None``.

        ``None`` means *unauthenticated* — the caller maps that to a 401. A token
        is unauthenticated when:

        * the session record is missing (unknown / TTL-evicted),
        * the presented ``token`` does not match the stored one,
        * the session is expired (R3.2) or revoked (R3.4), or
        * the account is not ACTIVE — SUSPENDED/DELETED fail closed (R3.6), and a
          user that no longer exists is likewise rejected.

        The user is always resolved from the server-side record, never from any
        client-supplied identity claim (R2.3).
        """
        record = self._store.get(session_token.session_id)
        if record is None:
            return None

        # Constant-time compare of the opaque token to resist timing attacks.
        if not secrets.compare_digest(record.token, session_token.token):
            return None

        if not record.is_active():
            # Expired (R3.2) or revoked (R3.4). Best-effort cleanup of an expired
            # record + its index entry keeps list/bulk operations tidy.
            if record.is_expired():
                self._store.delete(record.session_id, record.user_id)
            return None

        # R3.6: re-read authoritative account status; SUSPENDED/DELETED (or a
        # vanished user) fail closed regardless of the live session.
        status = self._user_status.get_account_status(record.user_id)
        if status != Account_Status.ACTIVE:
            return None

        return AuthenticatedActor(user_id=record.user_id, account_status=status)

    # -- revocation -------------------------------------------------------

    def revoke_session(
        self,
        session_id: str,
        actor: AuthenticatedActor,
        *,
        request_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Revoke a single session so its token can no longer authenticate.

        Deleting the record (and its index entry) makes the token unusable on all
        subsequent requests (R3.3/R3.4). Idempotent: revoking an already-gone
        session is a no-op that still records the revocation intent. A
        ``SESSION_REVOKED`` audit event is emitted (R3.7).
        """
        record = self._store.get(session_id)
        # Prefer the record's owner (server truth); fall back to the acting actor
        # so we can still clean up the index even if the record is already gone.
        user_id = record.user_id if record is not None else actor.user_id
        self._store.delete(session_id, user_id)

        metadata: dict[str, object] = {"session_id": session_id}
        if reason is not None:
            metadata["reason"] = reason
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=SESSION_REVOKED_EVENT,
            resource_type=SESSION_RESOURCE_TYPE,
            resource_id=None,
            outcome="SUCCESS",
            request_id=request_id,
            metadata=metadata,
        )

    def revoke_all_sessions(
        self,
        user_id: uuid.UUID,
        reason: str,
        *,
        request_id: str | None = None,
    ) -> None:
        """Revoke every session for ``user_id`` (recovery R4.5, deletion R8.2).

        Each removed session is recorded as a ``SESSION_REVOKED`` audit event so
        the bulk action is fully attributable. Safe to call when the user has no
        sessions (no events recorded).
        """
        for session_id in self._store.ids_for_user(user_id):
            self._store.delete(session_id, user_id)
            self._audit.record(
                actor_type="USER",
                actor_id=user_id,
                event_type=SESSION_REVOKED_EVENT,
                resource_type=SESSION_RESOURCE_TYPE,
                resource_id=None,
                outcome="SUCCESS",
                request_id=request_id,
                metadata={"session_id": session_id, "reason": reason},
            )

    # -- listing ----------------------------------------------------------

    def list_active_sessions(self, user_id: uuid.UUID) -> list[SessionSummary]:
        """Return the user's own active (non-expired, non-revoked) sessions (R3.5).

        Expired/revoked entries are filtered out and any expired records found are
        cleaned up so the index stays accurate. Summaries exclude the token so a
        secret is never re-exposed.
        """
        now = _now()
        summaries: list[SessionSummary] = []
        for session_id in self._store.ids_for_user(user_id):
            record = self._store.get(session_id)
            if record is None:
                # TTL-evicted; drop the dangling index entry.
                self._store.delete(session_id, user_id)
                continue
            if record.is_expired(now=now):
                self._store.delete(session_id, user_id)
                continue
            if record.revoked:
                continue
            summaries.append(
                SessionSummary(
                    session_id=record.session_id,
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                )
            )
        return summaries


__all__ = [
    "SessionService",
    "SessionToken",
    "SessionRecord",
    "SessionSummary",
    "SessionStore",
    "RedisSessionStore",
    "UserStatusLookup",
    "SESSION_CREATED_EVENT",
    "SESSION_REVOKED_EVENT",
    "SESSION_RESOURCE_TYPE",
    # Re-exported from app.auth.authentication (task 6.2) so the whole Auth
    # module surface is reachable from a single import site, as the design
    # groups AuthenticationService and SessionService in one "Auth module".
    "AuthenticationService",
    "IdentityProvider",
    "InMemoryIdentityProvider",
    "Argon2idIdentityProvider",
    "RecoveryChallenge",
    "RecoveryChallengeStore",
    "RedisRecoveryChallengeStore",
    "ReauthToken",
    "ReauthGrantStore",
    "RedisReauthGrantStore",
    "Sensitive_Operation",
    "LOGIN_EVENT",
    "CREDENTIAL_CHANGE_EVENT",
    "REAUTH_SUCCESS_EVENT",
    "USER_REGISTERED_EVENT",
]


# NOTE: imported at the *end* of the module to avoid a circular import —
# app.auth.authentication imports SessionService/SessionToken from this module.
from app.auth.authentication import (  # noqa: E402
    CREDENTIAL_CHANGE_EVENT,
    LOGIN_EVENT,
    REAUTH_SUCCESS_EVENT,
    USER_REGISTERED_EVENT,
    Argon2idIdentityProvider,
    AuthenticationService,
    IdentityProvider,
    InMemoryIdentityProvider,
    ReauthGrantStore,
    ReauthToken,
    RecoveryChallenge,
    RecoveryChallengeStore,
    RedisReauthGrantStore,
    RedisRecoveryChallengeStore,
    Sensitive_Operation,
)
