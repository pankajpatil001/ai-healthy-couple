"""AuthenticationService and the identity-provider abstraction (task 6.2).

Design "Auth module" — :class:`AuthenticationService` verifies identity via a
managed identity provider and drives registration, login, account recovery, and
re-authentication. It never trusts client-supplied identity and issues sessions
only through :class:`~app.auth.service.SessionService`
(05-authentication-and-authorization.md §2, §3, §8).

Credential material is delegated to the identity provider and is **not** stored
on :class:`~app.users.models.User` (08-technology-stack.md §9): the User table
holds only the ``auth_identifier`` coordinate. This module therefore introduces
an :class:`IdentityProvider` abstraction — the boundary to the mature auth
solution — with a concrete in-memory implementation
(:class:`InMemoryIdentityProvider`) for development and tests.

Requirement map:

* ``register`` — R1.1 (create ACTIVE), R1.2 (reject duplicate identifier),
  R1.3 (reject malformed/missing identifier), R1.4 (record ``created_at``),
  R1.5 (identifier is sensitive, never disclosed).
* ``login`` — R2.1 (issue a session for a valid ACTIVE account), R2.2 (generic
  failure that does not disclose whether the identifier exists), R2.3 (identity
  resolved server-side via the session).
* ``initiate_recovery`` / ``complete_recovery`` — R4.1 (single-purpose,
  time-limited challenge), R4.2 (identical response whether or not the identifier
  exists), R4.3/R4.4 (accept only a valid, unexpired, unused single-use
  challenge), R4.5 (revoke all sessions on success), R4.6 (CREDENTIAL_CHANGE
  audit).
* ``require_reauthentication`` — R5.1/R5.2 (verify a fresh proof; failure → 403),
  R5.3 (Sensitive_Operation set), R5.4 (REAUTH_SUCCESS audit with operation type,
  no relationship content). Produces a short-lived single-operation grant.
"""

from __future__ import annotations

import enum
import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.config import Settings, get_settings
from app.enums import Account_Status
from app.errors import (
    AuthenticationFailedError,
    ReauthRequiredError,
    ValidationError,
)
from app.auth.service import SessionService, SessionToken
from app.redis import reauth_key, recovery_key
from app.users.repository import UserRepository

# ---------------------------------------------------------------------------
# Audit vocabulary
# ---------------------------------------------------------------------------

#: Recorded on a successful login (R2.1). Session creation itself is audited by
#: SessionService as SESSION_CREATED (R2.5); this marks the authentication event.
LOGIN_EVENT = "LOGIN"
#: Recorded when account recovery completes and credentials are re-established
#: (R4.6). "Credential change" per the design's audit vocabulary.
CREDENTIAL_CHANGE_EVENT = "CREDENTIAL_CHANGE"
#: Recorded when re-authentication succeeds for a Sensitive_Operation (R5.4).
REAUTH_SUCCESS_EVENT = "REAUTH_SUCCESS"
#: Recorded on registration of a new account (R1.1).
USER_REGISTERED_EVENT = "USER_REGISTERED"

#: Audit resource types (structural labels only — never relationship content).
USER_RESOURCE_TYPE = "User"
SESSION_RESOURCE_TYPE = "Session"

#: Entropy behind opaque recovery-challenge and re-auth-grant secrets. 32 bytes
#: = 256 bits, rendered URL-safe; unguessable.
_SECRET_ENTROPY_BYTES = 32

#: Max length of an ``auth_identifier`` — mirrors the ``users.auth_identifier``
#: column width (String(320), the practical email length limit).
_MAX_IDENTIFIER_LENGTH = 320


def _now() -> datetime:
    """Timezone-aware current time (UTC), centralised for deterministic tests."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Sensitive operations (R5.3)
# ---------------------------------------------------------------------------


class Sensitive_Operation(str, enum.Enum):
    """Operations that require successful Re_Authentication before proceeding.

    The Foundation set (R5.3): account deletion request, couple disconnection,
    and account/security setting changes. Carried as the ``operation_type`` in
    the re-auth grant and the REAUTH_SUCCESS audit event (R5.4).
    """

    ACCOUNT_DELETION_REQUEST = "ACCOUNT_DELETION_REQUEST"
    COUPLE_DISCONNECTION = "COUPLE_DISCONNECTION"
    ACCOUNT_SECURITY_SETTING_CHANGE = "ACCOUNT_SECURITY_SETTING_CHANGE"


# ---------------------------------------------------------------------------
# Identity provider abstraction (08-technology-stack.md §9)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecoveryChallenge:
    """A single-purpose, time-limited account-recovery challenge (R4.1).

    ``challenge_id`` is an opaque server-side reference and ``secret`` is the
    unguessable value the user must present to :meth:`complete_recovery`. Only a
    hash of the secret is persisted (in Redis); the raw secret is returned once.
    """

    challenge_id: str
    secret: str


class IdentityProvider(ABC):
    """Boundary to the mature auth solution that owns credential material.

    Authentication primitives are delegated to a managed identity provider
    rather than built from scratch, and credential material is **never** stored
    on the User row (08-technology-stack.md §9). The Foundation depends only on
    this narrow interface:

    * :meth:`register_credentials` — associate credential material with an
      identifier when an account is created.
    * :meth:`verify_credentials` — verify a presented credential for login /
      re-authentication. Returns a boolean; it does **not** reveal whether the
      *identifier* exists, so callers can produce a generic failure (R2.2).
    * :meth:`reset_credentials` — replace credential material during recovery
      (R4.3), used only after a valid challenge is verified server-side.

    A concrete implementation (managed IdP) lives outside this slice; the
    in-memory :class:`InMemoryIdentityProvider` below serves development/tests.
    """

    @abstractmethod
    def register_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> None:
        """Associate ``credential_material`` with ``auth_identifier``."""

    @abstractmethod
    def verify_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> bool:
        """Return True iff the credential is valid for the identifier.

        MUST NOT distinguish "identifier unknown" from "credential wrong" to any
        observable degree that would let a caller leak account existence (R2.2).
        """

    @abstractmethod
    def reset_credentials(
        self, auth_identifier: str, new_credential_material: str
    ) -> None:
        """Replace the credential material for ``auth_identifier`` (R4.3)."""


class InMemoryIdentityProvider(IdentityProvider):
    """A development/test :class:`IdentityProvider` backed by an in-memory map.

    Stores a salted hash of the credential (never the plaintext) so it behaves
    like a real provider with respect to the one property that matters here:
    credentials are verified, not stored in cleartext, and the User row holds no
    credential material. It is emphatically **not** for production — the managed
    IdP replaces it — but it lets the service be exercised deterministically.

    Verification of an unknown identifier performs the same hashing work as a
    known one before returning ``False`` (a constant-ish path) so it does not
    trivially disclose existence (R2.2).
    """

    def __init__(self) -> None:
        # auth_identifier -> (salt, hash)
        self._credentials: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _hash(salt: str, credential_material: str) -> str:
        import hashlib

        return hashlib.sha256(f"{salt}:{credential_material}".encode()).hexdigest()

    def register_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> None:
        salt = secrets.token_hex(16)
        self._credentials[auth_identifier] = (
            salt,
            self._hash(salt, credential_material),
        )

    def verify_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> bool:
        entry = self._credentials.get(auth_identifier)
        # Compute a hash regardless so an unknown identifier does the same work
        # as a known one before failing (R2.2 — no existence disclosure).
        salt, stored = entry if entry is not None else (secrets.token_hex(16), "")
        candidate = self._hash(salt, credential_material)
        if entry is None:
            return False
        return secrets.compare_digest(candidate, stored)

    def reset_credentials(
        self, auth_identifier: str, new_credential_material: str
    ) -> None:
        # Recovery may re-establish credentials for a known identifier only; the
        # service verifies the challenge before calling this.
        self.register_credentials(auth_identifier, new_credential_material)


class Argon2idIdentityProvider(IdentityProvider):
    """Production :class:`IdentityProvider` using Argon2id (approved Phase 2).

    Application-managed credentials: the password is hashed with Argon2id (via
    ``argon2-cffi``) and only the encoded hash string is persisted, through the
    injected :class:`~app.auth.repository.CredentialRepository`. The plaintext is
    never stored or logged. Argon2id is a memory-hard, side-channel-resistant
    password hash — the appropriate choice for at-rest credential protection
    (08-technology-stack.md §9: "a mature authentication solution rather than
    building authentication primitives from scratch").

    The provider is addressed purely by ``auth_identifier`` (matching the
    interface the AuthenticationService already uses). It is **session-scoped**:
    a fresh instance is built per request with the request's DB session so
    writes participate in the request transaction. Verification of an unknown
    identifier still performs an Argon2 verify against a dummy hash so the timing
    of a known vs unknown identifier does not trivially disclose existence
    (R2.2).
    """

    def __init__(self, credential_repository) -> None:
        from argon2 import PasswordHasher

        self._repo = credential_repository
        # Default argon2-cffi parameters are a sensible, modern baseline; they
        # are embedded in each encoded hash so future tuning stays verifiable
        # against old hashes without a schema change.
        self._hasher = PasswordHasher()
        # A precomputed dummy hash for constant-work verification of unknown
        # identifiers (R2.2). Value is irrelevant; only the work matters.
        self._dummy_hash = self._hasher.hash("dummy-verification-password")

    def register_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> None:
        """Hash ``credential_material`` with Argon2id and persist the hash."""
        self._repo.upsert(auth_identifier, self._hasher.hash(credential_material))

    def verify_credentials(
        self, auth_identifier: str, credential_material: str
    ) -> bool:
        """Return True iff the credential verifies against the stored hash.

        Does the same Argon2 verification work whether or not the identifier is
        known (verifying against a dummy hash when absent) so it does not
        trivially disclose account existence via timing (R2.2). Never raises for
        a wrong password — a mismatch returns ``False``.
        """
        from argon2.exceptions import VerificationError, VerifyMismatchError

        stored = self._repo.get_hash(auth_identifier)
        target = stored if stored is not None else self._dummy_hash
        try:
            self._hasher.verify(target, credential_material)
        except (VerifyMismatchError, VerificationError):
            return False
        # A valid verify against the dummy hash (only possible if the caller
        # guessed the dummy password) must still fail for an unknown identifier.
        return stored is not None

    def reset_credentials(
        self, auth_identifier: str, new_credential_material: str
    ) -> None:
        """Replace the stored hash during recovery (R4.3).

        The AuthenticationService verifies the recovery challenge before calling
        this; here we simply re-hash and upsert the new credential.
        """
        self._repo.upsert(
            auth_identifier, self._hasher.hash(new_credential_material)
        )


# ---------------------------------------------------------------------------
# Recovery-challenge store (Redis-backed, single-use, time-limited)
# ---------------------------------------------------------------------------


class RecoveryChallengeStore(ABC):
    """Persistence boundary for single-use, time-limited recovery challenges.

    Behind an abstraction so the service depends on a small interface and tests
    can use a real Redis namespace or an in-memory fake. The store owns TTL
    (time-limited, R4.1) and single-use consumption (R4.4).
    """

    @abstractmethod
    def save(
        self, challenge_id: str, *, user_id: uuid.UUID, secret_hash: str, ttl_seconds: int
    ) -> None:
        """Persist a challenge with a TTL of ``ttl_seconds``."""

    @abstractmethod
    def consume(self, challenge_id: str) -> tuple[uuid.UUID, str] | None:
        """Atomically fetch-and-delete a challenge.

        Returns ``(user_id, secret_hash)`` if present (deleting it so it cannot
        be reused — single-use, R4.4), else ``None`` (unknown / expired / already
        consumed).
        """


class RedisRecoveryChallengeStore(RecoveryChallengeStore):
    """A :class:`RecoveryChallengeStore` backed by Redis.

    Each challenge is a small hash at ``recovery_key(challenge_id)`` with a TTL
    equal to ``recovery_challenge_ttl_seconds`` so Redis expires it even if no
    application check runs (time-limited, R4.1/R4.4). Consumption deletes the key
    atomically (get-then-delete guarded so a concurrent completion cannot reuse
    it — single-use, R4.4).
    """

    def __init__(self, client, settings: Settings | None = None) -> None:
        self._client = client
        self._settings = settings or get_settings()

    def _key(self, challenge_id: str) -> str:
        return recovery_key(challenge_id, self._settings)

    def save(
        self, challenge_id: str, *, user_id: uuid.UUID, secret_hash: str, ttl_seconds: int
    ) -> None:
        key = self._key(challenge_id)
        self._client.hset(
            key,
            mapping={"user_id": str(user_id), "secret_hash": secret_hash},
        )
        self._client.expire(key, max(ttl_seconds, 1))

    def consume(self, challenge_id: str) -> tuple[uuid.UUID, str] | None:
        key = self._key(challenge_id)
        raw = self._client.hgetall(key)
        if not raw:
            return None
        # Delete first; if delete removed nothing a concurrent consumer already
        # took it, so treat as absent (single-use, R4.4).
        deleted = self._client.delete(key)
        if not deleted:
            return None
        return uuid.UUID(raw["user_id"]), raw["secret_hash"]


# ---------------------------------------------------------------------------
# Re-auth grant store (Redis-backed, short-lived, single-operation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReauthToken:
    """A short-lived, single-operation re-authentication grant (R5.1).

    ``grant_id`` references the server-side grant; ``token`` is the unguessable
    secret the caller presents when performing the gated Sensitive_Operation.
    The grant is bound to a specific ``user_id`` and ``operation_type`` so it
    authorises exactly one operation for one actor.
    """

    grant_id: str
    token: str
    operation_type: Sensitive_Operation


class ReauthGrantStore(ABC):
    """Persistence boundary for short-lived, single-operation re-auth grants."""

    @abstractmethod
    def save(
        self,
        grant_id: str,
        *,
        user_id: uuid.UUID,
        operation_type: str,
        token_hash: str,
        ttl_seconds: int,
    ) -> None:
        """Persist a grant with a TTL of ``ttl_seconds`` (short-lived)."""

    @abstractmethod
    def consume(self, grant_id: str) -> tuple[uuid.UUID, str, str] | None:
        """Atomically fetch-and-delete a grant.

        Returns ``(user_id, operation_type, token_hash)`` if present (deleting it
        so it authorises exactly one operation), else ``None``.
        """


class RedisReauthGrantStore(ReauthGrantStore):
    """A :class:`ReauthGrantStore` backed by Redis at ``reauth_key(grant_id)``.

    TTL equals ``reauth_grant_ttl_seconds`` (short-lived, R5); consumption
    deletes the key atomically so one grant authorises a single operation.
    """

    def __init__(self, client, settings: Settings | None = None) -> None:
        self._client = client
        self._settings = settings or get_settings()

    def _key(self, grant_id: str) -> str:
        return reauth_key(grant_id, self._settings)

    def save(
        self,
        grant_id: str,
        *,
        user_id: uuid.UUID,
        operation_type: str,
        token_hash: str,
        ttl_seconds: int,
    ) -> None:
        key = self._key(grant_id)
        self._client.hset(
            key,
            mapping={
                "user_id": str(user_id),
                "operation_type": operation_type,
                "token_hash": token_hash,
            },
        )
        self._client.expire(key, max(ttl_seconds, 1))

    def consume(self, grant_id: str) -> tuple[uuid.UUID, str, str] | None:
        key = self._key(grant_id)
        raw = self._client.hgetall(key)
        if not raw:
            return None
        deleted = self._client.delete(key)
        if not deleted:
            return None
        return uuid.UUID(raw["user_id"]), raw["operation_type"], raw["token_hash"]


# ---------------------------------------------------------------------------
# Identifier validation (R1.3)
# ---------------------------------------------------------------------------


def _normalise_and_validate_identifier(auth_identifier: object) -> str:
    """Return a normalised identifier or raise :class:`ValidationError` (R1.3).

    The Foundation treats the identifier as an email-shaped coordinate. This is
    a *shape* check (present, a string, within length, a single ``@`` with
    non-empty local/domain parts and a dot in the domain), not full RFC
    validation — the managed IdP owns deliverability. Malformed or missing input
    is rejected with a validation error before any account is created.
    """
    if not isinstance(auth_identifier, str):
        raise ValidationError("A valid authentication identifier is required.")
    identifier = auth_identifier.strip().lower()
    if not identifier or len(identifier) > _MAX_IDENTIFIER_LENGTH:
        raise ValidationError("A valid authentication identifier is required.")
    if identifier.count("@") != 1:
        raise ValidationError("A valid authentication identifier is required.")
    local, _, domain = identifier.partition("@")
    if not local or not domain or "." not in domain:
        raise ValidationError("A valid authentication identifier is required.")
    if any(ch.isspace() for ch in identifier):
        raise ValidationError("A valid authentication identifier is required.")
    return identifier


def _hash_secret(secret: str) -> str:
    """SHA-256 hex digest of an opaque secret (challenge / grant token).

    Only hashes of these single-use secrets are stored; the raw value is handed
    to the client once and verified by constant-time comparison of hashes.
    """
    import hashlib

    return hashlib.sha256(secret.encode()).hexdigest()


# ---------------------------------------------------------------------------
# AuthenticationService
# ---------------------------------------------------------------------------


class AuthenticationService:
    """Registration, login, recovery, and re-authentication (design "Auth module").

    Collaborators are injected so the service is testable and decoupled:

    * ``user_repository`` — the only path to the ``users`` table (R1.x).
    * ``identity_provider`` — owns credential material; verifies/registers/resets
      credentials (08-technology-stack.md §9).
    * ``session_service`` — issues sessions on login (R2.1) and bulk-revokes on
      recovery (R4.5).
    * ``audit_service`` — records LOGIN / CREDENTIAL_CHANGE / REAUTH_SUCCESS with
      minimal, content-free metadata (R2.5, R4.6, R5.4).
    * ``recovery_store`` / ``reauth_store`` — Redis-backed single-use / short-lived
      state for recovery challenges (R4.1) and re-auth grants (R5.1).
    """

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        identity_provider: IdentityProvider,
        session_service: SessionService,
        audit_service: AuditService,
        recovery_store: RecoveryChallengeStore,
        reauth_store: ReauthGrantStore,
        settings: Settings | None = None,
    ) -> None:
        self._users = user_repository
        self._idp = identity_provider
        self._sessions = session_service
        self._audit = audit_service
        self._recovery = recovery_store
        self._reauth = reauth_store
        self._settings = settings or get_settings()

    # -- registration (R1) ------------------------------------------------

    def register(
        self,
        auth_identifier: str,
        credential_material: str,
        *,
        request_id: str | None = None,
    ):
        """Create a new ACTIVE account for ``auth_identifier`` (R1.1, R1.4).

        Rejects a malformed/missing identifier with :class:`ValidationError`
        (R1.3) and a duplicate identifier with :class:`IdentifierInUseError`
        (R1.2) — the repository's UNIQUE-constraint guard makes the latter
        race-safe and never leaks the existing account's data (R1.5). Credential
        material is registered with the identity provider, never stored on the
        User row (08-technology-stack.md §9).

        Returns the created :class:`~app.users.models.User`.
        """
        identifier = _normalise_and_validate_identifier(auth_identifier)
        if not isinstance(credential_material, str) or not credential_material:
            raise ValidationError("Credential material is required.")

        # Repository.create is the authoritative duplicate guard (R1.2); it
        # raises IdentifierInUseError on the UNIQUE violation.
        user = self._users.create(
            auth_identifier=identifier, status=Account_Status.ACTIVE
        )
        # Credential material is owned by the IdP, not the User row.
        self._idp.register_credentials(identifier, credential_material)

        self._audit.record(
            actor_type="USER",
            actor_id=user.id,
            event_type=USER_REGISTERED_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=user.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return user

    # -- login (R2) -------------------------------------------------------

    def login(
        self,
        auth_identifier: str,
        credential_material: str,
        *,
        request_id: str | None = None,
    ) -> SessionToken:
        """Verify credentials and issue a session for an ACTIVE account (R2.1).

        On any failure — unknown identifier, wrong credential, or a non-ACTIVE
        account — raises a single generic :class:`AuthenticationFailedError`
        (401) that does **not** disclose whether the identifier exists (R2.2).
        Identity is resolved entirely server-side; the returned
        :class:`SessionToken` is the only thing handed back (R2.3).
        """
        # Do not short-circuit before verification in a way that reveals
        # existence: resolve the user, then always exercise the IdP.
        if not isinstance(auth_identifier, str) or not isinstance(
            credential_material, str
        ):
            raise AuthenticationFailedError()
        identifier = auth_identifier.strip().lower()

        user = self._users.get_by_auth_identifier(identifier)
        credential_ok = self._idp.verify_credentials(identifier, credential_material)

        # Fail closed and generic for every failure mode (R2.2): unknown user,
        # bad credential, or an account that is not ACTIVE.
        if (
            user is None
            or not credential_ok
            or user.status != Account_Status.ACTIVE
        ):
            self._audit.record(
                actor_type="USER",
                actor_id=user.id if user is not None else None,
                event_type=LOGIN_EVENT,
                resource_type=USER_RESOURCE_TYPE,
                resource_id=user.id if user is not None else None,
                outcome="FAILURE",
                request_id=request_id,
                metadata={"reason": "INVALID_CREDENTIALS"},
            )
            raise AuthenticationFailedError()

        token = self._sessions.create_session(user.id, request_id=request_id)
        self._audit.record(
            actor_type="USER",
            actor_id=user.id,
            event_type=LOGIN_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=user.id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return token

    # -- recovery (R4) ----------------------------------------------------

    def initiate_recovery(
        self, auth_identifier: str, *, request_id: str | None = None
    ) -> RecoveryChallenge | None:
        """Begin account recovery, disclosing nothing about account existence (R4.2).

        Returns the same *observable* result to the caller whether or not the
        identifier exists: the API layer sends an identical generic success to
        the end user in both cases (design Error Handling — recovery for unknown
        identifier → 200 generic). When the identifier *does* correspond to an
        account, a single-purpose, time-limited :class:`RecoveryChallenge` is
        issued and its hash stored in Redis with a TTL (R4.1); the returned
        challenge is what a delivery channel would send to the account owner.
        When it does not, ``None`` is returned internally and no challenge is
        issued — but the caller's user-facing response is unchanged (R4.2).
        """
        if not isinstance(auth_identifier, str):
            return None
        identifier = auth_identifier.strip().lower()
        user = self._users.get_by_auth_identifier(identifier)
        if user is None:
            # No challenge issued, but the caller must return the SAME response
            # as the existing-identifier case (R4.2). No audit of a non-event.
            return None

        challenge_id = secrets.token_urlsafe(_SECRET_ENTROPY_BYTES)
        secret = secrets.token_urlsafe(_SECRET_ENTROPY_BYTES)
        self._recovery.save(
            challenge_id,
            user_id=user.id,
            secret_hash=_hash_secret(secret),
            ttl_seconds=self._settings.recovery_challenge_ttl_seconds,
        )
        return RecoveryChallenge(challenge_id=challenge_id, secret=secret)

    def complete_recovery(
        self,
        challenge_id: str,
        secret: str,
        new_credential_material: str,
        *,
        request_id: str | None = None,
    ) -> None:
        """Complete recovery with a valid, unexpired, unused challenge (R4.3).

        The challenge is consumed atomically (single-use, R4.4); a missing,
        expired, or already-used challenge, or a mismatched secret, raises
        :class:`AuthenticationFailedError`. On success the identity provider
        re-establishes credentials (R4.3), **all** of the user's sessions are
        revoked so any pre-existing (possibly attacker-held) session dies (R4.5),
        and a CREDENTIAL_CHANGE audit event is recorded (R4.6).
        """
        if not isinstance(new_credential_material, str) or not new_credential_material:
            raise ValidationError("New credential material is required.")

        consumed = self._recovery.consume(challenge_id) if challenge_id else None
        if consumed is None:
            raise AuthenticationFailedError()
        user_id, secret_hash = consumed

        # Constant-time compare of the presented secret's hash (R4.4). The
        # challenge is already consumed, so it cannot be retried.
        if not secrets.compare_digest(_hash_secret(secret or ""), secret_hash):
            raise AuthenticationFailedError()

        user = self._users.get_by_id(user_id)
        if user is None:
            raise AuthenticationFailedError()

        self._idp.reset_credentials(user.auth_identifier, new_credential_material)
        # R4.5: revoke every existing session so old/stolen tokens die.
        self._sessions.revoke_all_sessions(
            user.id, reason="RECOVERY", request_id=request_id
        )
        # R4.6: record the credential change (content-free metadata).
        self._audit.record(
            actor_type="USER",
            actor_id=user.id,
            event_type=CREDENTIAL_CHANGE_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=user.id,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={"reason": "RECOVERY"},
        )

    # -- re-authentication (R5) -------------------------------------------

    def require_reauthentication(
        self,
        session: AuthenticatedActor,
        reauth_proof: str,
        operation_type: Sensitive_Operation,
        *,
        auth_identifier: str | None = None,
        request_id: str | None = None,
    ) -> ReauthToken:
        """Verify a fresh identity proof and mint a single-operation grant (R5.1).

        The actor must present a *fresh* credential proof (verified via the
        identity provider) even though they already hold a valid session — a
        Sensitive_Operation is never authorised by session possession alone
        (R5.1). A missing or failing proof raises :class:`ReauthRequiredError`
        (403, R5.2). On success a short-lived, single-operation
        :class:`ReauthToken` bound to ``session.user_id`` and ``operation_type``
        is stored in Redis (R5.1) and a REAUTH_SUCCESS audit event carrying only
        the operation type is recorded (R5.4).

        ``auth_identifier`` may be supplied to avoid re-reading the user; when
        omitted it is resolved server-side from the session's user.
        """
        operation = Sensitive_Operation(operation_type)

        identifier = auth_identifier
        if identifier is None:
            user = self._users.get_by_id(session.user_id)
            identifier = user.auth_identifier if user is not None else None

        # Missing or failing proof → 403 (R5.2). Also fail closed if the actor's
        # identifier cannot be resolved server-side.
        if (
            identifier is None
            or not isinstance(reauth_proof, str)
            or not reauth_proof
            or not self._idp.verify_credentials(identifier, reauth_proof)
        ):
            self._audit.record(
                actor_type="USER",
                actor_id=session.user_id,
                event_type=REAUTH_SUCCESS_EVENT,
                resource_type=USER_RESOURCE_TYPE,
                resource_id=session.user_id,
                outcome="FAILURE",
                request_id=request_id,
                metadata={"operation_type": operation.value},
            )
            raise ReauthRequiredError()

        grant_id = secrets.token_urlsafe(_SECRET_ENTROPY_BYTES)
        token = secrets.token_urlsafe(_SECRET_ENTROPY_BYTES)
        self._reauth.save(
            grant_id,
            user_id=session.user_id,
            operation_type=operation.value,
            token_hash=_hash_secret(token),
            ttl_seconds=self._settings.reauth_grant_ttl_seconds,
        )
        self._audit.record(
            actor_type="USER",
            actor_id=session.user_id,
            event_type=REAUTH_SUCCESS_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=session.user_id,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={"operation_type": operation.value},
        )
        return ReauthToken(
            grant_id=grant_id, token=token, operation_type=operation
        )

    def consume_reauthentication(
        self,
        grant: ReauthToken,
        actor: AuthenticatedActor,
        operation_type: Sensitive_Operation,
    ) -> bool:
        """Validate and consume a re-auth grant for a Sensitive_Operation (R5.1).

        Returns True only if the grant exists, has not expired or been used,
        matches the presented ``token``, belongs to ``actor``, and was minted for
        ``operation_type``. Consuming the grant makes it single-use, so a caller
        that performs the gated operation cannot replay the same grant. Returns
        False otherwise; the caller (a Sensitive_Operation) then denies with a
        403 (R5.2). This is the enforcement side of the gate that
        :meth:`require_reauthentication` opens.
        """
        operation = Sensitive_Operation(operation_type)
        consumed = self._reauth.consume(grant.grant_id) if grant.grant_id else None
        if consumed is None:
            return False
        user_id, stored_operation, token_hash = consumed
        if user_id != actor.user_id:
            return False
        if stored_operation != operation.value:
            return False
        return secrets.compare_digest(_hash_secret(grant.token), token_hash)


__all__ = [
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
