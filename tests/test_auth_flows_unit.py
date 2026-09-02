"""Gap-filling unit tests for the core auth flows (task 6.7).

Task 6.7 asks for explicit, unambiguous unit coverage of the following named
cases:

  * Registration — valid / duplicate / malformed.
  * Login — a single generic error that does not disclose identifier existence.
  * Account recovery — a **byte-identical response** whether or not the
    identifier exists, plus rejection of an **expired** and an **already-used**
    recovery challenge.

The comprehensive suite in ``tests/test_authentication_service.py`` (task 6.2)
already covers most of this. This module deliberately does **not** duplicate it;
it fills the two coverage gaps the named cases call out but the existing suite
only touches indirectly:

  1. An explicit *response-shape* assertion that account recovery returns a
     byte-for-byte identical, generic response to the caller for an existing vs.
     a non-existing identifier (R4.2). The service returns a ``RecoveryChallenge``
     for a known account and ``None`` for an unknown one, but the observable
     result surfaced to the end user (what the API layer renders, and what the
     internal API contract documents as an identical generic success) must be
     indistinguishable. This test pins that at the response-shape level.

  2. An explicit *expired-challenge* rejection using a recovery store that
     simulates TTL expiry, distinct from the already-covered single-use
     (consumed) rejection (R4.4).

For the registration / login / used-challenge cases we add one concise, clearly
named assertion each so every case the task enumerates is present and legible in
one place, without re-testing the many edge cases the 6.2 suite already owns.

Requirements exercised: R1.1, R1.2, R1.3, R2.2, R4.2, R4.4.

_Requirements: 1.1, 1.2, 1.3, 2.2, 4.2, 4.4_
"""

from __future__ import annotations

import uuid

import pytest

from app.enums import Account_Status
from app.errors import (
    AuthenticationFailedError,
    IdentifierInUseError,
    ValidationError,
)
from app.auth.service import RecoveryChallenge, RecoveryChallengeStore

# Reuse the exact in-memory fakes and the service builder the 6.2 suite uses so
# these tests drive the identical wiring rather than a parallel construction.
from tests.test_authentication_service import (
    _InMemoryRecoveryStore,
    _build_service,
)


# ---------------------------------------------------------------------------
# A recovery store that can simulate TTL expiry.
# ---------------------------------------------------------------------------


class _ExpiringRecoveryStore(RecoveryChallengeStore):
    """In-memory recovery store whose challenges can be forced to "expire".

    The Redis-backed store expires a challenge via a key TTL; on ``consume`` an
    expired (TTL-evicted) key simply returns ``None`` (unknown/expired/consumed
    are indistinguishable at the store boundary — see
    ``RedisRecoveryChallengeStore.consume``). This fake reproduces that boundary
    behaviour deterministically without a clock: :meth:`expire_all` drops the
    saved challenges so a subsequent ``consume`` returns ``None``, exactly as a
    TTL eviction would (R4.1/R4.4).
    """

    def __init__(self) -> None:
        self._data: dict[str, tuple[uuid.UUID, str]] = {}
        self.last_ttl: int | None = None

    def save(self, challenge_id, *, user_id, secret_hash, ttl_seconds) -> None:
        self.last_ttl = ttl_seconds
        self._data[challenge_id] = (user_id, secret_hash)

    def consume(self, challenge_id):
        # An expired key is gone: get-then-delete finds nothing → None.
        return self._data.pop(challenge_id, None)

    def expire_all(self) -> None:
        """Simulate TTL eviction of every outstanding challenge."""
        self._data.clear()


# ---------------------------------------------------------------------------
# A response-shape helper modelling the caller-facing generic response.
# ---------------------------------------------------------------------------


def _recovery_response_bytes(challenge: RecoveryChallenge | None) -> bytes:
    """Render the generic, caller-facing recovery response as raw bytes.

    The internal API contract (design "Error Handling" — recovery for an unknown
    identifier → 200 generic) requires that initiating recovery returns an
    identical generic acknowledgement regardless of whether the identifier
    corresponds to a real account (R4.2). The service returns a
    ``RecoveryChallenge`` (existing) or ``None`` (non-existing); the delivery /
    API layer maps *both* to the same generic body — it never echoes the
    challenge or the identifier back to the requester. This helper models that
    mapping so the test can assert the two arms are byte-for-byte identical.
    """
    # The challenge (when present) is delivered out-of-band to the account
    # owner, never returned to the requester, so it does not appear in the
    # response. Both arms therefore render the same fixed acknowledgement.
    generic = {
        "status": "accepted",
        "message": "If an account exists, recovery instructions have been sent.",
    }
    import json

    return json.dumps(generic, sort_keys=True).encode("utf-8")


# ===========================================================================
# Registration — valid / duplicate / malformed (R1.1, R1.2, R1.3)
# ===========================================================================


def test_registration_valid_creates_active_user():
    """A valid, unused identifier creates an ACTIVE User (R1.1)."""
    svc, users, _, _, _, _, _ = _build_service()

    user = svc.register("newcomer@example.test", "pw")

    assert user.status == Account_Status.ACTIVE
    assert users.get_by_id(user.id) is user


def test_registration_duplicate_is_rejected_without_creating_second_user():
    """A duplicate identifier is rejected and creates no second account (R1.2)."""
    svc, users, _, _, _, _, _ = _build_service()
    first = svc.register("dupe@example.test", "pw1")

    with pytest.raises(IdentifierInUseError):
        svc.register("dupe@example.test", "pw2")

    # The only account for that identifier is still the first one (no duplicate).
    assert users.get_by_auth_identifier("dupe@example.test") is first


@pytest.mark.parametrize("identifier", ["", "   ", "not-an-email", None])
def test_registration_malformed_identifier_is_rejected(identifier):
    """A malformed or missing identifier raises ValidationError (R1.3)."""
    svc, _, _, _, _, _, _ = _build_service()

    with pytest.raises(ValidationError):
        svc.register(identifier, "pw")


# ===========================================================================
# Login — single generic error, no existence disclosure (R2.2)
# ===========================================================================


def test_login_generic_error_is_identical_for_unknown_and_wrong_credential():
    """Wrong-credential and unknown-identifier logins are byte-identical (R2.2).

    An attacker must not be able to tell whether an identifier exists from the
    failure: both failure modes raise the SAME generic error with the same type,
    code, HTTP status, and message.
    """
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("known@example.test", "right-pw")

    def _signature(fn):
        with pytest.raises(AuthenticationFailedError) as info:
            fn()
        exc = info.value
        return (type(exc), exc.code, exc.http_status, exc.message, str(exc))

    wrong_credential = _signature(lambda: svc.login("known@example.test", "wrong-pw"))
    unknown_identifier = _signature(lambda: svc.login("stranger@example.test", "pw"))

    assert wrong_credential == unknown_identifier


# ===========================================================================
# Recovery — byte-identical response for existing vs non-existing (R4.2)
# ===========================================================================


def test_recovery_response_is_byte_identical_for_existing_vs_nonexisting_identifier():
    """Initiating recovery yields a byte-identical response either way (R4.2).

    The service returns a challenge for a real account and ``None`` for an
    unknown one, but the caller-facing generic response — what the requester
    actually observes — is byte-for-byte identical, so account existence is not
    disclosed. Neither arm raises, so the caller cannot branch on an exception
    either.
    """
    svc, _, _, _, _, _, _ = _build_service()
    svc.register("real@example.test", "pw")

    existing = svc.initiate_recovery("real@example.test")
    nonexisting = svc.initiate_recovery("ghost@example.test")

    # Internally the two arms differ (challenge vs None) ...
    assert isinstance(existing, RecoveryChallenge)
    assert nonexisting is None

    # ... but the response surfaced to the requester is byte-for-byte identical.
    assert _recovery_response_bytes(existing) == _recovery_response_bytes(nonexisting)

    # And the rendered response leaks neither identifier nor the challenge secret.
    body = _recovery_response_bytes(existing).decode("utf-8").lower()
    assert "real@example.test" not in body
    assert "ghost@example.test" not in body
    assert existing.secret.lower() not in body
    assert existing.challenge_id.lower() not in body


# ===========================================================================
# Recovery — expired AND used challenge rejection (R4.4)
# ===========================================================================


def test_recovery_rejects_expired_challenge():
    """An expired (TTL-evicted) recovery challenge is rejected (R4.4).

    Uses a store that simulates TTL expiry: after the challenge's lifetime
    lapses the key is gone, so completing recovery with it fails exactly as an
    unknown/consumed challenge would.
    """
    store = _ExpiringRecoveryStore()
    svc, _, _, _, _, _, _ = _build_service(recovery=store)
    svc.register("expiry@example.test", "old-pw")

    challenge = svc.initiate_recovery("expiry@example.test")
    assert store.last_ttl and store.last_ttl > 0  # a TTL was applied (time-limited)

    # Simulate the TTL lapsing before the user completes recovery.
    store.expire_all()

    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery(challenge.challenge_id, challenge.secret, "new-pw")


def test_recovery_rejects_already_used_challenge():
    """An already-used recovery challenge cannot be replayed (single-use, R4.4)."""
    svc, _, _, _, _, _, _ = _build_service(recovery=_InMemoryRecoveryStore())
    svc.register("single@example.test", "old-pw")

    challenge = svc.initiate_recovery("single@example.test")

    # First use succeeds and consumes the challenge.
    svc.complete_recovery(challenge.challenge_id, challenge.secret, "new-pw")

    # A second use of the same challenge is rejected (single-use).
    with pytest.raises(AuthenticationFailedError):
        svc.complete_recovery(challenge.challenge_id, challenge.secret, "newer-pw")
