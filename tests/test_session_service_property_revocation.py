"""Property test for Property 9 — a revoked or expired session never authenticates
(task 6.3).

Feature: foundation-auth-couples, Property 9: A revoked or expired session never
authenticates.

The invariant (design.md "Property 9", R3.2, R3.3, R3.4, R4.5, R8.2): for *any*
session that is past its expiry time or has been revoked — including revocation
via single-session logout (``revoke_session``) or bulk revocation used by
recovery (R4.5) and account deletion (R8.2) (``revoke_all_sessions``) — *every*
subsequent authentication attempt with that session's token is treated as
unauthenticated (``authenticate`` returns ``None``).

The dual half of the invariant anchors it: a session that is *neither* expired
*nor* revoked, whose account is ACTIVE, still authenticates. This keeps the test
honest — "always return None" would satisfy the negative clause vacuously.

Uses the in-memory :class:`SessionStore` / status / audit doubles from
``tests.test_session_service`` so expiry is controlled deterministically via a
record's ``expires_at`` and revocation runs through the real service paths.
Runs on the "foundation" Hypothesis profile (min 100 iterations).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from hypothesis import assume, given
from hypothesis import strategies as st

from app.auth.service import (
    SESSION_REVOKED_EVENT,
    SessionRecord,
    SessionService,
)
from app.authorization.models import AuthenticatedActor
from app.enums import Account_Status

from tests.test_session_service import (
    _FakeStatusLookup,
    _InMemorySessionStore,
    _RecordingSession,
    _audit,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# How a live session becomes unauthenticatable. EXPIRED is modelled by rewriting
# the record's expires_at into the past; the three revocation causes exercise the
# real service revocation paths that logout / recovery / account deletion use.
_REVOKE_ALL_REASONS = ("RECOVERY", "DELETION", "LOGOUT_ALL")

invalidation_causes = st.sampled_from(
    ["EXPIRED", "REVOKE_SESSION", "REVOKE_ALL"]
)


def _service(store, statuses, audit):
    return SessionService(
        store=store,
        audit_service=_audit(audit),
        user_status_lookup=statuses,
    )


def _expire_in_place(store: _InMemorySessionStore, session_id: str, offset_seconds: int) -> None:
    """Rewrite a stored session so its expiry sits ``offset_seconds`` in the past."""
    rec = store.get(session_id)
    assert rec is not None
    store.put(
        SessionRecord(
            session_id=rec.session_id,
            user_id=rec.user_id,
            token=rec.token,
            created_at=rec.created_at,
            expires_at=rec.created_at - timedelta(seconds=offset_seconds),
            revoked=rec.revoked,
        )
    )


# ---------------------------------------------------------------------------
# Property 9 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------


@given(
    user_id=st.uuids(),
    cause=invalidation_causes,
    past_offset=st.integers(min_value=1, max_value=10_000_000),
    revoke_all_reason=st.sampled_from(_REVOKE_ALL_REASONS),
)
def test_property_revoked_or_expired_session_never_authenticates(
    user_id, cause, past_offset, revoke_all_reason
):
    """Property 9: once expired or revoked, a session's token never authenticates.

    For an arbitrary user, an active session first authenticates (the anchoring
    positive clause). After the session is invalidated — by expiry, single-session
    revocation, or bulk revocation (recovery/deletion) — every authentication with
    that same token is unauthenticated (``None``), regardless of the cause.

    Feature: foundation-auth-couples, Property 9.
    **Validates: Requirements 3.2, 3.3, 3.4, 4.5, 8.2**
    """
    store = _InMemorySessionStore()
    statuses = _FakeStatusLookup({user_id: Account_Status.ACTIVE})
    audit = _RecordingSession()
    svc = _service(store, statuses, audit)

    token = svc.create_session(user_id)

    # Positive anchor: a non-expired, non-revoked, ACTIVE session authenticates.
    assert svc.authenticate(token) == AuthenticatedActor(
        user_id, Account_Status.ACTIVE
    )

    # Invalidate the session by the chosen cause.
    if cause == "EXPIRED":
        _expire_in_place(store, token.session_id, past_offset)
    elif cause == "REVOKE_SESSION":
        # Logout of a single session (R3.3/R3.4).
        actor = AuthenticatedActor(user_id, Account_Status.ACTIVE)
        svc.revoke_session(token.session_id, actor, reason="LOGOUT")
    else:  # REVOKE_ALL
        # Bulk revocation used by recovery (R4.5) and account deletion (R8.2).
        svc.revoke_all_sessions(user_id, reason=revoke_all_reason)

    # The invariant: authentication with that token is now unauthenticated, and
    # stays that way no matter how many times it is retried.
    assert svc.authenticate(token) is None
    assert svc.authenticate(token) is None


@given(
    user_id=st.uuids(),
    revoked_flag=st.booleans(),
    expiry_offset=st.integers(min_value=-10_000_000, max_value=10_000_000),
)
def test_property_active_iff_not_expired_and_not_revoked(
    user_id, revoked_flag, expiry_offset
):
    """Property 9 (dual): a token authenticates exactly when active, else never.

    Directly quantifies over the two invalidating dimensions — the ``revoked``
    flag and an expiry offset that ranges over both past and future. A token
    authenticates if and only if the record is neither revoked nor expired (with
    the account ACTIVE); any revoked or expired record authenticates as ``None``
    (R3.2/R3.3/R3.4).

    Feature: foundation-auth-couples, Property 9.
    **Validates: Requirements 3.2, 3.3, 3.4**
    """
    store = _InMemorySessionStore()
    statuses = _FakeStatusLookup({user_id: Account_Status.ACTIVE})
    svc = _service(store, statuses, _RecordingSession())

    token = svc.create_session(user_id)
    rec = store.get(token.session_id)
    # A strictly-future offset would race the clock at offset 0; require a margin.
    assume(expiry_offset != 0)

    store.put(
        SessionRecord(
            session_id=rec.session_id,
            user_id=rec.user_id,
            token=rec.token,
            created_at=rec.created_at,
            expires_at=rec.created_at + timedelta(seconds=expiry_offset),
            revoked=revoked_flag,
        )
    )

    is_expired = expiry_offset < 0
    should_authenticate = (not revoked_flag) and (not is_expired)

    actor = svc.authenticate(token)
    if should_authenticate:
        assert actor == AuthenticatedActor(user_id, Account_Status.ACTIVE)
    else:
        assert actor is None
