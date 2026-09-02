"""Property-based test for Property 12 (task 10.5).

Feature: foundation-auth-couples, Property 12: Only PENDING, unexpired
invitations can be accepted, and never twice.

For an arbitrary invitation status (PENDING/ACCEPTED/DECLINED/EXPIRED/REVOKED)
and arbitrary expiry (past/future), acceptance succeeds ONLY when the invitation
is PENDING *and* unexpired. Every other case — a non-PENDING invitation, an
expired PENDING invitation, or a token matching no invitation at all — is refused
with the identical privacy-safe :class:`~app.errors.ResourceNotFoundError` (404,
Privacy_Safe_Response) and adds NO membership (R11.3/R10.3/R12.3/R12.4).

The suite also anchors the "never twice" clause: a token that was successfully
accepted flips its invitation to ACCEPTED, so re-presenting the same raw token is
refused with the same privacy-safe 404 — the token is single-use and not
reusable.

The in-memory fakes and helpers are reused verbatim from
``tests.test_invitation_accept_service`` so the property drives the exact same
service wiring as the example suite. Runs under the "foundation" Hypothesis
profile (min 100 iterations) registered in ``conftest.py``.

**Validates: Requirements 10.3, 11.3, 12.3, 12.4**
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.couples import tokens
from app.enums import (
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
)
from app.errors import ResourceNotFoundError
from tests.test_invitation_accept_service import (
    _FakeCoupleRepository,
    _actor,
    _pending_couple_with_invitation,
    _pure_service,
)

# Every invitation status the lifecycle can hold. Acceptance is legal from
# exactly one of them (PENDING) and only while unexpired.
_ALL_STATUSES = list(Invitation_Status)


def _member_count(repo: _FakeCoupleRepository) -> int:
    """PARTNER_B ACTIVE members are what acceptance would add; count them."""
    return sum(
        1
        for m in repo.members.values()
        if m.role == Member_Role.PARTNER_B and m.status == Member_Status.ACTIVE
    )


# ---------------------------------------------------------------------------
# Property 12 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------


@given(
    raw=st.text(min_size=1, max_size=64),
    status=st.sampled_from(_ALL_STATUSES),
    # Expiry offset in seconds relative to "now": negative => already expired,
    # positive => still live. Zero (== now) is treated as expired (inclusive).
    expiry_offset=st.integers(min_value=-1_000_000, max_value=1_000_000),
    present_unknown_token=st.booleans(),
)
def test_property_only_pending_unexpired_is_acceptable(
    raw, status, expiry_offset, present_unknown_token
):
    """Property 12: acceptance succeeds iff the invitation is PENDING and unexpired.

    A single invitation is seeded with an arbitrary status and expiry. Acceptance
    is attempted either with the invitation's real token or with a token that
    matches nothing. The outcome is fully determined:

    * PENDING + unexpired + correct token → accepted (couple ACTIVE, exactly one
      PARTNER_B ACTIVE member added, invitation ACCEPTED).
    * every other combination (non-PENDING, expired PENDING, or an unknown token)
      → privacy-safe 404 with NO membership added and the invitation's status
      left unchanged.

    Feature: foundation-auth-couples, Property 12.

    **Validates: Requirements 10.3, 11.3, 12.3, 12.4**
    """
    service, repo, audit = _pure_service()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_offset)
    _couple, invitation = _pending_couple_with_invitation(
        repo, raw, status=status, expires_at=expires_at
    )

    # A token is acceptable only when it resolves to THIS PENDING, unexpired
    # invitation. Presenting an unknown token never matches anything.
    token_to_present = "\x00no-such-token::" + raw if present_unknown_token else raw
    is_pending = status == Invitation_Status.PENDING
    is_unexpired = expires_at > datetime.now(timezone.utc)
    should_succeed = (
        (not present_unknown_token) and is_pending and is_unexpired
    )

    if should_succeed:
        view = service.accept_invitation(_actor(), token_to_present)

        # The three coupled changes all happened; exactly one member was added.
        assert view.status == Couple_Status.ACTIVE
        assert invitation.status == Invitation_Status.ACCEPTED
        assert _member_count(repo) == 1
    else:
        status_before = invitation.status
        with pytest.raises(ResourceNotFoundError) as err:
            service.accept_invitation(_actor(), token_to_present)

        # Identical privacy-safe response for every non-acceptable case (R11.3/
        # R10.3/R12.4): a 404 that never confirms the token/invitation exists.
        assert err.value.code == "RESOURCE_NOT_FOUND"
        assert err.value.http_status == 404
        # No membership is ever added on a refused acceptance.
        assert _member_count(repo) == 0
        # The refusal never *accepts* the invitation. The only permitted side
        # effect is lazy expiry (R12.3): a due PENDING invitation reached via its
        # OWN token is materialised EXPIRED. Every other refused case — a
        # non-PENDING invitation, a still-live PENDING one, or any case reached
        # via an unknown token (which resolves to no row and so touches nothing)
        # — leaves the invitation's status exactly as seeded.
        expired_on_access = (
            (not present_unknown_token) and is_pending and not is_unexpired
        )
        if expired_on_access:
            assert invitation.status == Invitation_Status.EXPIRED
        else:
            assert invitation.status == status_before


@given(raw=st.text(min_size=1, max_size=64), ttl=st.integers(60, 30 * 24 * 3600))
def test_property_accepted_token_is_not_reusable(raw, ttl):
    """Property 12 (never twice): an accepted token cannot be accepted again.

    For any raw token and TTL, the first acceptance of a valid PENDING invitation
    succeeds and flips it to ACCEPTED. Re-presenting the SAME raw token is then
    refused with the identical privacy-safe 404 (the invitation is no longer
    PENDING), and no second membership is added — the token is single-use.

    Feature: foundation-auth-couples, Property 12.

    **Validates: Requirements 10.3, 11.3, 12.4**
    """
    service, repo, _ = _pure_service()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    _couple, invitation = _pending_couple_with_invitation(
        repo, raw, expires_at=expires_at
    )

    # First acceptance succeeds.
    view = service.accept_invitation(_actor(), raw)
    assert view.status == Couple_Status.ACTIVE
    assert invitation.status == Invitation_Status.ACCEPTED
    assert _member_count(repo) == 1

    # Second acceptance of the very same token is refused, privacy-safe.
    with pytest.raises(ResourceNotFoundError) as err:
        service.accept_invitation(_actor(), raw)
    assert err.value.code == "RESOURCE_NOT_FOUND"
    assert err.value.http_status == 404

    # Still exactly one PARTNER_B member; the invitation stays ACCEPTED.
    assert _member_count(repo) == 1
    assert invitation.status == Invitation_Status.ACCEPTED
