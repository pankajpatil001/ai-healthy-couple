"""Property 13 — invitation acceptance is atomic against concurrent disconnection.

Feature: foundation-auth-couples

Design §37 / R11.4 (design.md "Property 13"):

    *For any* interleaving of a concurrent ``accept_invitation`` and
    ``disconnect_couple`` on the same couple, the resulting state SHALL be
    consistent — the couple is never left with a half-applied membership or a
    contradictory couple/member status combination.

The repository serialises these two operations against each other with row
locks and a re-check *at commit*: ``accept_invitation_atomic`` row-locks the
invitation and its couple ``FOR UPDATE`` and requires **both** to still be
``PENDING``; ``disconnect_couple_atomic`` row-locks the couple ``FOR UPDATE``
and requires it to be ``ACTIVE``. Because the two preconditions
(couple PENDING vs. couple ACTIVE) are mutually exclusive, from any given
committed state **at most one** of {accept, disconnect} can succeed; the other
observes the winner's committed state under the lock and is refused with
``ResourceNotFoundError`` — never a partial write.

This module models arbitrary *serialized interleavings* (any ordering of
accept / disconnect operations against the same couple + invitation) using the
in-memory fakes that mirror those row-lock / re-check semantics, and asserts an
explicit consistency invariant holds **after every operation in every
ordering**. A serialized-interleaving model plus the row-lock / re-check
contract is sufficient to validate R11.4; true concurrent threads are covered
separately by the accept-vs-disconnect concurrency integration test (task 13.4).

**Validates: Requirements 11.4**
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

# Reuse the accept fake that already models the row-locked re-check semantics
# of accept_invitation_atomic (re-checks invitation PENDING + couple PENDING
# under the simulated lock, and enforces the at-most-one-ACTIVE-couple rule).
# That fake keys ``members`` by ``member.id``; test_couple_service's same-named
# fake keys by ``(couple_id, user_id)`` and its disconnect monkeypatch is bound
# to *that* class, so it is not reusable here. We add a matching
# ``disconnect_couple_atomic`` (requires couple ACTIVE, row-locked re-check)
# onto the accept fake so this arena has BOTH atomic operations wired.
from tests.test_invitation_accept_service import _FakeCoupleRepository

from app.enums import (
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
)
from app.errors import ActiveCoupleExistsError, ResourceNotFoundError


def _fake_disconnect_couple_atomic(self, couple_id):
    """Mirror CoupleRepository.disconnect_couple_atomic on the accept fake.

    Row-locked re-check semantics: only an ACTIVE couple may be disconnected;
    otherwise raise ResourceNotFoundError without mutating anything. On success
    the couple and ALL its members become DISCONNECTED together (single atomic
    step). Keyed by ``member.id`` to match this fake's ``members`` dict.
    """
    couple = self.couples.get(couple_id)
    if couple is None or couple.status != Couple_Status.ACTIVE:
        raise ResourceNotFoundError()
    now = datetime.now(timezone.utc)
    couple.status = Couple_Status.DISCONNECTED
    couple.disconnected_at = now
    for member in self.members.values():
        if member.couple_id == couple_id:
            member.status = Member_Status.DISCONNECTED
            member.left_at = now
    return couple


_FakeCoupleRepository.disconnect_couple_atomic = _fake_disconnect_couple_atomic


# ---------------------------------------------------------------------------
# World builder: one couple + invitation + invitee, the accept/disconnect arena
# ---------------------------------------------------------------------------


def _fresh_world():
    """A PENDING couple with PARTNER_A ACTIVE and a PENDING invitation for an
    invitee — the exact starting arena where accept and disconnect race.

    Returns ``(repo, couple, invitation, partner_a_id, invitee_id)``.
    """
    repo = _FakeCoupleRepository()
    couple = repo._add_couple(status=Couple_Status.PENDING)
    partner_a_id = uuid.uuid4()
    repo._add_member(couple.id, partner_a_id, Member_Role.PARTNER_A)
    invitation = repo._add_invitation(couple.id, token_hash="tok-hash")
    invitee_id = uuid.uuid4()
    return repo, couple, invitation, partner_a_id, invitee_id


def _do_accept(repo, invitation, invitee_id):
    """Attempt the atomic accept; swallow the expected rejections.

    Returns True on a successful commit, False when the repository refused the
    operation (couple/invitation no longer PENDING, or invitee already coupled).
    """
    try:
        repo.accept_invitation_atomic(
            invitation_id=invitation.id, invitee_user_id=invitee_id
        )
        return True
    except (ResourceNotFoundError, ActiveCoupleExistsError):
        return False


def _do_disconnect(repo, couple):
    """Attempt the atomic disconnect; swallow the expected rejection.

    Returns True on a successful commit, False when the repository refused
    (couple not ACTIVE — still PENDING or already DISCONNECTED).
    """
    try:
        repo.disconnect_couple_atomic(couple.id)
        return True
    except ResourceNotFoundError:
        return False


# ---------------------------------------------------------------------------
# The consistency invariant (explicit) — asserted after EVERY operation
# ---------------------------------------------------------------------------


def _assert_consistent(repo, couple, invitation, invitee_id):
    """The couple/invitation/member state is internally non-contradictory.

    This encodes exactly the "no half-applied / no contradictory combination"
    contract of R11.4 / design Property 13. It must hold in the initial state
    and after every accept/disconnect (successful or refused), for any ordering.

    Rules (each a way the accept-vs-disconnect race could otherwise corrupt
    state):

    * Couple status is one of the three legal lifecycle states.
    * A PENDING couple has NOT been joined: no PARTNER_B member exists and the
      invitation is still PENDING (accept has not partially applied).
    * An ACTIVE couple has been fully joined: the invitation is ACCEPTED and
      the invitee is an ACTIVE PARTNER_B member (accept applied *completely* —
      never "ACTIVE but member missing" nor "member added but invitation still
      PENDING").
    * A DISCONNECTED couple has ALL its members DISCONNECTED (disconnect applied
      to every member — never "couple DISCONNECTED while the just-accepted
      member is still ACTIVE").
    * The invitee never ends up as an ACTIVE member of a DISCONNECTED couple.
    * No user is an ACTIVE member of more than one couple (the at-most-one-
      ACTIVE-couple rule the partial unique index enforces).
    """
    # -- couple status is legal --
    assert couple.status in {
        Couple_Status.PENDING,
        Couple_Status.ACTIVE,
        Couple_Status.DISCONNECTED,
    }

    members = [m for m in repo.members.values() if m.couple_id == couple.id]
    partner_bs = [m for m in members if m.role == Member_Role.PARTNER_B]

    if couple.status == Couple_Status.PENDING:
        # Accept has not (even partially) applied: no invitee member, and the
        # invitation is untouched.
        assert partner_bs == []
        assert invitation.status == Invitation_Status.PENDING
        assert couple.activated_at is None

    elif couple.status == Couple_Status.ACTIVE:
        # Accept applied COMPLETELY: invitation flipped AND invitee enrolled.
        assert invitation.status == Invitation_Status.ACCEPTED
        assert couple.activated_at is not None
        active_bs = [
            m
            for m in partner_bs
            if m.user_id == invitee_id and m.status == Member_Status.ACTIVE
        ]
        assert len(active_bs) == 1  # the member is present and ACTIVE

    else:  # DISCONNECTED
        # Disconnect applied to EVERY member — none left dangling ACTIVE.
        assert couple.disconnected_at is not None
        assert all(m.status == Member_Status.DISCONNECTED for m in members)
        # The just-(maybe-)accepted invitee is never ACTIVE on a dead couple.
        assert not any(
            m.user_id == invitee_id and m.status == Member_Status.ACTIVE
            for m in members
        )

    # -- global: at most one ACTIVE membership per user, over all couples --
    active_by_user: dict[uuid.UUID, int] = {}
    for m in repo.members.values():
        if m.status == Member_Status.ACTIVE:
            active_by_user[m.user_id] = active_by_user.get(m.user_id, 0) + 1
    assert all(count <= 1 for count in active_by_user.values())


# ---------------------------------------------------------------------------
# Property 13 — arbitrary interleavings leave a consistent end state
# ---------------------------------------------------------------------------

# 0 = accept attempt, 1 = disconnect attempt.
_OPERATIONS = st.lists(
    st.sampled_from([0, 1]), min_size=1, max_size=8
)


@settings(deadline=None)  # foundation profile: min 100 iterations (conftest)
@given(operations=_OPERATIONS)
def test_property_accept_disconnect_interleavings_stay_consistent(operations):
    """Property 13: for ANY ordering of accept/disconnect operations against the
    same couple + invitation, the state stays consistent and non-contradictory.

    From a PENDING couple, exactly one accept can succeed (making it ACTIVE);
    from an ACTIVE couple, exactly one disconnect can succeed (making it
    DISCONNECTED). Because accept requires couple PENDING and disconnect
    requires couple ACTIVE, at most one of the two can win from any state and
    the loser is cleanly refused — never producing a half-applied or
    contradictory couple/member combination. The invariant is checked after the
    initial setup and after every single operation.

    Feature: foundation-auth-couples

    **Validates: Requirements 11.4**
    """
    repo, couple, invitation, _partner_a_id, invitee_id = _fresh_world()

    # The invariant must hold from the very start.
    _assert_consistent(repo, couple, invitation, invitee_id)

    for op in operations:
        if op == 0:
            _do_accept(repo, invitation, invitee_id)
        else:
            _do_disconnect(repo, couple)
        # After EVERY interleaved operation the state is non-contradictory.
        _assert_consistent(repo, couple, invitation, invitee_id)

    # Sanity on the terminal state: a couple that ever went ACTIVE and was then
    # disconnected is fully torn down; one that only ever saw accepts is ACTIVE
    # with a live invitee; one that only saw failed disconnects is still PENDING.
    _assert_consistent(repo, couple, invitation, invitee_id)


@settings(deadline=None)
@given(
    # Force an accept to precede a disconnect in the ordering, so we exercise
    # the "second op observes the first's committed state" direction directly.
    lead_disconnects=st.integers(min_value=0, max_value=3),
    trailing_disconnects=st.integers(min_value=0, max_value=3),
)
def test_property_accept_then_disconnect_is_ordered_and_exclusive(
    lead_disconnects, trailing_disconnects
):
    """Property 13 (ordered slice): disconnects before the accept are all
    refused (couple PENDING), the accept then activates the couple, and a
    following disconnect observes the ACTIVE couple and tears it down cleanly.

    This mirrors the DB-backed "second operation observes the first's committed
    state" check: only one of {accept, disconnect} succeeds from a given state,
    and the end state is always consistent.

    Feature: foundation-auth-couples

    **Validates: Requirements 11.4**
    """
    repo, couple, invitation, _partner_a_id, invitee_id = _fresh_world()

    # Disconnect attempts against a still-PENDING couple must all be refused,
    # leaving the couple PENDING and un-joined.
    for _ in range(lead_disconnects):
        assert _do_disconnect(repo, couple) is False
        _assert_consistent(repo, couple, invitation, invitee_id)
    assert couple.status == Couple_Status.PENDING

    # The accept now succeeds and activates the couple completely.
    assert _do_accept(repo, invitation, invitee_id) is True
    _assert_consistent(repo, couple, invitation, invitee_id)
    assert couple.status == Couple_Status.ACTIVE
    assert invitation.status == Invitation_Status.ACCEPTED

    # A second accept can never win now (invitation + couple no longer PENDING).
    assert _do_accept(repo, invitation, invitee_id) is False
    _assert_consistent(repo, couple, invitation, invitee_id)

    # Trailing disconnects: the first observes ACTIVE and succeeds; any further
    # ones observe DISCONNECTED and are refused. End state stays consistent.
    disconnected_once = False
    for _ in range(trailing_disconnects):
        result = _do_disconnect(repo, couple)
        if not disconnected_once:
            assert result is True
            disconnected_once = True
        else:
            assert result is False
        _assert_consistent(repo, couple, invitation, invitee_id)

    if trailing_disconnects:
        assert couple.status == Couple_Status.DISCONNECTED


@settings(deadline=None)
@given(pre_disconnects=st.integers(min_value=1, max_value=4))
def test_property_disconnect_before_accept_never_corrupts(pre_disconnects):
    """Property 13 (disconnect-first slice): a disconnect attempt observed
    against a PENDING couple never short-circuits it to DISCONNECTED, so a
    later accept still commits fully and consistently.

    Feature: foundation-auth-couples

    **Validates: Requirements 11.4**
    """
    repo, couple, invitation, _partner_a_id, invitee_id = _fresh_world()

    for _ in range(pre_disconnects):
        # Disconnect requires ACTIVE; against PENDING it is a clean refusal.
        assert _do_disconnect(repo, couple) is False
        _assert_consistent(repo, couple, invitation, invitee_id)

    # The couple was never mutated by the refused disconnects.
    assert couple.status == Couple_Status.PENDING
    assert couple.disconnected_at is None
    assert all(
        m.status == Member_Status.ACTIVE
        for m in repo.members.values()
        if m.couple_id == couple.id
    )

    # Accept still applies atomically and consistently afterwards.
    assert _do_accept(repo, invitation, invitee_id) is True
    _assert_consistent(repo, couple, invitation, invitee_id)
    assert couple.status == Couple_Status.ACTIVE
