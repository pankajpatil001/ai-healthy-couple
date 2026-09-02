"""Property 11: At most one ACTIVE couple per user.

Feature: foundation-auth-couples

This dedicated property test proves the couple-membership invariant that
underpins Requirements 9.2, 9.3, and 11.2: across arbitrary interleavings of
couple-creation attempts by one or more users, *no user ever ends up an ACTIVE
member of more than one ACTIVE couple*, and every attempt that would violate
that invariant is rejected **without side effects** — no partial couple row, no
extra ACTIVE membership, no leftover state.

The invariant is enforced authoritatively by the partial unique index
``uq_couple_members_active_user`` on ``couple_members(user_id) WHERE
status = 'ACTIVE'`` (see migration ``0002_foundation_schema`` and the DB-backed
tests in ``tests/test_couple_service.py``). Here we drive the service logic over
many arbitrary operation sequences using the in-memory ``_FakeCoupleRepository``
whose invariant mirrors that index, so the property holds across a large input
space without a database.

R11.2 (invitation acceptance rejected when the invitee already has an ACTIVE
couple, leaving the invitation PENDING) is the same underlying invariant applied
to the accept path. ``InvitationService.accept_invitation`` is not implemented in
this slice (task 10.2), so the accept path is not exercised here; the property is
proven over the ``create_couple`` operations available today, and the invariant
it establishes is exactly what the future accept path must uphold.
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.enums import Member_Status
from app.errors import ActiveCoupleExistsError

# Reuse the in-memory fakes and pure-service builder from the couple service
# tests so this file does not duplicate — or edit — those doubles.
from tests.test_couple_service import _actor, _pure_service


def _active_couples_for(repo, user_id: uuid.UUID) -> list:
    """All ACTIVE memberships the fake repo holds for ``user_id``."""
    return [
        member
        for member in repo.members.values()
        if member.user_id == user_id and member.status == Member_Status.ACTIVE
    ]


def _snapshot(repo) -> tuple[dict, dict]:
    """Capture couple + membership state so a rejection can be shown inert.

    Records each couple's id/status and each membership's identifying fields and
    status, so a rejected attempt can be asserted to have changed *nothing*.
    """
    couples = {cid: c.status for cid, c in repo.couples.items()}
    members = {
        key: (m.couple_id, m.user_id, m.role, m.status)
        for key, m in repo.members.items()
    }
    return couples, members


# An operation is "actor index N attempts create_couple". Drawing indexes into a
# small pool of actors lets Hypothesis explore both repeated attempts by the same
# user (which must be rejected after the first success) and independent attempts
# by different users (which must each succeed), in arbitrary interleavings.
_operations = st.lists(
    st.integers(min_value=0, max_value=4),
    min_size=0,
    max_size=20,
)


@settings(max_examples=100, deadline=None)
@given(actor_count=st.integers(min_value=1, max_value=5), ops=_operations)
def test_property_at_most_one_active_couple_per_user(actor_count, ops):
    """Property 11: at most one ACTIVE couple per user; violations rejected inertly.

    Feature: foundation-auth-couples, Property 11

    Over an arbitrary sequence of ``create_couple`` attempts by an arbitrary pool
    of actors:

    * every user ends up an ACTIVE member of AT MOST ONE ACTIVE couple
      (R9.2, R9.3 — the same invariant an accepted invitation must not break,
      R11.2);
    * an actor's FIRST attempt succeeds and every subsequent attempt by that same
      actor is rejected with :class:`ActiveCoupleExistsError`;
    * each rejected attempt is a true no-op: it leaves the entire couple /
      membership state byte-for-byte unchanged (no partial couple row, no extra
      ACTIVE membership).

    **Validates: Requirements 9.2, 9.3, 11.2**
    """
    service, repo, audit = _pure_service()

    # A fixed pool of distinct actors; ``ops`` indexes into it (modulo size).
    actors = [_actor() for _ in range(actor_count)]

    # Track which actors have already had a successful create, so we know which
    # attempts are expected to succeed vs. be rejected.
    created_for: set[uuid.UUID] = set()
    audit_calls_before_success = 0

    for raw_index in ops:
        actor = actors[raw_index % actor_count]
        expect_success = actor.user_id not in created_for

        before = _snapshot(repo)
        audit_before = len(audit.calls)

        if expect_success:
            view = service.create_couple(actor)
            created_for.add(actor.user_id)
            audit_calls_before_success += 1
            # A successful create yields exactly one ACTIVE membership for the
            # actor and records exactly one audit event.
            assert view is not None
            assert len(_active_couples_for(repo, actor.user_id)) == 1
            assert len(audit.calls) == audit_before + 1
        else:
            with pytest.raises(ActiveCoupleExistsError):
                service.create_couple(actor)
            # No side effects: state is identical to before the rejected attempt,
            # and no audit event was emitted for the failed attempt.
            assert _snapshot(repo) == before
            assert len(audit.calls) == audit_before

        # The core invariant holds after EVERY operation, success or rejection.
        for a in actors:
            assert len(_active_couples_for(repo, a.user_id)) <= 1

    # Final state: each actor that ever attempted is an ACTIVE member of exactly
    # one couple; audit events equal the number of successful creates.
    for a in actors:
        active = _active_couples_for(repo, a.user_id)
        assert len(active) <= 1
        if a.user_id in created_for:
            assert len(active) == 1
    assert len(audit.calls) == len(created_for) == audit_calls_before_success


@settings(max_examples=100, deadline=None)
@given(attempts=st.integers(min_value=1, max_value=10))
def test_property_repeated_attempts_by_one_actor_reject_without_side_effects(
    attempts,
):
    """Property 11 (single-actor focus): only the first create takes effect.

    Feature: foundation-auth-couples, Property 11

    However many times a single actor calls ``create_couple``, exactly one call
    succeeds and all the rest are rejected with no side effects, leaving the
    actor an ACTIVE member of exactly one couple.

    **Validates: Requirements 9.2, 9.3, 11.2**
    """
    service, repo, audit = _pure_service()
    actor = _actor()

    successes = 0
    rejections = 0
    stable_state = None

    for _ in range(attempts):
        try:
            service.create_couple(actor)
            successes += 1
            # Capture the state right after the (only) successful create.
            stable_state = _snapshot(repo)
        except ActiveCoupleExistsError:
            rejections += 1
            # Every rejection is inert relative to the post-success state.
            assert _snapshot(repo) == stable_state

    assert successes == 1
    assert rejections == attempts - 1
    assert len(_active_couples_for(repo, actor.user_id)) == 1
    # Exactly one audit event — only the successful create emitted one.
    assert len(audit.calls) == 1
