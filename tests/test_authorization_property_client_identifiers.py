"""Property test: authorization ignores client-supplied identifiers (task 4.7).

Feature: foundation-auth-couples, Property 7: Authorization ignores
client-supplied identifiers and identity claims.

The invariant (design.md Property 7, R2.3, R14.1, R14.2, R14.3, R17.1): the
authorization decision is a pure function of *server-resolved* facts — the
session-resolved actor (``user_id`` + ``account_status``), the resource's
server-read ``visibility_scope`` / ``owner_id`` / ``couple_id``, and the
relationship facts resolved from server state. The purely client-controlled
fields carried on the :class:`ResourceDescriptor` for auditing only —
``resource_id`` and ``resource_type`` — must NEVER change the ALLOW / DENY
outcome. Mutating a client-supplied identifier cannot widen (or narrow) access.

Strategy: generate an arbitrary server state (actor identity + account status,
owner_id, visibility_scope, and a couple relationship registered in the
resolver), fix those facts, then vary the descriptor's client-supplied
``resource_id`` / ``resource_type`` across many arbitrary values and assert the
decision (allowed + reason + http_hint) is invariant.

The service is a pure decision function over injected server state, so this test
drives it with the in-memory :class:`FakeResolver` from the unit suite — no
database required.
"""

from __future__ import annotations

import uuid

from hypothesis import given
from hypothesis import strategies as st

from app.authorization.models import (
    Action,
    AuthenticatedActor,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.enums import Account_Status, Couple_Status, Member_Status, Visibility_Scope
from tests.test_authorization_service import FakeResolver


# ---------------------------------------------------------------------------
# Strategies over SERVER-resolved facts (the only things that may drive a
# decision) and over the CLIENT-supplied, audit-only identifiers (which must
# not).
# ---------------------------------------------------------------------------

# A stable pool of user ids so the generated actor can be the owner, a couple
# member, or an unrelated third party with realistic probability.
_ACTOR_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
_OTHER_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")
_COUPLE_ID = uuid.UUID("00000000-0000-4000-8000-0000000000c0")


@st.composite
def server_states(draw):
    """An arbitrary, self-consistent server-resolved authorization state.

    Returns the actor, action, a resolver primed with the server-side couple /
    membership facts, and the server-resolved descriptor fields (scope, owner,
    couple). Deliberately spans the interesting cases: non-ACTIVE accounts,
    owner vs non-owner, active/former/non members, and every visibility scope.
    """
    account_status = draw(st.sampled_from(list(Account_Status)))
    action = draw(st.sampled_from(list(Action)))
    scope = draw(st.sampled_from(list(Visibility_Scope)))

    # owner_id is a server-read fact: sometimes the actor, sometimes another
    # user, sometimes absent.
    owner_id = draw(st.sampled_from([_ACTOR_ID, _OTHER_ID, None]))
    # couple_id is a server-read fact carried on the row: present or absent.
    couple_id = draw(st.sampled_from([_COUPLE_ID, None]))

    resolver = FakeResolver()
    # Prime the server-side relationship facts (also arbitrary but fixed for
    # this state). These are resolved server-side, never from the request.
    couple_status = draw(st.sampled_from(list(Couple_Status) + [None]))
    if couple_status is not None:
        resolver.set_couple(_COUPLE_ID, couple_status)
    member_status = draw(st.sampled_from(list(Member_Status) + [None]))
    if member_status is not None:
        resolver.set_member(_COUPLE_ID, _ACTOR_ID, member_status)

    actor = AuthenticatedActor(user_id=_ACTOR_ID, account_status=account_status)
    return actor, action, resolver, scope, owner_id, couple_id


def _client_ids():
    """Arbitrary client-supplied resource_id values (incl. ``None``)."""
    return st.one_of(st.none(), st.uuids(version=4))


def _client_types():
    """Arbitrary client-supplied resource_type strings (incl. ``None``)."""
    return st.one_of(st.none(), st.text(max_size=32))


# ---------------------------------------------------------------------------
# Property 7 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(
    state=server_states(),
    # A list of distinct client-supplied identifier tuples to compare against
    # the baseline. Each entry is (resource_id, resource_type).
    supplied=st.lists(
        st.tuples(_client_ids(), _client_types()),
        min_size=1,
        max_size=8,
    ),
)
def test_property_decision_ignores_client_supplied_identifiers(state, supplied):
    """Property 7: mutating audit-only client identifiers never changes the decision.

    Holding every server-resolved fact fixed (actor identity + account status,
    owner_id, couple relationship in the resolver, visibility_scope), the
    ALLOW / DENY decision is invariant across arbitrary client-supplied
    ``resource_id`` / ``resource_type`` values. These fields are carried for
    auditing only and must never influence authorization (R14.2, R17.1); a
    valid session is never sufficient on its own, the decision derives from
    server state (R14.1, R14.3, R2.3).

    Feature: foundation-auth-couples, Property 7.
    **Validates: Requirements 2.3, 14.1, 14.2, 14.3, 17.1**
    """
    actor, action, resolver, scope, owner_id, couple_id = state
    service = AuthorizationService(resolver)

    def decide(resource_id, resource_type):
        resource = ResourceDescriptor(
            visibility_scope=scope,
            owner_id=owner_id,
            couple_id=couple_id,
            resource_id=resource_id,
            resource_type=resource_type,
        )
        return service.authorize(actor, action, resource)

    # Baseline: no client identifiers supplied at all.
    baseline = decide(None, None)
    baseline_key = (baseline.allowed, baseline.reason, baseline.http_hint)

    # Every arbitrary client-supplied identifier yields an identical decision.
    for resource_id, resource_type in supplied:
        decision = decide(resource_id, resource_type)
        assert (
            decision.allowed,
            decision.reason,
            decision.http_hint,
        ) == baseline_key, (
            "client-supplied identifiers changed the decision: "
            f"resource_id={resource_id!r}, resource_type={resource_type!r}"
        )


@given(
    state=server_states(),
    id_a=_client_ids(),
    id_b=_client_ids(),
    type_a=_client_types(),
    type_b=_client_types(),
)
def test_property_decision_is_pairwise_invariant_across_identifiers(
    state, id_a, id_b, type_a, type_b
):
    """Property 7 (pairwise form): any two client-identifier assignments agree.

    A focused pairwise generator so Hypothesis can shrink a discrepancy to the
    smallest differing (resource_id, resource_type) pair while the server state
    is held fixed.

    Feature: foundation-auth-couples, Property 7.
    **Validates: Requirements 2.3, 14.1, 14.2, 14.3, 17.1**
    """
    actor, action, resolver, scope, owner_id, couple_id = state
    service = AuthorizationService(resolver)

    def decide(resource_id, resource_type):
        return service.authorize(
            actor,
            action,
            ResourceDescriptor(
                visibility_scope=scope,
                owner_id=owner_id,
                couple_id=couple_id,
                resource_id=resource_id,
                resource_type=resource_type,
            ),
        )

    first = decide(id_a, type_a)
    second = decide(id_b, type_b)

    assert (first.allowed, first.reason, first.http_hint) == (
        second.allowed,
        second.reason,
        second.http_hint,
    )
