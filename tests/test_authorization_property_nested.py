"""Property test for Property 8 — nested resources are filtered by their own zone (task 4.8).

Property 8 (design.md "Property 8: Nested resources are filtered by their own
zone"), R14.4:

    WHEN a request targets a container resource with nested resources, THE
    Authorization_Service SHALL evaluate each nested resource against its own
    Visibility_Zone rather than returning all nested resources because the
    requester can access the container.

The guarantee is a *set equality*: for an arbitrary container of children with
mixed owners / zones / couples, and an arbitrary actor,
:meth:`AuthorizedRepository.filter_nested` returns EXACTLY the children the
actor is *independently* authorized to READ — never one extra child smuggled in
because the actor can reach the container. The example tests in
``tests/test_authorized_repository.py`` assert this for a few fixed containers;
here we quantify over the whole input space.

The oracle re-derives the expected subset the other way round: it calls
``authorize(actor, READ, describe(child))`` per child directly and keeps those
that ALLOW. ``filter_nested`` must equal that independently-computed list,
element-for-element and in original order — so this pins both *no under-return*
(every independently-authorized child is present) and *no over-return* (no child
is returned that the actor could not have read on its own).

The service is a pure decision function, so this drives it with an in-memory
resolver seeded with arbitrary couple + membership rows.

Feature: foundation-auth-couples, Property 8

**Validates: Requirements 14.4**
"""

from __future__ import annotations

import uuid

from hypothesis import given
from hypothesis import strategies as st

from app.authorization.models import Action, AuthenticatedActor
from app.authorization.repository import (
    AuthorizedRepository,
    descriptor_for_reflection,
)
from app.authorization.service import AuthorizationService
from app.couples.models import PrivateReflection
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Status,
    Visibility_Scope,
)


# ---------------------------------------------------------------------------
# In-memory relationship resolver (arbitrary server state for Pattern B facts).
# ---------------------------------------------------------------------------

class FakeResolver:
    """In-memory server-state resolver holding couple + membership rows."""

    def __init__(self) -> None:
        self.couple_status: dict[uuid.UUID, Couple_Status] = {}
        self.member_status: dict[tuple[uuid.UUID, uuid.UUID], Member_Status] = {}

    def get_couple_status(self, couple_id: uuid.UUID):
        return self.couple_status.get(couple_id)

    def get_member_status(self, couple_id: uuid.UUID, user_id: uuid.UUID):
        return self.member_status.get((couple_id, user_id))


# ---------------------------------------------------------------------------
# Strategies — a shared "world" of a few user ids and couple ids, an arbitrary
# actor drawn from that world, and a container of arbitrary children whose
# owners / couples reference the same world so real ALLOW cases actually occur.
# ---------------------------------------------------------------------------

def _reflection(
    owner_id: uuid.UUID,
    couple_id: uuid.UUID | None,
    scope: Visibility_Scope,
) -> PrivateReflection:
    """A detached PrivateReflection row (no session) for pure filtering."""
    row = PrivateReflection(
        user_id=owner_id,
        couple_id=couple_id,
        visibility_scope=scope,
    )
    row.id = uuid.uuid4()
    return row


@st.composite
def _scenarios(draw):
    """Draw an (actor, resolver, children) triple over a small shared world.

    A handful of user ids and couple ids are minted up front so that children
    can plausibly be owned by the actor, or hang off a couple the actor is an
    active member of — otherwise every child would trivially deny and the
    ``over-return`` direction of the property would never be exercised.
    """
    user_ids = draw(
        st.lists(st.uuids(version=4), min_size=2, max_size=4, unique=True)
    )
    couple_ids = draw(
        st.lists(st.uuids(version=4), min_size=1, max_size=3, unique=True)
    )

    actor = AuthenticatedActor(
        user_id=draw(st.sampled_from(user_ids)),
        account_status=draw(st.sampled_from(list(Account_Status))),
    )

    # Seed arbitrary couple lifecycle + per-user membership for every couple in
    # the world — including the actor's own membership. This spans ACTIVE /
    # PENDING / DISCONNECTED couples and members with / without ACTIVE status,
    # covering every Pattern B branch.
    resolver = FakeResolver()
    for couple_id in couple_ids:
        resolver.couple_status[couple_id] = draw(
            st.sampled_from(list(Couple_Status))
        )
        for user_id in user_ids:
            # Some users are members (ACTIVE/DISCONNECTED), some are not (None).
            status = draw(
                st.one_of(st.none(), st.sampled_from(list(Member_Status)))
            )
            if status is not None:
                resolver.member_status[(couple_id, user_id)] = status

    # Build an arbitrary container of children. Each child gets an arbitrary
    # zone, an arbitrary owner from the world (so PRIVATE_PARTNER may or may not
    # be the actor), and an arbitrary couple binding (a real couple, or none).
    child_count = draw(st.integers(min_value=0, max_value=8))
    children = []
    for _ in range(child_count):
        scope = draw(st.sampled_from(list(Visibility_Scope)))
        owner_id = draw(st.sampled_from(user_ids))
        couple_id = draw(st.one_of(st.none(), st.sampled_from(couple_ids)))
        children.append(_reflection(owner_id, couple_id, scope))

    return actor, resolver, children


# ---------------------------------------------------------------------------
# Property 8 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(scenario=_scenarios())
def test_property_nested_children_filtered_by_own_zone(scenario):
    """Property 8: filter_nested returns EXACTLY the independently-authorized set.

    For an arbitrary container of children with mixed owners, zones and couple
    bindings, and an arbitrary actor / membership state, the children returned
    by ``filter_nested`` equal exactly the children for which the actor is
    independently authorized (``authorize(actor, READ, child_descriptor)``
    ALLOWs), evaluated child-by-child against each child's OWN zone. Container
    access can never add a child, and every independently-authorized child is
    present, in original order.

    Feature: foundation-auth-couples, Property 8

    **Validates: Requirements 14.4**
    """
    actor, resolver, children = scenario
    service = AuthorizationService(resolver)
    repo = AuthorizedRepository(session=None, authorization=service)

    kept = repo.filter_nested(actor, children, descriptor_for_reflection)

    # Oracle: the subset the actor is INDEPENDENTLY authorized to read — each
    # child judged on its own descriptor, with no notion of a container at all.
    expected = [
        child
        for child in children
        if service.authorize(
            actor, Action.READ, descriptor_for_reflection(child)
        ).allowed
    ]

    # Exact list equality pins order preservation AND both directions:
    #  * no over-return (nothing granted via container access), and
    #  * no under-return (every independently-authorized child is present).
    assert kept == expected
    # Returned children are a subset of the input, never fabricated.
    assert all(child in children for child in kept)


@given(scenario=_scenarios())
def test_property_nested_never_returns_others_private_partner(scenario):
    """Property 8 (sharpened): no returned child is another user's PRIVATE_PARTNER.

    The headline R14.4 abuse case: a couple member must never receive the other
    partner's private reflection merely because it hangs off the shared couple.
    Whatever the couple/membership state, every child ``filter_nested`` returns
    that is PRIVATE_PARTNER must be owned by the actor.

    Feature: foundation-auth-couples, Property 8

    **Validates: Requirements 14.4**
    """
    actor, resolver, children = scenario
    repo = AuthorizedRepository(
        session=None, authorization=AuthorizationService(resolver)
    )

    kept = repo.filter_nested(actor, children, descriptor_for_reflection)

    for child in kept:
        if child.visibility_scope == Visibility_Scope.PRIVATE_PARTNER:
            assert child.user_id == actor.user_id
