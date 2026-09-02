"""Property-based tests for the AuthorizationService (Property 1).

Feature: foundation-auth-couples, Property 1: Private data is reachable only by
its owner.

This module implements the single property-based test that validates
correctness Property 1 from the design ("Correctness Properties"):

    *For any* PrivateReflection (or private profile) owned by user U and *any*
    action in {read, update, delete}, *for any* user V != U, the
    Authorization_Service SHALL deny V — regardless of whether U and V share a
    couple, whether the reflection references a `couple_id`, or what resource
    identifier V supplies — while always allowing U.

The test drives the pure decision function :meth:`AuthorizationService.authorize`
over arbitrary PRIVATE_PARTNER descriptors, exercising the full space the
property quantifies over:

  * arbitrary owner U and viewer V != U;
  * arbitrary couple lifecycle (PENDING / ACTIVE / DISCONNECTED) and arbitrary
    active/former membership for *both* U and V — so a shared, ACTIVE couple is
    included, proving membership never grants private access (R16.2, R16.4);
  * whether the reflection carries the shared `couple_id` or none (R16.4);
  * an arbitrary client-supplied `resource_id`, which must never influence the
    decision (R17.1, R17.2).

Runs under the "foundation" Hypothesis profile (min 100 iterations) registered
in ``conftest.py``.

**Validates: Requirements 6.1, 6.3, 6.4, 15.3, 16.1, 16.2, 16.3, 16.4, 17.2**
"""

from __future__ import annotations

import uuid

from hypothesis import given
from hypothesis import strategies as st

from app.authorization.models import (
    HTTP_NOT_FOUND,
    Action,
    AuthenticatedActor,
    DenyReason,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Status,
    Visibility_Scope,
)


# ---------------------------------------------------------------------------
# In-memory relationship resolver (server-state stand-in for Pattern B).
#
# Property 1 concerns PRIVATE_PARTNER resources, whose decision is pure Pattern
# A (owner check). The resolver is still populated with arbitrary couple/member
# facts so the property demonstrates that *no* relationship fact — active shared
# membership included — can ever grant a non-owner access to private data.
# ---------------------------------------------------------------------------

class FakeResolver:
    """In-memory server-state resolver holding couple + membership facts."""

    def __init__(self) -> None:
        self.couple_status: dict[uuid.UUID, Couple_Status] = {}
        self.member_status: dict[tuple[uuid.UUID, uuid.UUID], Member_Status] = {}

    def set_couple(self, couple_id: uuid.UUID, status: Couple_Status) -> None:
        self.couple_status[couple_id] = status

    def set_member(
        self, couple_id: uuid.UUID, user_id: uuid.UUID, status: Member_Status
    ) -> None:
        self.member_status[(couple_id, user_id)] = status

    def get_couple_status(self, couple_id: uuid.UUID):
        return self.couple_status.get(couple_id)

    def get_member_status(self, couple_id: uuid.UUID, user_id: uuid.UUID):
        return self.member_status.get((couple_id, user_id))


# ---------------------------------------------------------------------------
# Strategies — arbitrary-but-valid values across the space the property quantifies over.
# ---------------------------------------------------------------------------

# Only read/update/delete are quantified by Property 1 ("any action in
# {read, update, delete}"); the owner must be allowed and V denied for each.
_PRIVATE_ACTIONS = st.sampled_from([Action.READ, Action.UPDATE, Action.DELETE])
_COUPLE_STATUSES = st.sampled_from(list(Couple_Status))
_MEMBER_STATUSES = st.sampled_from(list(Member_Status))
_uuids = st.uuids(version=4)


@st.composite
def _private_scenarios(draw):
    """Generate a PRIVATE_PARTNER scenario: distinct owner U and viewer V, an
    arbitrary couple + membership arrangement, and an arbitrary supplied id."""
    owner_id = draw(_uuids)
    viewer_id = draw(_uuids.filter(lambda v: v != owner_id))
    couple_id = draw(_uuids)

    # Whether the private reflection references the shared couple (R16.4). Either
    # way it must remain private to its owner.
    resource_couple_id = draw(st.sampled_from([couple_id, None]))
    # An arbitrary, untrusted client-supplied identifier (R17.1, R17.2).
    supplied_resource_id = draw(st.one_of(st.none(), _uuids))

    resolver = FakeResolver()
    resolver.set_couple(couple_id, draw(_COUPLE_STATUSES))
    # Arbitrary membership for BOTH U and V — includes the case where they are
    # both ACTIVE members of an ACTIVE couple (shared partners).
    resolver.set_member(couple_id, owner_id, draw(_MEMBER_STATUSES))
    resolver.set_member(couple_id, viewer_id, draw(_MEMBER_STATUSES))

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=owner_id,
        couple_id=resource_couple_id,
        resource_id=supplied_resource_id,
    )
    action = draw(_PRIVATE_ACTIONS)
    return owner_id, viewer_id, resource, resolver, action


# ---------------------------------------------------------------------------
# Property 1 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(scenario=_private_scenarios())
def test_property_private_data_reachable_only_by_owner(scenario):
    """Property 1: a PRIVATE_PARTNER resource is reachable only by its owner.

    For an ACTIVE owner U and any distinct viewer V — under any couple
    lifecycle, any membership arrangement (including both being active members
    of an ACTIVE couple), whether or not the resource references the couple, and
    for any client-supplied resource id — the owner U is ALWAYS allowed and the
    viewer V is ALWAYS denied (privacy-safe not-found), across read/update/delete.

    Feature: foundation-auth-couples, Property 1.
    **Validates: Requirements 6.1, 6.3, 6.4, 15.3, 16.1, 16.2, 16.3, 16.4, 17.2**
    """
    owner_id, viewer_id, resource, resolver, action = scenario
    service = AuthorizationService(resolver)

    owner = AuthenticatedActor(
        user_id=owner_id, account_status=Account_Status.ACTIVE
    )
    viewer = AuthenticatedActor(
        user_id=viewer_id, account_status=Account_Status.ACTIVE
    )

    # The owner is ALWAYS allowed (R6.1, R16.1).
    owner_decision = service.authorize(owner, action, resource)
    assert owner_decision.allowed is True

    # Any V != U is ALWAYS denied — regardless of shared couple, couple_id on the
    # resource, or supplied id (R6.3, R6.4, R15.3, R16.2, R16.3, R16.4, R17.2).
    viewer_decision = service.authorize(viewer, action, resource)
    assert viewer_decision.allowed is False
    assert viewer_decision.reason == DenyReason.NOT_OWNER
    # Privacy-safe response: ownership/existence is never disclosed (R17.2).
    assert viewer_decision.http_hint == HTTP_NOT_FOUND
