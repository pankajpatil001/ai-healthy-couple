"""Property-based test for the AuthorizationService (Property 4).

Feature: foundation-auth-couples, Property 4: Former partners never gain access
to each other's private data.

This module implements the single property-based test that validates
correctness Property 4 from the design ("Correctness Properties"):

    *For any* couple that has become DISCONNECTED, neither Former_Partner SHALL
    be granted access to the other Former_Partner's `Private_Resource` as a
    result of previous membership.

Property 4 is a lifecycle-specific corollary of Pattern A (PRIVATE_PARTNER →
owner-only): private access gates on *ownership*, never *membership*, so once a
couple is DISCONNECTED, each former partner (a DISCONNECTED member) is denied
the *other's* PRIVATE_PARTNER resource. Prior membership — active or now
disconnected — is irrelevant, and referencing the (now DISCONNECTED) couple_id
on the resource never upgrades a private row to shared (R16.4). Each former
partner still retains access to their *own* private resource.

The test drives the pure decision function :meth:`AuthorizationService.authorize`
over arbitrary DISCONNECTED-couple scenarios, exercising the space the property
quantifies over:

  * two distinct former partners A and B of a couple that is DISCONNECTED;
  * arbitrary former-membership states for each (ACTIVE or DISCONNECTED rows) —
    covering the "as a result of previous membership" clause;
  * any action in {read, update, delete};
  * whether the private resource references the (DISCONNECTED) couple_id or none
    (R16.4);
  * an arbitrary client-supplied resource id, which must never influence the
    decision (R17.1, R17.2).

Assertions: B is denied A's private resource and A is denied B's (NOT_OWNER,
privacy-safe not-found), while each former partner is always allowed their own.

The :class:`FakeResolver` is reused from ``tests.test_authorization_service``
per the task instruction. Runs under the "foundation" Hypothesis profile (min
100 iterations) registered in ``conftest.py``.

**Validates: Requirements 13.5**
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

# Reuse the in-memory server-state resolver from the unit-test module, as the
# task requires — a single stand-in for the server-side relationship source.
from tests.test_authorization_service import FakeResolver


# ---------------------------------------------------------------------------
# Strategies — arbitrary-but-valid values across the space the property quantifies over.
# ---------------------------------------------------------------------------

# Property 4 concerns private access; the owner-only rule is identical for read,
# update, and delete (R16.1-R16.3), so all three are quantified.
_PRIVATE_ACTIONS = st.sampled_from([Action.READ, Action.UPDATE, Action.DELETE])
# Former-membership rows may be modelled as ACTIVE or DISCONNECTED; either way,
# membership must never grant private access to the *other* partner.
_MEMBER_STATUSES = st.sampled_from(list(Member_Status))
_uuids = st.uuids(version=4)


@st.composite
def _former_partner_scenarios(draw):
    """Generate a DISCONNECTED-couple scenario with two distinct former partners.

    Produces:
      * distinct partner ids A and B and a DISCONNECTED couple they belonged to;
      * arbitrary (former) membership rows for both A and B;
      * a PRIVATE_PARTNER resource owned by A and another owned by B, each
        optionally referencing the (DISCONNECTED) couple_id;
      * an arbitrary client-supplied resource id on each resource;
      * the action under test.
    """
    partner_a = draw(_uuids)
    partner_b = draw(_uuids.filter(lambda v: v != partner_a))
    couple_id = draw(_uuids)

    resolver = FakeResolver()
    # The couple has become DISCONNECTED (the property's precondition).
    resolver.set_couple(couple_id, Couple_Status.DISCONNECTED)
    # Arbitrary former-membership rows for BOTH partners — the "as a result of
    # previous membership" clause: neither an ACTIVE nor a DISCONNECTED row may
    # grant access to the other partner's private data.
    resolver.set_member(couple_id, partner_a, draw(_MEMBER_STATUSES))
    resolver.set_member(couple_id, partner_b, draw(_MEMBER_STATUSES))

    # Whether each private reflection references the (now DISCONNECTED) couple.
    # A couple_id must never upgrade a PRIVATE_PARTNER row to shared (R16.4).
    a_resource_couple_id = draw(st.sampled_from([couple_id, None]))
    b_resource_couple_id = draw(st.sampled_from([couple_id, None]))

    # Arbitrary, untrusted client-supplied identifiers (R17.1, R17.2).
    a_supplied_id = draw(st.one_of(st.none(), _uuids))
    b_supplied_id = draw(st.one_of(st.none(), _uuids))

    a_private = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=partner_a,
        couple_id=a_resource_couple_id,
        resource_id=a_supplied_id,
    )
    b_private = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=partner_b,
        couple_id=b_resource_couple_id,
        resource_id=b_supplied_id,
    )

    action = draw(_PRIVATE_ACTIONS)
    return partner_a, partner_b, a_private, b_private, resolver, action


# ---------------------------------------------------------------------------
# Property 4 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(scenario=_former_partner_scenarios())
def test_property_former_partners_never_reach_each_others_private_data(scenario):
    """Property 4: after DISCONNECTED, neither former partner reaches the other's
    private resource.

    For two former partners A and B of a DISCONNECTED couple — under any former
    membership arrangement, whether or not the private resource references the
    (DISCONNECTED) couple_id, and for any client-supplied resource id — B is
    ALWAYS denied A's PRIVATE_PARTNER resource and A is ALWAYS denied B's
    (NOT_OWNER, privacy-safe not-found), across read/update/delete. Each former
    partner is ALWAYS allowed their own private resource.

    Feature: foundation-auth-couples, Property 4.
    **Validates: Requirements 13.5**
    """
    partner_a, partner_b, a_private, b_private, resolver, action = scenario
    service = AuthorizationService(resolver)

    actor_a = AuthenticatedActor(
        user_id=partner_a, account_status=Account_Status.ACTIVE
    )
    actor_b = AuthenticatedActor(
        user_id=partner_b, account_status=Account_Status.ACTIVE
    )

    # B is ALWAYS denied A's private resource — prior membership never grants it
    # (R13.5, R16.2, R16.4). Privacy-safe not-found so existence never leaks.
    b_on_a = service.authorize(actor_b, action, a_private)
    assert b_on_a.allowed is False
    assert b_on_a.reason == DenyReason.NOT_OWNER
    assert b_on_a.http_hint == HTTP_NOT_FOUND

    # Symmetrically, A is ALWAYS denied B's private resource.
    a_on_b = service.authorize(actor_a, action, b_private)
    assert a_on_b.allowed is False
    assert a_on_b.reason == DenyReason.NOT_OWNER
    assert a_on_b.http_hint == HTTP_NOT_FOUND

    # Each former partner ALWAYS retains access to their OWN private resource:
    # disconnection removes shared access, not ownership of one's own data.
    assert service.authorize(actor_a, action, a_private).allowed is True
    assert service.authorize(actor_b, action, b_private).allowed is True
