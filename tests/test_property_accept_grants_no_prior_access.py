"""Property test for Property 2 — acceptance grants no access to prior resources
(task 10.4).

Property 2 (design.md "Property 2: Accepting an invitation grants no access to
any resource created before acceptance"):

    For any set of Private_Resources owned by an inviter before an invitee
    accepts, after acceptance the invitee SHALL be denied every one of those
    private resources; acceptance grants the invitee access only to
    SHARED_COUPLE resources of that couple.

This is a property of the *Authorization layer*, not of the invitation record:
acceptance changes only the invitee's relationship (adds a PARTNER_B ACTIVE
membership and flips the couple to ACTIVE). It creates no grant on any
pre-existing row.

We model the moment *just after* acceptance: invitee B is an ACTIVE member of an
ACTIVE couple C alongside owner A. Then, for ANY pre-existing PRIVATE_PARTNER
resource owned by A (whether or not it references C, and for read/update/delete),
B is DENIED with ``NOT_OWNER`` — private access gates on ownership (Pattern A),
which acceptance never confers (R11.6). For a SHARED_COUPLE resource of C, B IS
ALLOWED — shared access gates on active membership of an ACTIVE couple
(Pattern B), which acceptance does confer (R11.5).

The service is a pure decision function, so this drives it with the in-memory
``FakeResolver`` reused from ``tests.test_authorization_service`` — no database
required.

Feature: foundation-auth-couples, Property 2

**Validates: Requirements 11.5, 11.6**
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
from app.enums import Account_Status, Couple_Status, Member_Status, Visibility_Scope
from tests.test_authorization_service import FakeResolver


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Read/update/delete are the sensitive accesses to a pre-existing resource;
# CREATE is not an access to an already-created private resource, so the
# property quantifies over these three (R11.6).
_access_actions = st.sampled_from([Action.READ, Action.UPDATE, Action.DELETE])

# The couple_id carried by a pre-existing PRIVATE_PARTNER resource: it may
# reference the shared couple C, some *other* couple, or be absent entirely.
# None of these may open the row to the invitee — the zone comes from the row's
# own visibility_scope, never inferred from couple_id (R16.4).


def _post_acceptance_world():
    """A world just after B accepts A's invitation.

    Returns ``(resolver, owner_a, invitee_b, couple_c)`` where couple C is ACTIVE
    and both A (PARTNER_A) and B (PARTNER_B, the freshly-joined invitee) are
    ACTIVE members — exactly the relationship state acceptance produces.
    """
    owner_a = uuid.uuid4()
    invitee_b = uuid.uuid4()
    couple_c = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_c, Couple_Status.ACTIVE)
    resolver.set_member(couple_c, owner_a, Member_Status.ACTIVE)
    resolver.set_member(couple_c, invitee_b, Member_Status.ACTIVE)
    return resolver, owner_a, invitee_b, couple_c


# ---------------------------------------------------------------------------
# Property 2 — a pre-existing PRIVATE_PARTNER resource of A is denied to B.
# ---------------------------------------------------------------------------

@given(
    action=_access_actions,
    # The couple_id the pre-existing private resource carries: the shared couple
    # C (filled in inside the test), a foreign couple, or none.
    couple_ref=st.sampled_from(["shared", "foreign", "none"]),
    foreign_couple_id=st.uuids(version=4),
)
def test_property_accept_denies_all_prior_private_resources(
    action,
    couple_ref,
    foreign_couple_id,
):
    """Property 2: after acceptance, B is denied every pre-existing private
    resource of A (R11.6).

    For any PRIVATE_PARTNER resource owned by A — with a couple_id pointing at
    the shared couple, at a foreign couple, or at nothing — the just-joined
    invitee B is denied read/update/delete with ``NOT_OWNER`` and a privacy-safe
    404. Membership (which acceptance confers) never grants private access.

    Feature: foundation-auth-couples, Property 2

    **Validates: Requirements 11.6**
    """
    resolver, owner_a, invitee_b, couple_c = _post_acceptance_world()
    service = AuthorizationService(resolver)

    if couple_ref == "shared":
        carried_couple_id = couple_c
    elif couple_ref == "foreign":
        carried_couple_id = foreign_couple_id
    else:
        carried_couple_id = None

    actor_b = AuthenticatedActor(
        user_id=invitee_b, account_status=Account_Status.ACTIVE
    )
    prior_private = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=owner_a,
        couple_id=carried_couple_id,
    )

    decision = service.authorize(actor_b, action, prior_private)

    # Acceptance grants B nothing on A's pre-existing private data.
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_OWNER
    assert decision.http_hint == HTTP_NOT_FOUND

    # Sanity: the resource is genuinely A's — A is still allowed, so the DENY
    # above is about B's lack of ownership, not a broken/orphaned resource.
    actor_a = AuthenticatedActor(
        user_id=owner_a, account_status=Account_Status.ACTIVE
    )
    assert service.authorize(actor_a, action, prior_private).allowed is True


# ---------------------------------------------------------------------------
# Property 2 — the only thing acceptance grants B is SHARED_COUPLE of C.
# ---------------------------------------------------------------------------

@given(action=_access_actions)
def test_property_accept_grants_only_shared_couple_access(action):
    """Property 2: acceptance grants B access to SHARED_COUPLE resources of C
    (R11.5).

    A SHARED_COUPLE resource of the couple B just joined is the one thing
    acceptance opens: B is an ACTIVE member of the now-ACTIVE couple, so
    Pattern B allows read/update/delete.

    Feature: foundation-auth-couples, Property 2

    **Validates: Requirements 11.5**
    """
    resolver, _owner_a, invitee_b, couple_c = _post_acceptance_world()
    service = AuthorizationService(resolver)

    actor_b = AuthenticatedActor(
        user_id=invitee_b, account_status=Account_Status.ACTIVE
    )
    shared = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE,
        couple_id=couple_c,
    )

    assert service.authorize(actor_b, action, shared).allowed is True


# ---------------------------------------------------------------------------
# Property 2 — the combined guarantee over an arbitrary mix of prior resources:
# B gets ONLY SHARED_COUPLE(C), and NONE of A's pre-existing private rows.
# ---------------------------------------------------------------------------

# Each pre-existing resource A owns is modelled as (scope, couple_ref). Private
# rows may carry the shared, a foreign, or no couple_id; there is also at least
# one SHARED_COUPLE row of C in the mix so we prove the positive grant too.
_prior_resource = st.tuples(
    st.sampled_from(
        [Visibility_Scope.PRIVATE_PARTNER, Visibility_Scope.SHARED_COUPLE]
    ),
    st.sampled_from(["shared", "foreign", "none"]),
)


@given(
    resources=st.lists(_prior_resource, min_size=1, max_size=8),
    action=_access_actions,
    foreign_couple_id=st.uuids(version=4),
)
def test_property_accept_grants_only_shared_never_prior_private(
    resources,
    action,
    foreign_couple_id,
):
    """Property 2: over any bag of A's pre-existing resources, acceptance opens
    exactly the SHARED_COUPLE rows of C and no PRIVATE_PARTNER row (R11.5, R11.6).

    For each resource we assert: B is ALLOWED iff it is a SHARED_COUPLE resource
    anchored to C; every PRIVATE_PARTNER resource (regardless of the couple_id it
    carries) and every SHARED_COUPLE resource of a foreign/absent couple is
    DENIED. This is the whole property: only SHARED_COUPLE(C) access, never any
    pre-existing private resource.

    Feature: foundation-auth-couples, Property 2

    **Validates: Requirements 11.5, 11.6**
    """
    resolver, owner_a, invitee_b, couple_c = _post_acceptance_world()
    service = AuthorizationService(resolver)
    actor_b = AuthenticatedActor(
        user_id=invitee_b, account_status=Account_Status.ACTIVE
    )

    def _couple_id_for(ref: str) -> uuid.UUID | None:
        if ref == "shared":
            return couple_c
        if ref == "foreign":
            return foreign_couple_id
        return None

    for scope, couple_ref in resources:
        couple_id = _couple_id_for(couple_ref)
        resource = ResourceDescriptor(
            visibility_scope=scope,
            # Only PRIVATE_PARTNER rows have a personal owner; A owns them all.
            owner_id=owner_a if scope == Visibility_Scope.PRIVATE_PARTNER else None,
            couple_id=couple_id,
        )

        decision = service.authorize(actor_b, action, resource)

        is_shared_of_c = (
            scope == Visibility_Scope.SHARED_COUPLE and couple_id == couple_c
        )
        if is_shared_of_c:
            assert decision.allowed is True
        else:
            assert decision.allowed is False
            # A pre-existing private resource of A is denied as a non-owner.
            if scope == Visibility_Scope.PRIVATE_PARTNER:
                assert decision.reason == DenyReason.NOT_OWNER
