"""Property test for Pattern B shared-couple access (task 4.5).

Feature: foundation-auth-couples, Property 3: Shared access requires active
membership of an ACTIVE couple.

*For any* ``SHARED_COUPLE`` resource anchored to a couple C, the
``AuthorizationService`` SHALL ALLOW a requester *iff* the requester is an
ACTIVE ``CoupleMember`` of C **and** ``C.status == ACTIVE``. Every other
configuration — a non-member, a former partner of a DISCONNECTED couple, a
member of a still-PENDING couple, or a DISCONNECTED member of an otherwise
ACTIVE couple — SHALL be denied (design.md "Property 3", 06-authorization-matrix
Pattern B).

This complements — and does not duplicate — the hand-picked example cases in
``test_authorization_service.py``. Those pin specific ``DenyReason``/http_hint
values for a handful of configurations; this test asserts the single ALLOW/DENY
*biconditional* holds across the entire cross-product of couple status,
membership status (including "no membership row"), account status and action.

The service is a pure decision function, so we drive it with the same in-memory
``FakeResolver`` shape used by the example tests — no database required.

**Validates: Requirements 13.4, 15.4**
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


# ---------------------------------------------------------------------------
# In-memory relationship resolver (server-state stand-in for Pattern B).
# ---------------------------------------------------------------------------

class FakeResolver:
    """Holds couple statuses and (couple_id, user_id) -> member status maps."""

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
# Strategies — arbitrary couple status, membership state, account, action.
# ---------------------------------------------------------------------------

# "Membership state" of the actor toward the couple: either no membership row
# (a genuine non-member) or a concrete server-side Member_Status. Modelling the
# missing row explicitly is what lets the property cover the non-member case.
_MEMBERSHIP_STATES = st.one_of(
    st.none(),
    st.sampled_from(list(Member_Status)),
)

_COUPLE_STATES = st.one_of(
    st.none(),  # couple does not resolve at all
    st.sampled_from(list(Couple_Status)),
)


# ---------------------------------------------------------------------------
# Property 3 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(
    account_status=st.sampled_from(list(Account_Status)),
    couple_status=_COUPLE_STATES,
    membership_state=_MEMBERSHIP_STATES,
    action=st.sampled_from(list(Action)),
    same_couple_ref=st.booleans(),
)
def test_property_shared_access_requires_active_member_of_active_couple(
    account_status,
    couple_status,
    membership_state,
    action,
    same_couple_ref,
):
    """Property 3: SHARED_COUPLE ALLOW iff active member of an ACTIVE couple.

    For an arbitrary couple lifecycle status, an arbitrary membership state of
    the actor (including "no membership row" => non-member), an arbitrary
    account status and action, the decision on a ``SHARED_COUPLE`` resource is
    ALLOW *exactly when* the account is ACTIVE, the couple is ACTIVE, and the
    actor is an ACTIVE member — and DENY (privacy-safe not-found) otherwise.

    ``same_couple_ref`` lets the resource occasionally point at a *different*
    couple than the one the actor is a member of, exercising the non-member /
    former-partner case even when a membership row exists elsewhere.

    Feature: foundation-auth-couples, Property 3.

    **Validates: Requirements 13.4, 15.4**
    """
    membership_couple_id = uuid.uuid4()
    # The resource is anchored either to the couple the actor relates to, or to
    # an unrelated couple (making the actor a non-member of the anchor couple).
    resource_couple_id = membership_couple_id if same_couple_ref else uuid.uuid4()

    actor = AuthenticatedActor(user_id=uuid.uuid4(), account_status=account_status)

    resolver = FakeResolver()
    # Seed the anchor couple's lifecycle status only when it resolves.
    if couple_status is not None:
        resolver.set_couple(resource_couple_id, couple_status)
    # Seed the actor's membership row (if any) against the couple they relate to.
    if membership_state is not None:
        resolver.set_member(membership_couple_id, actor.user_id, membership_state)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE,
        couple_id=resource_couple_id,
    )

    decision = AuthorizationService(resolver).authorize(actor, action, resource)

    # The authoritative membership the service will see is the row for the
    # *anchor* couple — which only exists when the actor relates to that couple.
    effective_membership = membership_state if same_couple_ref else None

    should_allow = (
        account_status == Account_Status.ACTIVE
        and couple_status == Couple_Status.ACTIVE
        and effective_membership == Member_Status.ACTIVE
    )

    assert decision.allowed is should_allow

    # A denial is always a privacy-safe not-found for the Pattern B family (the
    # account gate is the one exception and is exercised by its own example
    # test); when the account is ACTIVE every SHARED_COUPLE denial is a 404.
    if not decision.allowed and account_status == Account_Status.ACTIVE:
        assert decision.http_hint == HTTP_NOT_FOUND
        assert decision.reason in {
            DenyReason.COUPLE_NOT_ACTIVE,
            DenyReason.NOT_ACTIVE_MEMBER,
        }


@given(
    couple_status=st.sampled_from(
        [Couple_Status.PENDING, Couple_Status.DISCONNECTED]
    ),
    membership_state=st.sampled_from(list(Member_Status)),
    action=st.sampled_from(list(Action)),
)
def test_property_non_active_couple_never_grants_shared_access(
    couple_status,
    membership_state,
    action,
):
    """Property 3 (former partner / pre-active): a non-ACTIVE couple denies.

    A former partner of a DISCONNECTED couple, or any member of a still-PENDING
    couple, is denied shared access regardless of their own membership status —
    the couple lifecycle gate closes first (R13.4).

    Feature: foundation-auth-couples, Property 3.

    **Validates: Requirements 13.4, 15.4**
    """
    couple_id = uuid.uuid4()
    actor = AuthenticatedActor(
        user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE
    )

    resolver = FakeResolver()
    resolver.set_couple(couple_id, couple_status)
    resolver.set_member(couple_id, actor.user_id, membership_state)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )

    decision = AuthorizationService(resolver).authorize(actor, action, resource)

    assert decision.allowed is False
    assert decision.reason == DenyReason.COUPLE_NOT_ACTIVE
    assert decision.http_hint == HTTP_NOT_FOUND
