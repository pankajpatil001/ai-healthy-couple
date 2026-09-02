"""Property test for Property 6 — out-of-reach and uncertain zones deny (task 4.6).

Property 6 (design.md "Property 6: Out-of-reach and uncertain zones deny"):

    For any request by a normal user to a SYSTEM_ONLY or PROFESSIONAL_SHARED
    resource, and for any request whose authorization decision cannot be
    established with confidence, the Authorization_Service SHALL deny.

This is the "closed side" of the visibility model: the two Foundation-hidden
zones are unconditionally out of reach, and any zone the pipeline cannot
classify defaults to DENY (R15.2). The property is proven against *arbitrary*
actors, actions, and couple/membership state — none of which may ever open one
of these zones. That is the guarantee the example tests
(``test_system_only_zone_denied`` / ``test_professional_shared_zone_denied`` in
``tests/test_authorization_service.py``) assert only for a single fixed input;
here we quantify over the whole input space rather than duplicate those cases.

The service is a pure decision function, so this drives it with an in-memory
resolver seeded with arbitrary couple/membership rows for the actor — including
the exact rows that *would* open a SHARED_COUPLE resource — to prove that even a
fully "connected" actor is denied a SYSTEM_ONLY / PROFESSIONAL_SHARED resource.

Feature: foundation-auth-couples, Property 6

**Validates: Requirements 15.2, 15.5, 15.6**
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
# Strategies — arbitrary actor / action / couple + membership state.
# ---------------------------------------------------------------------------

_actors = st.builds(
    AuthenticatedActor,
    user_id=st.uuids(version=4),
    account_status=st.sampled_from(list(Account_Status)),
)
_actions = st.sampled_from(list(Action))
_couple_statuses = st.sampled_from(list(Couple_Status))
_member_statuses = st.sampled_from(list(Member_Status))
# Sometimes attach a couple_id (with matching server rows), sometimes not — the
# closed zones must deny either way.
_optional_uuid = st.one_of(st.none(), st.uuids(version=4))


def _resolver_for(
    actor: AuthenticatedActor,
    couple_id: uuid.UUID | None,
    couple_status: Couple_Status,
    member_status: Member_Status,
) -> FakeResolver:
    """Seed a resolver that, for a SHARED_COUPLE resource, would grant access.

    By making the actor an ACTIVE member of an ACTIVE couple we set up the *most
    permissive* possible relationship state. If a SYSTEM_ONLY / PROFESSIONAL_SHARED
    resource is still denied under these rows, membership provably never opens
    the closed zones.
    """
    resolver = FakeResolver()
    if couple_id is not None:
        resolver.couple_status[couple_id] = couple_status
        resolver.member_status[(couple_id, actor.user_id)] = member_status
    return resolver


# ---------------------------------------------------------------------------
# Property 6 — SYSTEM_ONLY and PROFESSIONAL_SHARED always DENY.
# ---------------------------------------------------------------------------

@given(
    actor=_actors,
    action=_actions,
    scope=st.sampled_from(
        [Visibility_Scope.SYSTEM_ONLY, Visibility_Scope.PROFESSIONAL_SHARED]
    ),
    owner_id=_optional_uuid,
    couple_id=_optional_uuid,
    couple_status=_couple_statuses,
    member_status=_member_statuses,
)
def test_property_out_of_reach_zones_always_deny(
    actor,
    action,
    scope,
    owner_id,
    couple_id,
    couple_status,
    member_status,
):
    """Property 6: SYSTEM_ONLY / PROFESSIONAL_SHARED deny for every actor/action.

    For any actor (any account status), any action, and any couple/membership
    state — including an ACTIVE member of an ACTIVE couple, and even when the
    actor is named as the resource ``owner_id`` — a resource in a Foundation
    out-of-reach zone is denied with the zone's reason and a privacy-safe 404.

    Feature: foundation-auth-couples, Property 6

    **Validates: Requirements 15.5, 15.6**
    """
    resolver = _resolver_for(actor, couple_id, couple_status, member_status)
    service = AuthorizationService(resolver)
    resource = ResourceDescriptor(
        visibility_scope=scope,
        owner_id=owner_id,
        couple_id=couple_id,
    )

    decision = service.authorize(actor, action, resource)

    assert decision.allowed is False
    expected_reason = (
        DenyReason.SYSTEM_ONLY
        if scope == Visibility_Scope.SYSTEM_ONLY
        else DenyReason.PROFESSIONAL_SHARED
    )
    # A non-ACTIVE account short-circuits at pipeline step 1; either way the
    # request is denied. When the account is ACTIVE the zone reason applies.
    if actor.account_status == Account_Status.ACTIVE:
        assert decision.reason == expected_reason
        assert decision.http_hint == HTTP_NOT_FOUND
    else:
        assert decision.reason == DenyReason.ACCOUNT_NOT_ACTIVE


# ---------------------------------------------------------------------------
# Property 6 — an undecidable / unclassifiable zone defaults to DENY (R15.2).
# ---------------------------------------------------------------------------

class _UnknownScope:
    """A visibility_scope value the pipeline has no rule for.

    ``Visibility_Scope`` is a closed enum, so an "unknown zone" cannot arise
    from a normal enum member. To exercise the pipeline's default-deny fallback
    directly we substitute a sentinel that equals none of the known scopes,
    modelling any future/uncertain classification the pipeline cannot resolve.
    """

    def __init__(self, tag: object) -> None:
        self._tag = tag

    def __eq__(self, other: object) -> bool:  # never equal to a known scope
        return isinstance(other, _UnknownScope) and other._tag == self._tag

    def __hash__(self) -> int:
        return hash(("_UnknownScope", self._tag))


@given(
    actor=st.builds(
        AuthenticatedActor,
        user_id=st.uuids(version=4),
        # An ACTIVE account clears step 1, so the decision reaches the zone
        # dispatch where the undecidable fallback lives.
        account_status=st.just(Account_Status.ACTIVE),
    ),
    action=_actions,
    tag=st.integers(),
    owner_id=_optional_uuid,
    couple_id=_optional_uuid,
    couple_status=_couple_statuses,
    member_status=_member_statuses,
)
def test_property_undecidable_zone_defaults_to_deny(
    actor,
    action,
    tag,
    owner_id,
    couple_id,
    couple_status,
    member_status,
):
    """Property 6: an unclassifiable zone defaults to DENY (R15.2).

    For any request whose visibility zone the pipeline cannot classify — modelled
    by a scope sentinel matching none of the known zones — the decision is a
    default-deny (UNDECIDABLE) with a privacy-safe 404, regardless of actor,
    action, or couple/membership state.

    Feature: foundation-auth-couples, Property 6

    **Validates: Requirements 15.2**
    """
    resolver = _resolver_for(actor, couple_id, couple_status, member_status)
    service = AuthorizationService(resolver)
    # Build a valid descriptor, then substitute an unclassifiable scope. The
    # descriptor is a frozen, slotted dataclass, so bypass its immutability the
    # same way ``dataclasses.replace`` would — via object.__setattr__.
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=owner_id,
        couple_id=couple_id,
    )
    object.__setattr__(resource, "visibility_scope", _UnknownScope(tag))

    decision = service.authorize(actor, action, resource)

    assert decision.allowed is False
    assert decision.reason == DenyReason.UNDECIDABLE
    assert decision.http_hint == HTTP_NOT_FOUND
