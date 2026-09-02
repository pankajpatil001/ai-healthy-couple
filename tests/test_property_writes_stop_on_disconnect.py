"""Property test for Property 20 — collaborative writes stop on disconnection (task 9.4).

Property 20 (design.md "Property 20: Collaborative writes stop on disconnection"):

    Every new collaborative write to a DISCONNECTED couple's SHARED_COUPLE
    resources is disabled.

R13.3: *"WHILE a Couple's Couple_Status is DISCONNECTED, THE System SHALL disable
new collaborative writes to that Couple's SHARED_COUPLE resources."*

This is the write-side lifecycle guarantee of Pattern B. The
:class:`AuthorizationService` enforces it in ``_pattern_b_shared_couple``: a
SHARED_COUPLE resource is writable only while its couple is ACTIVE; once the
couple is DISCONNECTED the lifecycle check denies *before* membership is even
consulted, so ``authorize`` returns DENY with ``DenyReason.COUPLE_NOT_ACTIVE``.

The example suite (``test_pattern_b_former_partner_of_disconnected_couple_denied``
in ``tests/test_authorization_service.py``) asserts this for a single fixed
input. Here we quantify over the whole write-action / former-membership input
space: for a DISCONNECTED couple, EVERY collaborative write (CREATE / UPDATE /
DELETE) by any actor — including a former ACTIVE member of that very couple — is
denied. To keep the property non-vacuous we anchor it against the ACTIVE case:
an ACTIVE member of an ACTIVE couple is still allowed to write, proving the
denial is the disconnection's doing rather than a blanket refusal.

The service is a pure decision function, so this drives it with the in-memory
:class:`FakeResolver` reused from the example suite — no database required.

Feature: foundation-auth-couples, Property 20

**Validates: Requirements 13.3**
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

# Reuse the in-memory server-state resolver from the example suite so the
# property drives the exact same wiring the unit tests exercise.
from tests.test_authorization_service import FakeResolver


# ---------------------------------------------------------------------------
# Strategies — arbitrary collaborative write actions + former-membership state.
# ---------------------------------------------------------------------------

# Collaborative *writes* only: CREATE / UPDATE / DELETE (READ is not a write).
_write_actions = st.sampled_from([Action.CREATE, Action.UPDATE, Action.DELETE])

# Any membership status the former partner's row might carry. Even a stale
# ACTIVE membership row must not resurrect write access once the couple is gone.
_member_statuses = st.sampled_from(list(Member_Status))


def _active_actor() -> AuthenticatedActor:
    """An ACTIVE-account actor (step 1 of the pipeline clears)."""
    return AuthenticatedActor(user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE)


# ---------------------------------------------------------------------------
# Property 20 — DISCONNECTED couple: every collaborative write is disabled.
# ---------------------------------------------------------------------------

@given(
    action=_write_actions,
    former_member_status=_member_statuses,
    is_member=st.booleans(),
)
def test_property_disconnected_couple_disables_all_collaborative_writes(
    action,
    former_member_status,
    is_member,
):
    """Property 20: no new collaborative write survives disconnection.

    For a SHARED_COUPLE resource anchored to a DISCONNECTED couple, EVERY write
    action (CREATE / UPDATE / DELETE) by any ACTIVE-account actor — whether the
    actor holds a (possibly stale) membership row of any status or no membership
    at all — is DENIED with ``COUPLE_NOT_ACTIVE`` and a privacy-safe 404. The
    lifecycle gate fires before membership, so a Former_Partner's leftover ACTIVE
    row can never reopen write access (R13.3).

    Feature: foundation-auth-couples, Property 20

    **Validates: Requirements 13.3**
    """
    actor = _active_actor()
    couple_id = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.DISCONNECTED)
    if is_member:
        # A former partner of the couple, carrying an arbitrary membership row.
        resolver.set_member(couple_id, actor.user_id, former_member_status)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE,
        couple_id=couple_id,
    )

    decision = AuthorizationService(resolver).authorize(actor, action, resource)

    assert decision.allowed is False
    assert decision.reason == DenyReason.COUPLE_NOT_ACTIVE
    assert decision.http_hint == HTTP_NOT_FOUND


# ---------------------------------------------------------------------------
# Anchor — ACTIVE couple + ACTIVE member: writes ARE allowed (non-vacuity).
# ---------------------------------------------------------------------------

@given(action=_write_actions)
def test_property_active_couple_active_member_write_allowed(action):
    """Anchor for Property 20: the ACTIVE case still permits collaborative writes.

    An ACTIVE member of an ACTIVE couple may CREATE / UPDATE / DELETE a
    SHARED_COUPLE resource. This proves the disconnection denial above is caused
    by the lifecycle transition, not a blanket refusal of shared writes — so the
    "writes stop on disconnection" property is not vacuously satisfied.

    Feature: foundation-auth-couples, Property 20

    **Validates: Requirements 13.3**
    """
    actor = _active_actor()
    couple_id = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, actor.user_id, Member_Status.ACTIVE)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE,
        couple_id=couple_id,
    )

    decision = AuthorizationService(resolver).authorize(actor, action, resource)

    assert decision.allowed is True
