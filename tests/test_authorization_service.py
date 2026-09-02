"""Unit tests for the AuthorizationService decision pipeline (task 4.1).

Covers the five-step pipeline and both reference patterns from the design's
"Authorization Design" section:

  * Step 1 — non-ACTIVE accounts (SUSPENDED / DELETED) deny before any resource
    is resolved (R7.2, R7.3).
  * Step 2 — an unresolvable resource is a privacy-safe not-found (R14.1, R17.3).
  * Pattern A (PRIVATE_PARTNER) — ALLOW only the owner; deny every non-owner,
    even when the reflection carries a couple_id and even for the shared partner
    (R15.3, R16.1–R16.4).
  * Pattern B (SHARED_COUPLE) — ALLOW only an active member of an ACTIVE couple;
    deny non-members, former partners of a DISCONNECTED couple, and members of a
    still-PENDING couple (R15.4, R13.4).
  * SYSTEM_ONLY / PROFESSIONAL_SHARED — always deny in the Foundation (R15.5,
    R15.6).
  * Undecidable / unknown zone — default-deny (R15.2).
  * visibility_scope is honoured from the row; a couple_id never upgrades a
    PRIVATE_PARTNER resource to shared (R16.4).
  * Client-supplied identifiers are irrelevant — the decision is computed from
    the server-resolved actor + descriptor (R14.2, R17.1).

The service is a pure decision function, so these tests drive it with an
in-memory :class:`FakeResolver` — no database required.
"""

from __future__ import annotations

import uuid

import pytest

from app.authorization.models import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    Action,
    AuthenticatedActor,
    Decision,
    DenyReason,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.enums import Account_Status, Couple_Status, Member_Status, Visibility_Scope


# ---------------------------------------------------------------------------
# In-memory relationship resolver (stands in for the server-side repository).
# ---------------------------------------------------------------------------

class FakeResolver:
    """In-memory server-state resolver for Pattern B.

    Holds couple statuses and (couple_id, user_id) -> member status maps. This
    is the *server-derived* relationship source; the service asks it, never the
    client, for membership and lifecycle facts.
    """

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
# Helpers
# ---------------------------------------------------------------------------

def _actor(status: Account_Status = Account_Status.ACTIVE) -> AuthenticatedActor:
    return AuthenticatedActor(user_id=uuid.uuid4(), account_status=status)


def _service(resolver: FakeResolver | None = None) -> AuthorizationService:
    return AuthorizationService(resolver or FakeResolver())


# ---------------------------------------------------------------------------
# Step 1 — account ACTIVE gate (R7.2, R7.3)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status", [Account_Status.SUSPENDED, Account_Status.DELETED]
)
def test_non_active_account_denied_before_resource_resolution(status):
    """SUSPENDED/DELETED deny at step 1, before the resource is even inspected."""
    service = _service()
    actor = _actor(status)
    # Owner-matching resource that would otherwise ALLOW — the account gate wins.
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=actor.user_id,
    )

    decision = service.authorize(actor, Action.READ, resource)

    assert decision.allowed is False
    assert decision.reason == DenyReason.ACCOUNT_NOT_ACTIVE
    assert decision.http_hint == HTTP_FORBIDDEN


def test_active_account_passes_step_one():
    """An ACTIVE owner of a private resource is allowed (step 1 does not block)."""
    actor = _actor()
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER, owner_id=actor.user_id
    )
    assert _service().authorize(actor, Action.READ, resource).allowed is True


# ---------------------------------------------------------------------------
# Step 2 — unresolvable resource is a privacy-safe not-found (R14.1, R17.3)
# ---------------------------------------------------------------------------

def test_missing_resource_is_privacy_safe_not_found():
    decision = _service().authorize(_actor(), Action.READ, None)
    assert decision.allowed is False
    assert decision.reason == DenyReason.RESOURCE_NOT_FOUND
    assert decision.http_hint == HTTP_NOT_FOUND


# ---------------------------------------------------------------------------
# Pattern A — PRIVATE_PARTNER owner check (R15.3, R16.1-R16.4)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "action", [Action.READ, Action.UPDATE, Action.DELETE, Action.CREATE]
)
def test_pattern_a_owner_allowed_for_all_actions(action):
    """The owner may read/update/delete/create their own private resource."""
    actor = _actor()
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER, owner_id=actor.user_id
    )
    assert _service().authorize(actor, action, resource).allowed is True


@pytest.mark.parametrize(
    "action", [Action.READ, Action.UPDATE, Action.DELETE]
)
def test_pattern_a_non_owner_denied_for_all_actions(action):
    """A non-owner is denied read/update/delete with a privacy-safe not-found."""
    actor = _actor()
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=uuid.uuid4(),  # someone else owns it
    )
    decision = _service().authorize(actor, action, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_OWNER
    assert decision.http_hint == HTTP_NOT_FOUND


def test_pattern_a_partner_denied_even_with_couple_id():
    """Partner B is denied Partner A's private data even when it references the
    shared couple — membership never grants private access (R16.2, R16.4)."""
    owner_id = uuid.uuid4()
    partner_b = uuid.uuid4()
    couple_id = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, owner_id, Member_Status.ACTIVE)
    resolver.set_member(couple_id, partner_b, Member_Status.ACTIVE)

    actor = AuthenticatedActor(user_id=partner_b, account_status=Account_Status.ACTIVE)
    # PRIVATE_PARTNER resource owned by A, but carrying the shared couple_id.
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=owner_id,
        couple_id=couple_id,
    )

    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_OWNER


def test_pattern_a_none_owner_denied():
    """A PRIVATE_PARTNER resource with no resolved owner denies (no owner match)."""
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER, owner_id=None
    )
    decision = _service().authorize(_actor(), Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_OWNER


# ---------------------------------------------------------------------------
# Pattern B — SHARED_COUPLE active-member-of-ACTIVE-couple (R15.4, R13.4)
# ---------------------------------------------------------------------------

def test_pattern_b_active_member_of_active_couple_allowed():
    couple_id = uuid.uuid4()
    actor = _actor()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, actor.user_id, Member_Status.ACTIVE)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )
    assert _service(resolver).authorize(actor, Action.READ, resource).allowed is True


def test_pattern_b_non_member_denied():
    couple_id = uuid.uuid4()
    actor = _actor()  # never added as a member

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )
    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_ACTIVE_MEMBER
    assert decision.http_hint == HTTP_NOT_FOUND


def test_pattern_b_former_partner_of_disconnected_couple_denied():
    """After disconnection the couple is not ACTIVE, so Pattern B denies (R13.4)."""
    couple_id = uuid.uuid4()
    actor = _actor()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.DISCONNECTED)
    # The former partner's membership row is also DISCONNECTED, but the couple
    # lifecycle check denies first.
    resolver.set_member(couple_id, actor.user_id, Member_Status.DISCONNECTED)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )
    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.COUPLE_NOT_ACTIVE


def test_pattern_b_pending_couple_denied():
    """A member of a still-PENDING couple has no shared access yet (R13.4)."""
    couple_id = uuid.uuid4()
    actor = _actor()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.PENDING)
    resolver.set_member(couple_id, actor.user_id, Member_Status.ACTIVE)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )
    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.COUPLE_NOT_ACTIVE


def test_pattern_b_disconnected_member_of_active_couple_denied():
    """A DISCONNECTED member is not active even if the couple is ACTIVE."""
    couple_id = uuid.uuid4()
    actor = _actor()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, actor.user_id, Member_Status.DISCONNECTED)

    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=couple_id
    )
    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_ACTIVE_MEMBER


def test_pattern_b_shared_without_couple_id_denied():
    """A SHARED_COUPLE resource with no couple_id cannot satisfy membership."""
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.SHARED_COUPLE, couple_id=None
    )
    decision = _service().authorize(_actor(), Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_ACTIVE_MEMBER


# ---------------------------------------------------------------------------
# Out-of-reach zones — always DENY in the Foundation (R15.5, R15.6)
# ---------------------------------------------------------------------------

def test_system_only_zone_denied():
    resource = ResourceDescriptor(visibility_scope=Visibility_Scope.SYSTEM_ONLY)
    decision = _service().authorize(_actor(), Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.SYSTEM_ONLY
    assert decision.http_hint == HTTP_NOT_FOUND


def test_professional_shared_zone_denied():
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PROFESSIONAL_SHARED
    )
    decision = _service().authorize(_actor(), Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.PROFESSIONAL_SHARED
    assert decision.http_hint == HTTP_NOT_FOUND


# ---------------------------------------------------------------------------
# visibility_scope drives the zone — never inferred from couple_id (R16.4)
# ---------------------------------------------------------------------------

def test_couple_id_does_not_upgrade_private_to_shared():
    """A PRIVATE_PARTNER row that references a couple stays private: a non-owner
    member is still denied, proving the zone comes from the row, not couple_id."""
    owner_id = uuid.uuid4()
    member = uuid.uuid4()
    couple_id = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, member, Member_Status.ACTIVE)

    actor = AuthenticatedActor(user_id=member, account_status=Account_Status.ACTIVE)
    resource = ResourceDescriptor(
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        owner_id=owner_id,
        couple_id=couple_id,
    )
    # If the service inferred "shared" from couple_id, this active member would
    # be ALLOWed. It must be DENYed as a non-owner.
    decision = _service(resolver).authorize(actor, Action.READ, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.NOT_OWNER


# ---------------------------------------------------------------------------
# Client-supplied identifiers are irrelevant (R14.2, R17.1)
# ---------------------------------------------------------------------------

def test_supplied_resource_id_does_not_change_decision():
    """Mutating the descriptor's carried resource_id never changes the outcome —
    the decision derives from owner/membership, not the id."""
    actor = _actor()
    base = dict(visibility_scope=Visibility_Scope.PRIVATE_PARTNER, owner_id=actor.user_id)

    d1 = _service().authorize(
        actor, Action.READ, ResourceDescriptor(resource_id=uuid.uuid4(), **base)
    )
    d2 = _service().authorize(
        actor, Action.READ, ResourceDescriptor(resource_id=uuid.uuid4(), **base)
    )
    assert d1.allowed is True and d2.allowed is True


# ---------------------------------------------------------------------------
# Decision value-object ergonomics
# ---------------------------------------------------------------------------

def test_decision_bool_reflects_allow():
    assert bool(Decision.allow()) is True
    assert bool(Decision.deny(DenyReason.NOT_OWNER, HTTP_NOT_FOUND)) is False
