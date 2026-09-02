"""Tests for the authorized repository scoping + nested filtering (task 4.2).

Two layers are exercised:

* **Descriptor construction + nested filtering** — pure, in-memory, driven by a
  :class:`FakeResolver`. These prove that:
    - descriptors are built *from the row* (visibility_scope/owner/couple), never
      hand-built from client input (R16.4, R17.1);
    - :meth:`AuthorizedRepository.filter_nested` evaluates each child against its
      OWN zone, so a couple member never receives the other partner's private
      reflection merely because it references the shared couple (R14.4).

* **SQLAlchemy-backed scoping (defense in depth)** — using the ``pg_schema``
  fixture, real ``PrivateReflection`` / ``Couple`` / ``CoupleMember`` rows are
  written and read back through :class:`AuthorizedRepository`, wired to the
  :class:`SqlAlchemyRelationshipResolver`. These prove that a scoped read returns
  a row only for the authorized actor and ``None`` otherwise, and that mutating
  the requested id cannot widen results (R14.2, R17.1, R17.2).
"""

from __future__ import annotations

import uuid

import pytest

from app.authorization.models import Action, AuthenticatedActor, ResourceDescriptor
from app.authorization.repository import (
    AuthorizedRepository,
    descriptor_for_reflection,
)
from app.authorization.service import AuthorizationService
from app.couples.models import PrivateReflection
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Role,
    Member_Status,
    Visibility_Scope,
)


# ---------------------------------------------------------------------------
# In-memory relationship resolver (mirrors tests/test_authorization_service.py)
# ---------------------------------------------------------------------------

class FakeResolver:
    """In-memory server-state resolver for Pattern B."""

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


def _actor(
    user_id: uuid.UUID | None = None,
    status: Account_Status = Account_Status.ACTIVE,
) -> AuthenticatedActor:
    return AuthenticatedActor(
        user_id=user_id or uuid.uuid4(), account_status=status
    )


def _reflection(
    owner_id: uuid.UUID,
    *,
    couple_id: uuid.UUID | None = None,
    scope: Visibility_Scope = Visibility_Scope.PRIVATE_PARTNER,
    reflection_id: uuid.UUID | None = None,
) -> PrivateReflection:
    """A detached PrivateReflection row (no session) for pure filtering tests."""
    row = PrivateReflection(
        user_id=owner_id,
        couple_id=couple_id,
        visibility_scope=scope,
    )
    row.id = reflection_id or uuid.uuid4()
    return row


def _repo(resolver: FakeResolver) -> AuthorizedRepository:
    # session is unused by the pure filtering / descriptor paths.
    return AuthorizedRepository(session=None, authorization=AuthorizationService(resolver))


# ---------------------------------------------------------------------------
# Descriptor construction — read from the row, never client input (R16.4, R17.1)
# ---------------------------------------------------------------------------

def test_descriptor_reads_scope_owner_and_couple_from_row():
    owner_id = uuid.uuid4()
    couple_id = uuid.uuid4()
    reflection_id = uuid.uuid4()
    row = _reflection(owner_id, couple_id=couple_id, reflection_id=reflection_id)

    descriptor = descriptor_for_reflection(row)

    assert descriptor.visibility_scope == Visibility_Scope.PRIVATE_PARTNER
    assert descriptor.owner_id == owner_id
    assert descriptor.couple_id == couple_id
    assert descriptor.resource_id == reflection_id
    assert descriptor.resource_type == "PrivateReflection"


# ---------------------------------------------------------------------------
# filter_nested — each child evaluated against ITS OWN zone (R14.4)
# ---------------------------------------------------------------------------

def test_filter_nested_keeps_only_children_the_actor_may_read():
    owner = _actor()
    other_owner = uuid.uuid4()

    mine = _reflection(owner.user_id)
    theirs = _reflection(other_owner)

    repo = _repo(FakeResolver())
    kept = repo.filter_nested(
        owner, [mine, theirs], descriptor_for_reflection
    )

    assert kept == [mine]


def test_filter_nested_partner_does_not_receive_others_private_via_shared_couple():
    """The key R14.4 case: two reflections hanging off the SAME shared couple,
    one owned by each partner. Partner B must receive only their own, never
    Partner A's, even though both carry the shared couple_id."""
    couple_id = uuid.uuid4()
    partner_a = uuid.uuid4()
    partner_b = uuid.uuid4()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, partner_a, Member_Status.ACTIVE)
    resolver.set_member(couple_id, partner_b, Member_Status.ACTIVE)

    a_private = _reflection(partner_a, couple_id=couple_id)
    b_private = _reflection(partner_b, couple_id=couple_id)

    actor_b = _actor(partner_b)
    kept = _repo(resolver).filter_nested(
        actor_b, [a_private, b_private], descriptor_for_reflection
    )

    assert kept == [b_private]


def test_filter_nested_evaluates_mixed_zones_independently():
    """A container with a private (owned by other) child and a shared child in an
    ACTIVE couple the actor belongs to: only the shared child is returned."""
    couple_id = uuid.uuid4()
    actor = _actor()

    resolver = FakeResolver()
    resolver.set_couple(couple_id, Couple_Status.ACTIVE)
    resolver.set_member(couple_id, actor.user_id, Member_Status.ACTIVE)

    others_private = _reflection(uuid.uuid4(), couple_id=couple_id)
    shared = _reflection(
        uuid.uuid4(), couple_id=couple_id, scope=Visibility_Scope.SHARED_COUPLE
    )

    kept = _repo(resolver).filter_nested(
        actor, [others_private, shared], descriptor_for_reflection
    )

    assert kept == [shared]


def test_filter_nested_preserves_order_and_drops_denied_silently():
    owner = _actor()
    c1 = _reflection(owner.user_id)
    c2 = _reflection(uuid.uuid4())  # denied
    c3 = _reflection(owner.user_id)

    kept = _repo(FakeResolver()).filter_nested(
        owner, [c1, c2, c3], descriptor_for_reflection
    )

    assert kept == [c1, c3]


def test_filter_nested_empty_container_returns_empty():
    assert _repo(FakeResolver()).filter_nested(
        _actor(), [], descriptor_for_reflection
    ) == []


def test_filter_nested_denies_all_for_non_active_account():
    """Step 1 of the pipeline denies a SUSPENDED account before any zone rule,
    so even the owner's own children are filtered out."""
    owner_id = uuid.uuid4()
    actor = _actor(owner_id, status=Account_Status.SUSPENDED)
    mine = _reflection(owner_id)

    kept = _repo(FakeResolver()).filter_nested(
        actor, [mine], descriptor_for_reflection
    )
    assert kept == []


def test_list_authorized_private_reflections_delegates_to_filter():
    owner = _actor()
    mine = _reflection(owner.user_id)
    theirs = _reflection(uuid.uuid4())

    kept = _repo(FakeResolver()).list_authorized_private_reflections(
        owner, [mine, theirs]
    )
    assert kept == [mine]


# ---------------------------------------------------------------------------
# SQLAlchemy-backed scoping (defense in depth) — pg_schema fixture (R14.2)
# ---------------------------------------------------------------------------

def _create_tables(session):
    """Create the ORM tables used by these tests in the ephemeral schema."""
    from app.couples.models import Couple, CoupleMember, PrivateReflection
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            Couple.__table__,
            CoupleMember.__table__,
            PrivateReflection.__table__,
        ],
    )


def _sql_repo(session):
    from app.authorization.resolver import SqlAlchemyRelationshipResolver

    resolver = SqlAlchemyRelationshipResolver(session)
    return AuthorizedRepository(session, AuthorizationService(resolver))


def test_scoped_read_returns_row_for_owner(pg_schema):
    _create_tables(pg_schema)
    owner_id = uuid.uuid4()

    reflection = PrivateReflection(
        user_id=owner_id, visibility_scope=Visibility_Scope.PRIVATE_PARTNER
    )
    pg_schema.add(reflection)
    pg_schema.flush()

    repo = _sql_repo(pg_schema)
    actor = _actor(owner_id)

    got = repo.get_private_reflection(actor, reflection.id)
    assert got is not None
    assert got.id == reflection.id


def test_scoped_read_returns_none_for_non_owner(pg_schema):
    """Defense in depth: even reading by exact id, a non-owner gets nothing —
    indistinguishable from not-found (R17.2)."""
    _create_tables(pg_schema)

    reflection = PrivateReflection(
        user_id=uuid.uuid4(), visibility_scope=Visibility_Scope.PRIVATE_PARTNER
    )
    pg_schema.add(reflection)
    pg_schema.flush()

    repo = _sql_repo(pg_schema)
    stranger = _actor()  # different user

    assert repo.get_private_reflection(stranger, reflection.id) is None


def test_scoped_read_missing_row_returns_none(pg_schema):
    _create_tables(pg_schema)
    repo = _sql_repo(pg_schema)
    assert repo.get_private_reflection(_actor(), uuid.uuid4()) is None


def test_scoped_read_partner_denied_others_private_even_with_couple(pg_schema):
    """Partner B, an active member of an ACTIVE couple, still cannot read Partner
    A's PRIVATE_PARTNER reflection that references that couple (R16.4)."""
    from app.couples.models import Couple, CoupleMember

    _create_tables(pg_schema)

    partner_a = uuid.uuid4()
    partner_b = uuid.uuid4()

    couple = Couple(status=Couple_Status.ACTIVE)
    pg_schema.add(couple)
    pg_schema.flush()

    pg_schema.add_all(
        [
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_a,
                role=Member_Role.PARTNER_A,
                status=Member_Status.ACTIVE,
            ),
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_b,
                role=Member_Role.PARTNER_B,
                status=Member_Status.ACTIVE,
            ),
        ]
    )
    a_private = PrivateReflection(
        user_id=partner_a,
        couple_id=couple.id,
        visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
    )
    pg_schema.add(a_private)
    pg_schema.flush()

    repo = _sql_repo(pg_schema)
    assert repo.get_private_reflection(_actor(partner_b), a_private.id) is None
    # ...but Partner A can read their own.
    assert repo.get_private_reflection(_actor(partner_a), a_private.id) is not None


def test_scoped_read_mutating_requested_id_cannot_widen(pg_schema):
    """Requesting a different id resolves a different (or no) row; the decision is
    computed from that row's owner, so a swapped id never widens access (R17.1)."""
    _create_tables(pg_schema)

    owner_id = uuid.uuid4()
    mine = PrivateReflection(
        user_id=owner_id, visibility_scope=Visibility_Scope.PRIVATE_PARTNER
    )
    theirs = PrivateReflection(
        user_id=uuid.uuid4(), visibility_scope=Visibility_Scope.PRIVATE_PARTNER
    )
    pg_schema.add_all([mine, theirs])
    pg_schema.flush()

    repo = _sql_repo(pg_schema)
    actor = _actor(owner_id)

    assert repo.get_private_reflection(actor, mine.id) is not None
    # Swapping to the other user's reflection id yields nothing.
    assert repo.get_private_reflection(actor, theirs.id) is None


def test_resolver_reports_membership_and_lifecycle_from_state(pg_schema):
    from app.authorization.resolver import SqlAlchemyRelationshipResolver
    from app.couples.models import Couple, CoupleMember

    _create_tables(pg_schema)

    user_id = uuid.uuid4()
    couple = Couple(status=Couple_Status.ACTIVE)
    pg_schema.add(couple)
    pg_schema.flush()
    pg_schema.add(
        CoupleMember(
            couple_id=couple.id,
            user_id=user_id,
            role=Member_Role.PARTNER_A,
            status=Member_Status.ACTIVE,
        )
    )
    pg_schema.flush()

    resolver = SqlAlchemyRelationshipResolver(pg_schema)

    assert resolver.get_couple_status(couple.id) == Couple_Status.ACTIVE
    assert resolver.get_couple_status(uuid.uuid4()) is None
    assert resolver.get_member_status(couple.id, user_id) == Member_Status.ACTIVE
    assert resolver.get_member_status(couple.id, uuid.uuid4()) is None
