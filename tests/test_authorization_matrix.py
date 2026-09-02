"""Positive / negative authorization test matrix (task 13.1).

This is the *example-based* companion to the authorization property tests: a
one-to-one transcription of the matrix in design.md ("Authorization test matrix
(positive / negative)"), which itself mirrors
[06-authorization-matrix.md §19]. Where the property tests prove the invariants
hold across *all* inputs, this matrix pins the *specific* rows a reviewer reads
straight off the design doc, so a regression in any one row fails loudly and
points at the exact scenario.

The matrix has four blocks, tested at the layer each scenario actually lives in:

* **Partner privacy** and **Zones** and the private-data **Lifecycle / IDOR**
  rows are decided by :class:`AuthorizationService` over ``PrivateReflection``
  rows. ``PrivateReflection`` has no HTTP route in the Foundation (authoring is
  Phase 2), so these are exercised through the real
  :class:`AuthorizedRepository` wired to the
  :class:`SqlAlchemyRelationshipResolver` against the ``pg_schema`` fixture —
  the same defense-in-depth path production reads travel.
* **Couple data** (non-member reads a couple by id -> privacy-safe 404) and the
  **DELETED-account** row are exercised end to end through the wired FastAPI
  app, reusing the ``harness`` fixture from ``tests/test_api_endpoints.py`` so
  the assertion is the real HTTP status a client would see.

Design references: the matrix block in design.md; requirements
R6.1, R6.3, R6.4, R13.4, R13.5, R15.5, R15.6, R16.1-R16.4, R17.1-R17.4.
"""

from __future__ import annotations

import uuid

import pytest

from app.authorization.models import Action, AuthenticatedActor
from app.authorization.repository import AuthorizedRepository
from app.authorization.resolver import SqlAlchemyRelationshipResolver
from app.authorization.service import AuthorizationService
from app.couples.models import Couple, CoupleMember, PrivateReflection
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Role,
    Member_Status,
    Visibility_Scope,
)

# Reuse the wired-app harness (real ephemeral schema + in-memory Redis/state)
# and its helpers, so the HTTP-layer rows of the matrix assert real responses.
from tests.test_api_endpoints import (  # noqa: F401  (harness is a fixture)
    _bearer,
    _login,
    _make_active_couple,
    _new_identifier,
    _register,
    harness,
)


# ===========================================================================
# Authorization-decision layer harness (PrivateReflection has no HTTP route)
# ===========================================================================


def _create_tables(session) -> None:
    """Create the ORM tables these decision-layer rows touch."""
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            Couple.__table__,
            CoupleMember.__table__,
            PrivateReflection.__table__,
        ],
    )


class _Stack:
    """The real authorization stack over one ephemeral-schema session.

    Bundles the ``AuthorizationService`` (the decision function) with the
    ``AuthorizedRepository`` (the scoped-read path), both wired to the real
    ``SqlAlchemyRelationshipResolver``, so a test can assert the decision *and*
    the observable read a caller would get.
    """

    def __init__(self, session) -> None:
        resolver = SqlAlchemyRelationshipResolver(session)
        self.authz = AuthorizationService(resolver)
        self.repo = AuthorizedRepository(session, self.authz)

    def describe(self, row: PrivateReflection):
        return self.repo.describe_reflection(row)

    def get_private_reflection(self, actor, reflection_id, action: Action = Action.READ):
        """Passthrough to the scoped read, so tests assert the observable result."""
        return self.repo.get_private_reflection(actor, reflection_id, action)


def _repo(session) -> _Stack:
    """The real authorization stack wired to the SQLAlchemy resolver."""
    return _Stack(session)


def _actor(
    user_id: uuid.UUID,
    status: Account_Status = Account_Status.ACTIVE,
) -> AuthenticatedActor:
    return AuthenticatedActor(user_id=user_id, account_status=status)


def _add_reflection(
    session,
    owner_id: uuid.UUID,
    *,
    couple_id: uuid.UUID | None = None,
    scope: Visibility_Scope = Visibility_Scope.PRIVATE_PARTNER,
) -> PrivateReflection:
    row = PrivateReflection(
        user_id=owner_id, couple_id=couple_id, visibility_scope=scope
    )
    session.add(row)
    session.flush()
    return row


def _add_active_couple(session) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Create an ACTIVE couple with two ACTIVE members. Returns (couple_id, a, b)."""
    partner_a = uuid.uuid4()
    partner_b = uuid.uuid4()
    couple = Couple(status=Couple_Status.ACTIVE)
    session.add(couple)
    session.flush()
    session.add_all(
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
    session.flush()
    return couple.id, partner_a, partner_b


def _allows(stack: "_Stack", actor, row, action: Action) -> bool:
    """Return True iff the authorization decision for (actor, action, row) ALLOWs.

    Uses the same descriptor the scoped reads build, so read/update/delete all
    flow through the identical decision the repository would apply.
    """
    descriptor = stack.describe(row)
    return stack.authz.authorize(actor, action, descriptor).allowed


_WRITE_ACTIONS = [Action.READ, Action.UPDATE, Action.DELETE]


# ===========================================================================
# Block 1 — Partner privacy
# ===========================================================================


@pytest.mark.parametrize("action", _WRITE_ACTIONS)
def test_owner_reads_updates_deletes_own_private_reflection(pg_schema, action):
    """✓ Partner A reads / updates / deletes own PrivateReflection (R6.1, R16.1)."""
    _create_tables(pg_schema)
    owner_id = uuid.uuid4()
    row = _add_reflection(pg_schema, owner_id)
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(owner_id), row, action) is True
    # The scoped read path agrees for READ.
    if action is Action.READ:
        assert repo.get_private_reflection(_actor(owner_id), row.id) is not None


@pytest.mark.parametrize("action", _WRITE_ACTIONS)
def test_partner_b_denied_partner_a_private_reflection(pg_schema, action):
    """✗ Partner B reads / updates / deletes Partner A's PrivateReflection.

    Even as an ACTIVE member of the same ACTIVE couple, B fails the Pattern A
    owner check for every action (R6.3, R6.4, R16.2, R16.3).
    """
    _create_tables(pg_schema)
    couple_id, partner_a, partner_b = _add_active_couple(pg_schema)
    a_private = _add_reflection(pg_schema, partner_a, couple_id=couple_id)
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(partner_b), a_private, action) is False
    if action is Action.READ:
        assert repo.get_private_reflection(_actor(partner_b), a_private.id) is None


def test_partner_b_enumerating_partner_a_reflections_each_id_is_not_found(pg_schema):
    """✗ Partner B enumerates Partner A reflections (each id -> privacy-safe None).

    A missing id and a real-but-forbidden id are indistinguishable to B — both
    yield ``None`` from the scoped read, which the API maps to an identical 404
    (R17.2, R17.3).
    """
    _create_tables(pg_schema)
    couple_id, partner_a, partner_b = _add_active_couple(pg_schema)
    a_reflections = [
        _add_reflection(pg_schema, partner_a, couple_id=couple_id) for _ in range(3)
    ]
    repo = _repo(pg_schema)

    # Every real id owned by A is invisible to B.
    for row in a_reflections:
        assert repo.get_private_reflection(_actor(partner_b), row.id) is None
    # A random (non-existent) id is likewise None — same observable outcome.
    assert repo.get_private_reflection(_actor(partner_b), uuid.uuid4()) is None


@pytest.mark.parametrize("action", _WRITE_ACTIONS)
def test_partner_b_denied_reflection_that_references_shared_couple_id(pg_schema, action):
    """✗ Partner B reads Partner A reflection that references the shared couple_id.

    A ``couple_id`` on a PRIVATE_PARTNER row is context only; it never promotes
    the row to SHARED_COUPLE, so B is still denied (R16.4).
    """
    _create_tables(pg_schema)
    couple_id, partner_a, partner_b = _add_active_couple(pg_schema)
    # The reflection explicitly carries the shared couple_id.
    a_private = _add_reflection(pg_schema, partner_a, couple_id=couple_id)
    assert a_private.couple_id == couple_id
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(partner_b), a_private, action) is False


# ===========================================================================
# Block 2 — Couple data
# ===========================================================================


def test_both_members_read_shared_couple_resource_of_active_couple(pg_schema):
    """✓ Partner A and Partner B read a SHARED_COUPLE resource of their ACTIVE couple.

    Pattern B allows an active member of an ACTIVE couple (R15.4, R13.4).
    """
    _create_tables(pg_schema)
    couple_id, partner_a, partner_b = _add_active_couple(pg_schema)
    shared = _add_reflection(
        pg_schema,
        owner_id=uuid.uuid4(),  # owner irrelevant for SHARED_COUPLE
        couple_id=couple_id,
        scope=Visibility_Scope.SHARED_COUPLE,
    )
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(partner_a), shared, Action.READ) is True
    assert _allows(repo, _actor(partner_b), shared, Action.READ) is True


def test_non_member_reading_shared_resource_by_id_is_denied(pg_schema):
    """✗ Non-member reads a SHARED_COUPLE resource by id (decision layer)."""
    _create_tables(pg_schema)
    couple_id, _partner_a, _partner_b = _add_active_couple(pg_schema)
    shared = _add_reflection(
        pg_schema,
        owner_id=uuid.uuid4(),
        couple_id=couple_id,
        scope=Visibility_Scope.SHARED_COUPLE,
    )
    repo = _repo(pg_schema)
    stranger = _actor(uuid.uuid4())

    assert _allows(repo, stranger, shared, Action.READ) is False


def test_non_member_reads_couple_by_id_is_privacy_safe_404(harness):
    """✗ Non-member reads couple by id -> 404 (privacy-safe), end to end.

    A stranger's read of a real couple id is indistinguishable from a read of a
    non-existent couple id: same 404, same RESOURCE_NOT_FOUND code (R17.3, R17.4).
    """
    owner = _new_identifier()
    _register(harness.client, owner)
    owner_token = _login(harness.client, owner)
    couple_id = harness.client.post(
        "/couples", headers=_bearer(owner_token)
    ).json()["data"]["id"]

    stranger = _new_identifier()
    _register(harness.client, stranger)
    stranger_token = _login(harness.client, stranger)

    forbidden = harness.client.get(
        f"/couples/{couple_id}", headers=_bearer(stranger_token)
    )
    missing = harness.client.get(
        f"/couples/{uuid.uuid4()}", headers=_bearer(stranger_token)
    )
    assert forbidden.status_code == missing.status_code == 404
    assert (
        forbidden.json()["error"]["code"]
        == missing.json()["error"]["code"]
        == "RESOURCE_NOT_FOUND"
    )


# ===========================================================================
# Block 3 — Zones
# ===========================================================================


def test_normal_user_reads_system_only_resource_is_denied(pg_schema):
    """✗ Normal user reads a SYSTEM_ONLY resource (R15.5)."""
    _create_tables(pg_schema)
    user_id = uuid.uuid4()
    # A SYSTEM_ONLY row — owned by the actor, to prove ownership never rescues it.
    row = _add_reflection(
        pg_schema, owner_id=user_id, scope=Visibility_Scope.SYSTEM_ONLY
    )
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(user_id), row, Action.READ) is False


def test_any_user_reads_professional_shared_resource_is_denied(pg_schema):
    """✗ Any user reads a PROFESSIONAL_SHARED resource — Foundation denies (R15.6).

    Denied for the owner, an active couple member, and a stranger alike.
    """
    _create_tables(pg_schema)
    couple_id, partner_a, partner_b = _add_active_couple(pg_schema)
    owner_id = uuid.uuid4()
    row = _add_reflection(
        pg_schema,
        owner_id=owner_id,
        couple_id=couple_id,
        scope=Visibility_Scope.PROFESSIONAL_SHARED,
    )
    repo = _repo(pg_schema)

    for who in (owner_id, partner_a, partner_b, uuid.uuid4()):
        assert _allows(repo, _actor(who), row, Action.READ) is False


# ===========================================================================
# Block 4 — Lifecycle / IDOR
# ===========================================================================


def test_invitee_accesses_couple_data_before_accepting_is_denied(pg_schema):
    """✗ Invitee accesses couple data before accepting the invitation.

    Before acceptance the couple is PENDING and the invitee has no membership
    row: Pattern B denies on both lifecycle and membership (R13.4).
    """
    _create_tables(pg_schema)
    # PENDING couple with only PARTNER_A present (invitee not yet a member).
    inviter = uuid.uuid4()
    couple = Couple(status=Couple_Status.PENDING)
    pg_schema.add(couple)
    pg_schema.flush()
    pg_schema.add(
        CoupleMember(
            couple_id=couple.id,
            user_id=inviter,
            role=Member_Role.PARTNER_A,
            status=Member_Status.ACTIVE,
        )
    )
    pg_schema.flush()
    shared = _add_reflection(
        pg_schema,
        owner_id=uuid.uuid4(),
        couple_id=couple.id,
        scope=Visibility_Scope.SHARED_COUPLE,
    )
    repo = _repo(pg_schema)
    invitee = _actor(uuid.uuid4())

    assert _allows(repo, invitee, shared, Action.READ) is False


def test_former_partner_denied_shared_data_after_disconnection(pg_schema):
    """✗ Former partner accesses shared data after disconnection.

    A DISCONNECTED couple fails the lifecycle gate, so a former member is denied
    the couple's SHARED_COUPLE resource (R13.4).
    """
    _create_tables(pg_schema)
    partner_a = uuid.uuid4()
    partner_b = uuid.uuid4()
    couple = Couple(status=Couple_Status.DISCONNECTED)
    pg_schema.add(couple)
    pg_schema.flush()
    pg_schema.add_all(
        [
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_a,
                role=Member_Role.PARTNER_A,
                status=Member_Status.DISCONNECTED,
            ),
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_b,
                role=Member_Role.PARTNER_B,
                status=Member_Status.DISCONNECTED,
            ),
        ]
    )
    shared = _add_reflection(
        pg_schema,
        owner_id=uuid.uuid4(),
        couple_id=couple.id,
        scope=Visibility_Scope.SHARED_COUPLE,
    )
    pg_schema.flush()
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(partner_a), shared, Action.READ) is False
    assert _allows(repo, _actor(partner_b), shared, Action.READ) is False


@pytest.mark.parametrize("action", _WRITE_ACTIONS)
def test_former_partner_denied_other_former_partners_private_data(pg_schema, action):
    """✗ Former partner accesses the other former partner's private data.

    Previous membership in a now-DISCONNECTED couple grants no path to the
    other partner's PRIVATE_PARTNER data — ownership is the only gate (R13.5).
    """
    _create_tables(pg_schema)
    partner_a = uuid.uuid4()
    partner_b = uuid.uuid4()
    couple = Couple(status=Couple_Status.DISCONNECTED)
    pg_schema.add(couple)
    pg_schema.flush()
    pg_schema.add_all(
        [
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_a,
                role=Member_Role.PARTNER_A,
                status=Member_Status.DISCONNECTED,
            ),
            CoupleMember(
                couple_id=couple.id,
                user_id=partner_b,
                role=Member_Role.PARTNER_B,
                status=Member_Status.DISCONNECTED,
            ),
        ]
    )
    a_private = _add_reflection(pg_schema, partner_a, couple_id=couple.id)
    repo = _repo(pg_schema)

    assert _allows(repo, _actor(partner_b), a_private, action) is False


def test_deleted_account_session_accesses_any_resource_is_denied(pg_schema):
    """✗ DELETED-account session accesses any resource (decision layer, R7.3).

    Pipeline step 1 denies a non-ACTIVE actor before any resource is resolved,
    so even the actor's own private reflection is denied.
    """
    _create_tables(pg_schema)
    owner_id = uuid.uuid4()
    own = _add_reflection(pg_schema, owner_id)
    repo = _repo(pg_schema)

    deleted_actor = _actor(owner_id, status=Account_Status.DELETED)
    assert _allows(repo, deleted_actor, own, Action.READ) is False
    # And through the scoped read, the DELETED owner sees nothing.
    assert repo.get_private_reflection(deleted_actor, own.id) is None


def test_deleted_account_session_is_rejected_end_to_end(harness):
    """✗ DELETED-account session accesses any resource — end to end (R3.6, R7.3).

    After the user's account is transitioned to DELETED server-side, the still
    "live" session token no longer authenticates.
    """
    from app.users.models import User

    identifier = _new_identifier()
    user_id = _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    # The token works while ACTIVE.
    assert harness.client.get(
        "/account/profile", headers=_bearer(token)
    ).status_code == 200

    # Transition the account to DELETED via server state (lifecycle is
    # server-controlled; we simulate the outcome the deletion pipeline reaches).
    user = harness.session.query(User).filter(User.id == uuid.UUID(user_id)).one()
    user.status = Account_Status.DELETED
    harness.session.flush()

    after = harness.client.get("/account/profile", headers=_bearer(token))
    assert after.status_code == 401


@pytest.mark.parametrize("action", _WRITE_ACTIONS)
def test_changing_reflection_id_never_widens_access(pg_schema, action):
    """✗ Changing reflection_id never widens access (R17.1).

    The decision is computed from whatever row the id resolves to, so swapping
    to another user's reflection id yields that row's owner check — never the
    requester's own. An owner reading their own id is allowed; the same actor
    presenting the other user's id is denied.
    """
    _create_tables(pg_schema)
    owner_id = uuid.uuid4()
    mine = _add_reflection(pg_schema, owner_id)
    theirs = _add_reflection(pg_schema, uuid.uuid4())
    repo = _repo(pg_schema)
    actor = _actor(owner_id)

    assert _allows(repo, actor, mine, action) is True
    assert _allows(repo, actor, theirs, action) is False
    if action is Action.READ:
        assert repo.get_private_reflection(actor, mine.id) is not None
        assert repo.get_private_reflection(actor, theirs.id) is None


def test_changing_couple_id_does_not_grant_shared_access(pg_schema):
    """✗ Changing couple_id never widens access (R17.1).

    A SHARED_COUPLE row's membership is resolved from the row's own couple_id
    against server state. An actor who is a member of couple X gains nothing by
    the resource pointing at couple Y where they are not a member.
    """
    _create_tables(pg_schema)
    couple_x, member_x, _b = _add_active_couple(pg_schema)
    couple_y, _cx, _cy = _add_active_couple(pg_schema)

    # A shared resource that belongs to couple Y (not X).
    shared_y = _add_reflection(
        pg_schema,
        owner_id=uuid.uuid4(),
        couple_id=couple_y,
        scope=Visibility_Scope.SHARED_COUPLE,
    )
    repo = _repo(pg_schema)

    # member_x is active in X, not in Y -> denied on the Y-anchored resource.
    assert _allows(repo, _actor(member_x), shared_y, Action.READ) is False


def test_changing_user_id_claim_cannot_impersonate_owner(pg_schema):
    """✗ Changing user_id never widens access (R14.2, R17.1).

    The actor identity comes from the server-resolved session, not from any
    client-supplied user_id. A non-owner actor is denied the owner's private
    reflection regardless of any id they might present.
    """
    _create_tables(pg_schema)
    owner_id = uuid.uuid4()
    owned = _add_reflection(pg_schema, owner_id)
    repo = _repo(pg_schema)

    attacker = _actor(uuid.uuid4())
    assert _allows(repo, attacker, owned, Action.READ) is False
    assert repo.get_private_reflection(attacker, owned.id) is None
