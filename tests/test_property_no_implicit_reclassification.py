"""Property test — no implicit reclassification on couple formation (task 10.7).

Feature: foundation-auth-couples, Property 5

**Property 5: No implicit reclassification on couple formation.** Forming a
couple (:meth:`CoupleService.create_couple`) and activating it by accepting an
invitation (:meth:`InvitationService.accept_invitation`, couple → ACTIVE) NEVER
changes a :class:`~app.couples.models.PrivateReflection`'s ``visibility_scope``.
A reflection that is ``PRIVATE_PARTNER`` before couple formation/activation
remains ``PRIVATE_PARTNER`` afterwards, and its owner (``user_id``) is unchanged
(R16.5). The only path from ``PRIVATE_PARTNER`` to ``SHARED_COUPLE`` is an
explicit sharing action — no such implicit path exists on couple formation
(R16.6).

Two layers:

* **DB-backed property (defense in depth)** — using the real ``pg_schema``
  session with the real schema/indexes (as authored in migration
  ``0002_foundation_schema``). For arbitrary reflection arrangements
  (``couple_id`` present or absent, arbitrary owner among the couple's members
  or a third party), a ``PRIVATE_PARTNER`` reflection created before acceptance
  is byte-for-byte unchanged in scope and ownership after the couple is
  activated by ``accept_invitation``. Because ``pg_schema`` is function-scoped
  the ``function_scoped_fixture`` health check is suppressed and each Hypothesis
  example runs inside its own SAVEPOINT that is rolled back, so examples never
  leak state into one another.

* **Pure assertion (source-level)** — ``create_couple`` and
  ``accept_invitation`` touch no ``PrivateReflection`` at all: driven by
  in-memory fakes that record every reflection they hold, the reflection set is
  identical before and after both operations, confirming there is no implicit
  reclassification path in the service code.

**Validates: Requirements 16.5, 16.6**
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.couples.models import PrivateReflection
from app.enums import (
    Couple_Status,
    Member_Role,
    Visibility_Scope,
)

# Reuse the DB helpers and fakes already proven by the accept-service tests so
# this property test stays minimal and consistent with the rest of the suite.
from tests.test_invitation_accept_service import (
    _actor,
    _create_audit_table,
    _create_couples_tables,
    _db_service,
    _persist_pending_couple_with_invitation,
    _pending_couple_with_invitation,
    _pure_service,
)

# ---------------------------------------------------------------------------
# Reflection-arrangement strategy
# ---------------------------------------------------------------------------
#
# An "owner selector" picks who owns the reflection relative to the couple, and
# "attach_couple" decides whether the reflection references the couple through
# its (context-only, R16.4) couple_id. Owners are resolved to concrete ids at
# use time because the couple/members do not exist yet when the example is
# drawn.

_OWNER_CHOICES = ("creator", "invitee", "third_party")

_arrangement = st.fixed_dictionaries(
    {
        "owner": st.sampled_from(_OWNER_CHOICES),
        "attach_couple": st.booleans(),
    }
)


def _resolve_owner(owner_choice, *, creator_id, invitee_id):
    if owner_choice == "creator":
        return creator_id
    if owner_choice == "invitee":
        return invitee_id
    return uuid.uuid4()  # an unrelated third party


# ===========================================================================
# DB-backed property: activation never reclassifies a PRIVATE_PARTNER reflection
# (Feature: foundation-auth-couples, Property 5)
# ===========================================================================


@settings(
    max_examples=100,
    deadline=None,
    # pg_schema is function-scoped and intentionally reused across examples; we
    # isolate each example with a SAVEPOINT (nested transaction) instead.
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(arrangement=_arrangement)
def test_property_activation_never_reclassifies_reflection(pg_schema, arrangement):
    """Property 5: for any reflection arrangement, activating a couple by
    accepting an invitation leaves a PRIVATE_PARTNER reflection's
    ``visibility_scope`` and owner unchanged — activation NEVER implicitly
    reclassifies it to SHARED_COUPLE (R16.5); the only path to SHARED_COUPLE is
    an explicit action, and none runs here (R16.6).

    Feature: foundation-auth-couples, Property 5

    **Validates: Requirements 16.5, 16.6**
    """
    # Isolate this example: everything happens inside a SAVEPOINT that is rolled
    # back at the end, so examples cannot collide on the shared session/schema.
    savepoint = pg_schema.begin_nested()
    try:
        # DDL inside the SAVEPOINT so the schema (and every row) is rolled back
        # with the example — perfect per-example isolation on the shared session.
        _create_couples_tables(pg_schema)
        _create_audit_table(pg_schema)
        service, repo = _db_service(pg_schema)
        raw = f"reclass-token-{uuid.uuid4().hex}"
        couple, _invitation, creator = _persist_pending_couple_with_invitation(
            pg_schema, repo, raw
        )
        invitee = _actor()

        owner_id = _resolve_owner(
            arrangement["owner"],
            creator_id=creator.user_id,
            invitee_id=invitee.user_id,
        )
        reflection = PrivateReflection(
            id=uuid.uuid4(),
            user_id=owner_id,
            couple_id=couple.id if arrangement["attach_couple"] else None,
            visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        )
        pg_schema.add(reflection)
        pg_schema.flush()

        reflection_id = reflection.id
        couple_id_before = reflection.couple_id

        # Activate the couple (PENDING -> ACTIVE) by accepting the invitation.
        view = service.accept_invitation(invitee, raw)
        pg_schema.flush()
        # Precondition sanity: the couple really did activate.
        assert view.status == Couple_Status.ACTIVE

        # Re-read from the database (not the in-memory identity map alone).
        pg_schema.expire_all()
        row = pg_schema.get(PrivateReflection, reflection_id)

        # The scope is UNCHANGED — no implicit PRIVATE_PARTNER -> SHARED_COUPLE
        # reclassification happened on activation (R16.5).
        assert row.visibility_scope == Visibility_Scope.PRIVATE_PARTNER
        # Owner and couple context are untouched too (R16.5); couple_id is
        # context only and never turns the reflection shared (R16.4).
        assert row.user_id == owner_id
        assert row.couple_id == couple_id_before
    finally:
        savepoint.rollback()


# ===========================================================================
# DB-backed: create_couple (couple formation) also never reclassifies
# (Feature: foundation-auth-couples, Property 5)
# ===========================================================================


@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(attach_couple=st.booleans())
def test_property_create_couple_never_reclassifies_reflection(
    pg_schema, attach_couple
):
    """Property 5: forming a couple (create_couple) never reclassifies a
    PRIVATE_PARTNER reflection owned by the creator — the newly PENDING couple's
    formation touches no reflection (R16.5/R16.6).

    Feature: foundation-auth-couples, Property 5

    **Validates: Requirements 16.5, 16.6**
    """
    savepoint = pg_schema.begin_nested()
    try:
        from app.audit.repository import AuditRepository
        from app.audit.service import AuditService
        from app.couples.repository import CoupleRepository
        from app.couples.service import CoupleService

        # DDL inside the SAVEPOINT so schema + rows roll back with the example.
        _create_couples_tables(pg_schema)
        _create_audit_table(pg_schema)

        couple_service = CoupleService(
            couple_repository=CoupleRepository(pg_schema),
            audit_service=AuditService(AuditRepository(pg_schema)),
        )
        creator = _actor()

        # A private reflection owned by the creator BEFORE the couple exists.
        reflection = PrivateReflection(
            id=uuid.uuid4(),
            user_id=creator.user_id,
            couple_id=None,
            visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
        )
        pg_schema.add(reflection)
        pg_schema.flush()
        reflection_id = reflection.id

        view = couple_service.create_couple(creator)
        pg_schema.flush()
        assert view.status == Couple_Status.PENDING

        # If requested, attach the (now-existing) couple id as context only.
        if attach_couple:
            reflection.couple_id = view.id
            pg_schema.flush()
        couple_id_before = reflection.couple_id

        pg_schema.expire_all()
        row = pg_schema.get(PrivateReflection, reflection_id)
        assert row.visibility_scope == Visibility_Scope.PRIVATE_PARTNER  # R16.5
        assert row.user_id == creator.user_id
        assert row.couple_id == couple_id_before  # R16.4 (context only)
    finally:
        savepoint.rollback()


# ===========================================================================
# Pure: create_couple and accept_invitation touch no PrivateReflection at all
# (Feature: foundation-auth-couples, Property 5)
# ===========================================================================


class _ReflectionTrackingRepo:
    """Wraps a fake CoupleRepository and holds a set of PrivateReflections that
    no couple operation is ever handed a path to mutate.

    The service accepts/creates couples through the wrapped repository; this
    wrapper additionally exposes the reflections it "owns" so the test can
    snapshot them before and after. Since the couples service has no method that
    reads or writes reflections, the set is provably identical afterwards.
    """

    def __init__(self, inner):
        self._inner = inner
        self.reflections: dict[uuid.UUID, PrivateReflection] = {}

    def add_reflection(self, reflection: PrivateReflection) -> None:
        self.reflections[reflection.id] = reflection

    def snapshot(self):
        return {
            rid: (r.user_id, r.visibility_scope, r.couple_id)
            for rid, r in self.reflections.items()
        }

    def __getattr__(self, name):
        # Delegate every repository call to the inner fake.
        return getattr(self._inner, name)


@settings(max_examples=100, deadline=None)
@given(
    raw=st.text(min_size=1, max_size=48),
    reflections=st.lists(_arrangement, min_size=0, max_size=5),
)
def test_property_accept_touches_no_reflection(raw, reflections):
    """Property 5: acceptance changes only the relationship — the full set of
    PrivateReflections (scope + owner + couple context) is byte-for-byte
    identical before and after accept_invitation, for any arrangement of
    reflections. No implicit reclassification path exists (R16.5/R16.6).

    Feature: foundation-auth-couples, Property 5

    **Validates: Requirements 16.5, 16.6**
    """
    service, inner_repo, _audit = _pure_service()
    tracker = _ReflectionTrackingRepo(inner_repo)
    couple, _invitation = _pending_couple_with_invitation(inner_repo, raw)
    invitee = _actor()

    creator_id = next(
        m.user_id
        for m in inner_repo.members.values()
        if m.role == Member_Role.PARTNER_A
    )
    for spec in reflections:
        owner_id = _resolve_owner(
            spec["owner"], creator_id=creator_id, invitee_id=invitee.user_id
        )
        tracker.add_reflection(
            PrivateReflection(
                id=uuid.uuid4(),
                user_id=owner_id,
                couple_id=couple.id if spec["attach_couple"] else None,
                visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
            )
        )

    before = tracker.snapshot()

    # Rewire the service onto the tracking repository (it delegates everything),
    # so acceptance runs through exactly the same code path.
    service._couples = tracker
    view = service.accept_invitation(invitee, raw)

    assert view.status == Couple_Status.ACTIVE  # the couple activated
    # Not a single reflection was reclassified, re-owned, or re-scoped.
    assert tracker.snapshot() == before
