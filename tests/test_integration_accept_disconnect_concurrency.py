"""Accept-vs-disconnect concurrency integration test (task 13.4).

Feature: foundation-auth-couples

Design "Integration tests" / design §37 / R11.4 / R13.2:

    Accept-vs-disconnect concurrency: interleave ``accept_invitation`` and
    ``disconnect_couple``; assert no inconsistent end state (R11.4, §37).

This is the DB-backed counterpart to the in-memory *Property 13* test
(``tests/test_property_accept_disconnect_atomic.py``), which models arbitrary
*serialized* interleavings against fakes. Here we exercise the **real**
services and the **real** repository against a **real, ephemeral PostgreSQL
database**, so the actual ``FOR UPDATE`` row locks and the re-check-at-commit
logic in :meth:`CoupleRepository.accept_invitation_atomic` /
:meth:`CoupleRepository.disconnect_couple_atomic` are what serialise the race —
exactly the mechanism design §37 relies on to satisfy R11.4.

Two layers of interleaving are covered:

* **Truly concurrent (threads + two DB connections).** Two independent
  connections into the *same committed schema* race ``accept_invitation`` and
  ``disconnect_couple`` on the same couple, released together by a barrier.
  Postgres row locks serialise them; whichever commits first wins and the other
  observes the winner's committed state under the lock and is cleanly refused.
  We assert a strong end-state invariant afterwards.

* **Every deterministic ordering.** For each ordering of a small operation
  sequence (accept / disconnect attempts) driven on a single real session, the
  invariant holds after *every* step — no half-applied membership, no
  contradictory couple/member status combination — for any interleaving.

Because the shared ``pg_schema`` fixture keeps everything inside one
uncommitted transaction (so a second connection could not see the rows), the
truly-concurrent test manages its **own committed schema** (created and dropped
around the test) so both connections observe the same tables and rows. It skips
cleanly when PostgreSQL is unreachable.

The re-auth gate on ``disconnect_couple`` (a Sensitive_Operation, R5.3/R13.2)
is satisfied here with a lightweight always-accepting auth double: this test
targets the *DB atomicity* concern of R11.4/§37, and the re-auth gate itself is
covered exhaustively by the disconnect-flow unit/DB tests and the re-auth
property test. Keeping auth in-memory also means the concurrency test needs only
PostgreSQL, not Redis.

**Validates: Requirements 11.4, 13.2**
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.couples.models import Couple, CoupleInvitation, CoupleMember
from app.couples.repository import (
    ACTIVE_MEMBER_UNIQUE_INDEX,
    INVITATION_TOKEN_HASH_UNIQUE_INDEX,
    CoupleRepository,
)
from app.couples.service import CoupleService, InvitationService
from app.enums import (
    Account_Status,
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
)
from app.errors import (
    ActiveCoupleExistsError,
    ReauthRequiredError,
    ResourceNotFoundError,
)


# ---------------------------------------------------------------------------
# Auth double — the re-auth gate is out of scope for the DB-race concern
# ---------------------------------------------------------------------------


class _AlwaysOkAuth:
    """Accept any re-auth grant for the disconnect Sensitive_Operation.

    Disconnect gates on a valid re-auth grant (R5.3/R13.2); that gate is proven
    elsewhere. Here we only care about the DB atomicity of the accept-vs-
    disconnect race, so this double lets the operation reach the repository.
    """

    def consume_reauthentication(self, grant, actor, operation_type):  # noqa: D401
        return True


def _actor(user_id: uuid.UUID | None = None) -> AuthenticatedActor:
    return AuthenticatedActor(
        user_id=user_id or uuid.uuid4(), account_status=Account_Status.ACTIVE
    )


def _couple_service(session: Session) -> CoupleService:
    return CoupleService(
        couple_repository=CoupleRepository(session),
        audit_service=AuditService(AuditRepository(session)),
        authentication_service=_AlwaysOkAuth(),
    )


def _invitation_service(session: Session) -> InvitationService:
    return InvitationService(
        couple_repository=CoupleRepository(session),
        audit_service=AuditService(AuditRepository(session)),
    )


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

_TABLES = (Couple, CoupleMember, CoupleInvitation)


def _create_schema_objects(session: Session) -> None:
    """Create the couples tables + the REAL partial/unique indexes.

    ``Base.metadata.create_all`` builds the tables from the ORM models; the
    partial unique index (at-most-one-ACTIVE-couple) and the unique token-hash
    index live in migration ``0002_foundation_schema``, so they are added
    explicitly to reproduce the authored schema. The audit table backs the
    content-free events the services record.
    """
    from app.audit.models import AuditEvent
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[t.__table__ for t in _TABLES] + [AuditEvent.__table__],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{ACTIVE_MEMBER_UNIQUE_INDEX}" '
            "ON couple_members (user_id) WHERE status = 'ACTIVE'"
        )
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{INVITATION_TOKEN_HASH_UNIQUE_INDEX}" '
            "ON couple_invitations (token_hash)"
        )
    )


def _seed_pending_couple_with_invitation(session: Session):
    """Persist the race arena: a PENDING couple with PARTNER_A + a PENDING invite.

    Returns ``(couple_id, invitation_id, raw_token, invitee)`` where ``invitee``
    is the actor who will attempt to accept. The disconnect actor is PARTNER_A
    (the couple creator). Everything is flushed so ids are assigned.
    """
    repo = CoupleRepository(session)
    partner_a = _actor()
    couple = repo.create_couple_with_creator(partner_a.user_id)
    session.flush()

    inv_service = _invitation_service(session)
    raw = inv_service.create_invitation(
        partner_a, couple.id, "invitee@example.test"
    )
    session.flush()
    return couple.id, raw.invitation_id, raw.raw_token, partner_a, _actor()


# ---------------------------------------------------------------------------
# The end-state consistency invariant (shared by both layers)
# ---------------------------------------------------------------------------


def _assert_consistent_end_state(
    session: Session,
    couple_id: uuid.UUID,
    invitation_id: uuid.UUID,
    invitee_id: uuid.UUID,
) -> None:
    """The couple/invitation/member rows are internally non-contradictory.

    This is the DB-level encoding of R11.4 / design Property 13 — the couple is
    never left half-joined or in a contradictory status combination, whichever
    of {accept, disconnect} won the race:

    * couple status is one of the three legal lifecycle states;
    * PENDING  → no PARTNER_B row, invitation still PENDING (accept not applied);
    * ACTIVE   → invitation ACCEPTED and the invitee is a single ACTIVE
      PARTNER_B (accept applied completely);
    * DISCONNECTED → every member row is DISCONNECTED (no dangling ACTIVE
      member), and the invitee is never an ACTIVE member of a dead couple;
    * globally, no user is an ACTIVE member of more than one couple (the partial
      unique index invariant).
    """
    session.expire_all()  # read committed state, not stale identity-map copies

    couple = session.get(Couple, couple_id)
    invitation = session.get(CoupleInvitation, invitation_id)
    assert couple is not None
    assert invitation is not None
    assert couple.status in {
        Couple_Status.PENDING,
        Couple_Status.ACTIVE,
        Couple_Status.DISCONNECTED,
    }

    members = (
        session.execute(
            select(CoupleMember).where(CoupleMember.couple_id == couple_id)
        )
        .scalars()
        .all()
    )
    partner_bs = [m for m in members if m.role == Member_Role.PARTNER_B]

    if couple.status == Couple_Status.PENDING:
        assert partner_bs == []
        assert invitation.status == Invitation_Status.PENDING
        assert couple.activated_at is None

    elif couple.status == Couple_Status.ACTIVE:
        assert invitation.status == Invitation_Status.ACCEPTED
        assert couple.activated_at is not None
        active_bs = [
            m
            for m in partner_bs
            if m.user_id == invitee_id and m.status == Member_Status.ACTIVE
        ]
        assert len(active_bs) == 1

    else:  # DISCONNECTED
        assert couple.disconnected_at is not None
        assert all(m.status == Member_Status.DISCONNECTED for m in members)
        assert not any(
            m.user_id == invitee_id and m.status == Member_Status.ACTIVE
            for m in members
        )

    # Global: at most one ACTIVE membership per user across all couples.
    all_members = (
        session.execute(select(CoupleMember)).scalars().all()
    )
    active_by_user: dict[uuid.UUID, int] = {}
    for m in all_members:
        if m.status == Member_Status.ACTIVE:
            active_by_user[m.user_id] = active_by_user.get(m.user_id, 0) + 1
    assert all(count <= 1 for count in active_by_user.values())


# ===========================================================================
# Layer 1 — deterministic interleavings on a single real session
# ===========================================================================
#
# The shared pg_schema fixture keeps everything inside one open transaction, so
# a single session is enough to drive the repository's row-lock + re-check code
# against real Postgres for every ordering. (True cross-connection concurrency
# is exercised separately in Layer 2, which manages its own committed schema.)


def _attempt_accept(session, invitee, raw_token) -> bool:
    """Try the real accept; True on success, False on a clean refusal.

    A refusal is raised out of the repository's inner SAVEPOINT (``begin_nested``),
    which unwinds only its own partial work — so the surrounding transaction
    (and the tables/rows created in it by the ``pg_schema`` fixture) stays
    intact. We deliberately do NOT call ``session.rollback()`` here, which would
    discard the whole outer transaction.
    """
    try:
        _invitation_service(session).accept_invitation(invitee, raw_token)
        return True
    except (ResourceNotFoundError, ActiveCoupleExistsError):
        return False


def _attempt_disconnect(session, actor, couple_id) -> bool:
    """Try the real disconnect; True on success, False on a clean refusal.

    As with :func:`_attempt_accept`, a refusal unwinds only the repository's
    inner SAVEPOINT; the outer transaction is left usable.
    """
    try:
        _couple_service(session).disconnect_couple(
            actor, couple_id, reauth_grant=object()
        )
        return True
    except (ResourceNotFoundError, ReauthRequiredError):
        return False


# 0 = accept attempt, 1 = disconnect attempt. Enumerate every ordering of a
# short sequence so all interleavings of the two operations are covered.
def _all_orderings(length: int):
    if length == 0:
        yield ()
        return
    for head in (0, 1):
        for tail in _all_orderings(length - 1):
            yield (head,) + tail


@pytest.mark.parametrize("ordering", list(_all_orderings(3)))
def test_db_interleavings_stay_consistent(pg_schema, ordering):
    """R11.4/§37 (DB): for ANY ordering of accept/disconnect against the same
    couple, the persisted end state is consistent after every step.

    From a PENDING couple exactly one accept can commit (couple→ACTIVE); from an
    ACTIVE couple exactly one disconnect can commit (couple→DISCONNECTED). The
    repository's ``FOR UPDATE`` + re-check-at-commit refuses the loser cleanly,
    so no ordering yields a half-applied membership or a contradictory status
    combination.

    **Validates: Requirements 11.4, 13.2**
    """
    _create_schema_objects(pg_schema)
    couple_id, invitation_id, raw_token, partner_a, invitee = (
        _seed_pending_couple_with_invitation(pg_schema)
    )

    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)

    for op in ordering:
        if op == 0:
            _attempt_accept(pg_schema, invitee, raw_token)
        else:
            _attempt_disconnect(pg_schema, partner_a, couple_id)
        _assert_consistent_end_state(
            pg_schema, couple_id, invitation_id, invitee.user_id
        )


def test_db_accept_then_disconnect_is_ordered_and_exclusive(pg_schema):
    """R11.4/R13.2 (DB): a disconnect before the accept is refused (couple
    PENDING); the accept activates the couple; a following disconnect observes
    ACTIVE and tears it down — each step leaves a consistent state.

    **Validates: Requirements 11.4, 13.2**
    """
    _create_schema_objects(pg_schema)
    couple_id, invitation_id, raw_token, partner_a, invitee = (
        _seed_pending_couple_with_invitation(pg_schema)
    )

    # Disconnect against a still-PENDING couple is a clean refusal.
    assert _attempt_disconnect(pg_schema, partner_a, couple_id) is False
    assert pg_schema.get(Couple, couple_id).status == Couple_Status.PENDING
    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)

    # The accept commits and activates the couple completely.
    assert _attempt_accept(pg_schema, invitee, raw_token) is True
    pg_schema.expire_all()
    assert pg_schema.get(Couple, couple_id).status == Couple_Status.ACTIVE
    assert (
        pg_schema.get(CoupleInvitation, invitation_id).status
        == Invitation_Status.ACCEPTED
    )
    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)

    # A second accept can never win now (invitation + couple no longer PENDING).
    assert _attempt_accept(pg_schema, invitee, raw_token) is False
    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)

    # The disconnect now observes ACTIVE and succeeds; a second is refused.
    assert _attempt_disconnect(pg_schema, partner_a, couple_id) is True
    pg_schema.expire_all()
    assert pg_schema.get(Couple, couple_id).status == Couple_Status.DISCONNECTED
    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)

    assert _attempt_disconnect(pg_schema, partner_a, couple_id) is False
    _assert_consistent_end_state(pg_schema, couple_id, invitation_id, invitee.user_id)


# ===========================================================================
# Layer 2 — truly concurrent threads over two committed DB connections
# ===========================================================================


@pytest.fixture
def committed_schema():
    """Yield a schema name backed by COMMITTED tables, on a dedicated connection.

    Unlike ``pg_schema`` (everything inside one open transaction, invisible to
    other connections), this creates the schema and its tables and COMMITS them,
    so independent connections opened by concurrent threads all observe the same
    rows — a prerequisite for a genuine cross-connection row-lock race. The
    schema is dropped (CASCADE) on teardown. Skips if Postgres is unreachable.
    """
    from app.db import engine

    schema_name = f"test_conc_{uuid.uuid4().hex}"

    try:
        admin = engine.connect()
    except SQLAlchemyError as exc:  # pragma: no cover - infra-dependent
        pytest.skip(f"PostgreSQL not reachable: {exc}")

    try:
        admin.execute(text(f'CREATE SCHEMA "{schema_name}"'))
        admin.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - infra-dependent
        admin.close()
        pytest.skip(f"Could not create ephemeral schema: {exc}")

    # Build the tables/indexes inside the schema and COMMIT so other
    # connections can see them.
    setup = Session(bind=engine.connect())
    setup.execute(text(f'SET search_path TO "{schema_name}"'))
    try:
        _create_schema_objects(setup)
        setup.commit()
    finally:
        setup.close()

    try:
        yield schema_name
    finally:
        try:
            admin.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
            admin.commit()
        except SQLAlchemyError:  # pragma: no cover - best-effort cleanup
            admin.rollback()
        finally:
            admin.close()


def _open_session(schema_name: str) -> Session:
    """A fresh Session on its own connection, scoped to ``schema_name``."""
    from app.db import engine

    session = Session(bind=engine.connect())
    session.execute(text(f'SET search_path TO "{schema_name}"'))
    return session


def _seed_committed_arena(schema_name: str):
    """Seed a PENDING couple + PENDING invitation and COMMIT it.

    Returns ``(couple_id, invitation_id, raw_token, partner_a, invitee)``.
    """
    session = _open_session(schema_name)
    try:
        couple_id, invitation_id, raw_token, partner_a, invitee = (
            _seed_pending_couple_with_invitation(session)
        )
        session.commit()
        return couple_id, invitation_id, raw_token, partner_a, invitee
    finally:
        session.close()


def _seed_committed_active_arena(schema_name: str):
    """Seed an already-ACTIVE couple (invitation ACCEPTED, invitee enrolled) and
    a *second* PENDING invitation for a fresh candidate, then COMMIT it.

    This is the arena for the other direction of the race: the couple is already
    ACTIVE, so a concurrent ``accept`` of the second invitation must LOSE
    (couple no longer PENDING) while a concurrent ``disconnect`` can WIN.

    Returns ``(couple_id, second_invitation_id, second_raw_token, partner_a,
    candidate)`` where ``candidate`` is the actor attempting the doomed accept.
    """
    session = _open_session(schema_name)
    try:
        couple_id, invitation_id, raw_token, partner_a, invitee = (
            _seed_pending_couple_with_invitation(session)
        )
        # Bring the couple to ACTIVE by accepting the first invitation for real.
        _invitation_service(session).accept_invitation(invitee, raw_token)
        session.flush()

        # A second PENDING invitation for a different candidate. (Belt-and-braces
        # against the both-roles-filled guard: create it directly so the seed
        # does not depend on invite-creation rules for an ACTIVE couple.)
        candidate = _actor()
        from app.couples import tokens

        raw2, hash2 = tokens.new_invitation_token()
        session.add(
            CoupleInvitation(
                id=uuid.uuid4(),
                couple_id=couple_id,
                inviter_user_id=partner_a.user_id,
                invitee_identifier="candidate@example.test",
                token_hash=hash2,
                status=Invitation_Status.PENDING,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        session.flush()
        second_invitation_id = (
            session.execute(
                select(CoupleInvitation.id).where(
                    CoupleInvitation.token_hash == hash2
                )
            ).scalar_one()
        )
        session.commit()
        return couple_id, second_invitation_id, raw2, partner_a, candidate
    finally:
        session.close()


def test_concurrent_accept_vs_disconnect_no_inconsistent_end_state(committed_schema):
    """R11.4/§37 (DB, truly concurrent): two connections race accept vs
    disconnect on the same couple; the end state is always consistent.

    Both threads block on a barrier and are released together, then each runs
    its real service call in its own transaction and commits. Postgres row locks
    (``FOR UPDATE`` on the invitation + couple for accept, on the couple for
    disconnect) serialise them: exactly one of {accept, disconnect} can commit
    from the initial PENDING state, the other observes the winner under the lock
    and is cleanly refused — never a partial write. Repeated across several
    fresh arenas to shake out ordering nondeterminism.

    **Validates: Requirements 11.4, 13.2**
    """
    ROUNDS = 12
    saw_accept_win = 0
    saw_disconnect_win = 0

    for _ in range(ROUNDS):
        couple_id, invitation_id, raw_token, partner_a, invitee = (
            _seed_committed_arena(committed_schema)
        )

        barrier = threading.Barrier(2)
        results: dict[str, object] = {}

        def do_accept():
            session = _open_session(committed_schema)
            try:
                barrier.wait()
                try:
                    _invitation_service(session).accept_invitation(
                        invitee, raw_token
                    )
                    session.commit()
                    results["accept"] = True
                except (ResourceNotFoundError, ActiveCoupleExistsError) as exc:
                    session.rollback()
                    results["accept"] = False
                    results["accept_exc"] = type(exc).__name__
            except Exception as exc:  # pragma: no cover - surfaced to assertion
                session.rollback()
                results["accept_error"] = repr(exc)
            finally:
                session.close()

        def do_disconnect():
            session = _open_session(committed_schema)
            try:
                barrier.wait()
                try:
                    _couple_service(session).disconnect_couple(
                        partner_a, couple_id, reauth_grant=object()
                    )
                    session.commit()
                    results["disconnect"] = True
                except (ResourceNotFoundError, ReauthRequiredError) as exc:
                    session.rollback()
                    results["disconnect"] = False
                    results["disconnect_exc"] = type(exc).__name__
            except Exception as exc:  # pragma: no cover - surfaced to assertion
                session.rollback()
                results["disconnect_error"] = repr(exc)
            finally:
                session.close()

        t_accept = threading.Thread(target=do_accept)
        t_disconnect = threading.Thread(target=do_disconnect)
        t_accept.start()
        t_disconnect.start()
        t_accept.join(timeout=30)
        t_disconnect.join(timeout=30)

        assert not t_accept.is_alive() and not t_disconnect.is_alive(), (
            "a racing operation deadlocked/hung"
        )
        # Neither thread raised an unexpected error.
        assert "accept_error" not in results, results.get("accept_error")
        assert "disconnect_error" not in results, results.get("disconnect_error")

        # Disconnect cannot commit against the *initial* PENDING couple — the
        # repository re-checks ACTIVE under its FOR UPDATE lock and refuses a
        # non-ACTIVE couple. But the two threads are released together, so a
        # legitimate serialisation is: accept commits first (PENDING -> ACTIVE),
        # then disconnect observes the now-ACTIVE couple under its lock and
        # disconnects it (ACTIVE -> DISCONNECTED). In that ordering *both*
        # operations succeed, which is a consistent end state (couple
        # DISCONNECTED, invitation ACCEPTED, both members DISCONNECTED), verified
        # below. The one ordering that must never happen is disconnect winning
        # while accept was refused, since disconnect from PENDING is impossible:
        # a disconnect success therefore implies accept also succeeded first.
        if results.get("disconnect") is True:
            assert results.get("accept") is True, (
                "disconnect committed but accept did not — disconnect cannot "
                "win from a PENDING couple, so this would be an impossible state"
            )
        if results.get("accept") is True:
            saw_accept_win += 1
        else:
            saw_disconnect_win += 1

        verify = _open_session(committed_schema)
        try:
            _assert_consistent_end_state(
                verify, couple_id, invitation_id, invitee.user_id
            )
        finally:
            verify.close()

    # The accept should have been able to win at least once across the rounds
    # (from PENDING it has no competing committed state to lose to). This guards
    # against a false-green where every accept silently failed for an unrelated
    # reason rather than genuinely racing.
    assert saw_accept_win >= 1
    # A round counts as a "disconnect win" only when accept was refused; that can
    # never happen from a PENDING couple (disconnect can't win without accept
    # activating the couple first), so this stays 0.
    assert saw_disconnect_win == 0
    assert saw_accept_win == ROUNDS


def test_concurrent_disconnect_vs_late_accept_on_active_couple(committed_schema):
    """R11.4/§37 (DB, truly concurrent — other direction): on an ALREADY-ACTIVE
    couple, a concurrent ``disconnect`` and a late ``accept`` of a still-PENDING
    second invitation race; the disconnect wins and the late accept is cleanly
    refused, never producing an inconsistent state.

    This exercises the direction the PENDING-couple race cannot: here disconnect
    *can* commit (the couple is ACTIVE) while the accept *must* lose — the accept
    re-reads, under its ``FOR UPDATE`` lock, a couple that a racing disconnect
    has moved off PENDING (or that it observes still-ACTIVE and then the
    disconnect serialises after), so it is refused with a Privacy_Safe_Response
    and adds no membership. Either way the end state is consistent: the couple is
    DISCONNECTED with every member DISCONNECTED and the late candidate never
    enrolled.

    **Validates: Requirements 11.4, 13.2**
    """
    ROUNDS = 12
    saw_disconnect_win = 0

    for _ in range(ROUNDS):
        couple_id, invitation_id, raw_token, partner_a, candidate = (
            _seed_committed_active_arena(committed_schema)
        )

        barrier = threading.Barrier(2)
        results: dict[str, object] = {}

        def do_accept():
            session = _open_session(committed_schema)
            try:
                barrier.wait()
                try:
                    _invitation_service(session).accept_invitation(
                        candidate, raw_token
                    )
                    session.commit()
                    results["accept"] = True
                except (ResourceNotFoundError, ActiveCoupleExistsError) as exc:
                    session.rollback()
                    results["accept"] = False
                    results["accept_exc"] = type(exc).__name__
            except Exception as exc:  # pragma: no cover - surfaced to assertion
                session.rollback()
                results["accept_error"] = repr(exc)
            finally:
                session.close()

        def do_disconnect():
            session = _open_session(committed_schema)
            try:
                barrier.wait()
                try:
                    _couple_service(session).disconnect_couple(
                        partner_a, couple_id, reauth_grant=object()
                    )
                    session.commit()
                    results["disconnect"] = True
                except (ResourceNotFoundError, ReauthRequiredError) as exc:
                    session.rollback()
                    results["disconnect"] = False
                    results["disconnect_exc"] = type(exc).__name__
            except Exception as exc:  # pragma: no cover - surfaced to assertion
                session.rollback()
                results["disconnect_error"] = repr(exc)
            finally:
                session.close()

        t_accept = threading.Thread(target=do_accept)
        t_disconnect = threading.Thread(target=do_disconnect)
        t_accept.start()
        t_disconnect.start()
        t_accept.join(timeout=30)
        t_disconnect.join(timeout=30)

        assert not t_accept.is_alive() and not t_disconnect.is_alive(), (
            "a racing operation deadlocked/hung"
        )
        assert "accept_error" not in results, results.get("accept_error")
        assert "disconnect_error" not in results, results.get("disconnect_error")

        # The couple was ACTIVE, so the disconnect commits; the late accept can
        # never enroll the candidate (couple/invitation no longer joinable).
        assert results.get("disconnect") is True
        assert results.get("accept") is False
        saw_disconnect_win += 1

        verify = _open_session(committed_schema)
        try:
            _assert_consistent_end_state(
                verify, couple_id, invitation_id, candidate.user_id
            )
            # Stronger, direction-specific checks for this arena.
            couple = verify.get(Couple, couple_id)
            assert couple.status == Couple_Status.DISCONNECTED
            # The late candidate was never enrolled at all.
            candidate_rows = (
                verify.execute(
                    select(CoupleMember).where(
                        CoupleMember.couple_id == couple_id,
                        CoupleMember.user_id == candidate.user_id,
                    )
                )
                .scalars()
                .all()
            )
            assert candidate_rows == []
        finally:
            verify.close()

    assert saw_disconnect_win == ROUNDS
