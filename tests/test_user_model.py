"""Persistence-layer tests for the User model's identifier uniqueness (task 2.4).

Property 16 (design.md "Property 16: Registration enforces identifier uniqueness")
says that for any authentication identifier already associated with a User, a
registration attempt SHALL be rejected and SHALL NOT create a duplicate User;
the count of Users with that identifier remains exactly one.

``AuthenticationService.register`` is not implemented yet (task 6.2), so the
invariant is exercised where it is ultimately enforced: the database. The
``uq_users_auth_identifier`` UNIQUE constraint (migration
``0002_foundation_schema``, R1.2) is what makes a second insert with the same
identifier fail — leaving exactly one row.

The ORM model deliberately keeps the UNIQUE constraint in the migration rather
than on ``User.__table__`` (see ``app/users/models.py``). These tests therefore
create the ``users`` table in the ephemeral schema and add the same named
constraint the migration authors, so the constraint under test is a faithful
copy of production, not a test-only invention.

The tests run against a real, ephemeral PostgreSQL schema (the ``pg_schema``
fixture) so the constraint is enforced by Postgres itself, not mocked. The
duplicate insert is attempted inside a SAVEPOINT so that rolling back the failed
insert does not also undo the (uncommitted) table creation.

Feature: foundation-auth-couples, Property 16: Registration enforces identifier uniqueness
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from sqlalchemy import UniqueConstraint, func, select
from sqlalchemy.exc import IntegrityError

from app.enums import Account_Status
from app.users.models import User

from tests import strategies as domain_st


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_unique_constraint() -> None:
    """Attach the production UNIQUE constraint to ``User.__table__`` once.

    The production constraint lives in the migration, not on the ORM
    ``__table__`` (by design). We add it here under the same name the migration
    uses (``uq_users_auth_identifier``) so the invariant we test is exactly the
    one production enforces.
    """
    if not any(
        isinstance(c, UniqueConstraint) and c.name == "uq_users_auth_identifier"
        for c in User.__table__.constraints
    ):
        User.__table__.append_constraint(
            UniqueConstraint("auth_identifier", name="uq_users_auth_identifier")
        )


def _create_users_table(session) -> None:
    """Create the ``users`` table (and its enum type) in the test schema."""
    _ensure_unique_constraint()
    # Creates the account_status enum type and the users table in the schema
    # the session's search_path points at.
    User.__table__.create(bind=session.connection())


def _count_with_identifier(session, identifier: str) -> int:
    return session.execute(
        select(func.count()).select_from(User).where(
            User.auth_identifier == identifier
        )
    ).scalar_one()


def _register(session, identifier: str) -> None:
    """Persist one User with ``identifier`` (a stand-in for registration)."""
    session.add(
        User(id=uuid.uuid4(), auth_identifier=identifier, status=Account_Status.ACTIVE)
    )
    session.flush()


# ---------------------------------------------------------------------------
# Example-based sanity checks
# ---------------------------------------------------------------------------

def test_first_registration_with_identifier_succeeds(pg_schema):
    """A first, unused identifier persists exactly one User (R1.1)."""
    _create_users_table(pg_schema)

    identifier = "alice@example.test"
    _register(pg_schema, identifier)

    assert _count_with_identifier(pg_schema, identifier) == 1


def test_duplicate_identifier_is_rejected(pg_schema):
    """A second insert with the same identifier fails and adds no row (R1.2)."""
    _create_users_table(pg_schema)

    identifier = "bob@example.test"
    _register(pg_schema, identifier)

    # Attempt the duplicate inside a SAVEPOINT so its rollback leaves the table
    # (created in the still-open outer transaction) intact.
    with pytest.raises(IntegrityError):
        with pg_schema.begin_nested():
            _register(pg_schema, identifier)

    assert _count_with_identifier(pg_schema, identifier) == 1


# ---------------------------------------------------------------------------
# Property 16: registration enforces identifier uniqueness
# ---------------------------------------------------------------------------

# The pg_schema fixture is function-scoped and (correctly) shared across the
# examples Hypothesis generates for this test. That is intentional: the table is
# created once, and each example runs inside its own SAVEPOINT that is rolled
# back afterwards, so examples do not leak rows into one another.
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(identifier=domain_st.auth_identifiers())
def test_property_registration_enforces_identifier_uniqueness(pg_schema, identifier):
    """Property 16: a duplicate registration never yields two Users.

    For any authentication identifier, once one User holds it a second
    registration with the same identifier is rejected and creates no duplicate;
    the count of Users with that identifier stays exactly one.

    **Validates: Requirements 1.1, 1.2**
    """
    if not pg_schema.execute(
        select(func.to_regclass("users"))
    ).scalar_one():
        _create_users_table(pg_schema)

    with pg_schema.begin_nested() as example_savepoint:
        # First registration: the identifier is unused, so it succeeds (R1.1).
        _register(pg_schema, identifier)
        assert _count_with_identifier(pg_schema, identifier) == 1

        # Second registration with the SAME identifier must be rejected (R1.2):
        # Postgres raises on the UNIQUE constraint and no duplicate is written.
        with pytest.raises(IntegrityError):
            with pg_schema.begin_nested():
                _register(pg_schema, identifier)

        # Invariant: exactly one User carries the identifier.
        assert _count_with_identifier(pg_schema, identifier) == 1

        # Undo this example's inserts so the next example starts clean while the
        # table itself (created outside this savepoint) survives.
        example_savepoint.rollback()
