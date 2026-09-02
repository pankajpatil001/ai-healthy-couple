"""Users module repository — the only path to user/account persistence.

The repository is the single doorway between the service layer and the ``users``
table (design.md "Logical modules": *"an authorized repository layer (the only
path to the database). No route handler talks to the database directly."*).

For task 6.2 (AuthenticationService) the repository must be able to:

* create a User during registration (R1.1, R1.4);
* detect a duplicate ``auth_identifier`` so registration can fail closed with a
  privacy-safe conflict rather than leaking another account's data (R1.2, R1.5);
* look a User up by ``auth_identifier`` (login / recovery) and by ``id``.

Duplicate detection is layered:

1. A cheap pre-check (``get_by_auth_identifier``) rejects the common case early.
2. The authoritative guard is the ``uq_users_auth_identifier`` UNIQUE constraint
   (migration ``0002_foundation_schema``). Even under a race between two
   concurrent registrations the database rejects the second insert; the
   repository surfaces that as :class:`~app.errors.IdentifierInUseError` so the
   service and API never depend on the pre-check alone.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.enums import Account_Status, Deletion_Status
from app.errors import IdentifierInUseError
from app.users.models import DataDeletionRequest, User

#: The UNIQUE constraint name the initial migration assigns to
#: ``users.auth_identifier`` (migration ``0002_foundation_schema``). Used to
#: recognise a duplicate-identifier IntegrityError specifically, rather than
#: swallowing every integrity failure.
AUTH_IDENTIFIER_UNIQUE_CONSTRAINT = "uq_users_auth_identifier"


class UserRepository:
    """Persistence for :class:`~app.users.models.User` rows.

    Holds a SQLAlchemy :class:`~sqlalchemy.orm.Session`; committing the
    surrounding transaction is the caller's responsibility (mirrors
    :class:`~app.audit.repository.AuditRepository` and
    :func:`app.db.get_session`).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- reads ------------------------------------------------------------

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Return the User with ``user_id`` or ``None`` if absent."""
        return self._session.get(User, user_id)

    def get_by_auth_identifier(self, auth_identifier: str) -> User | None:
        """Return the User holding ``auth_identifier`` or ``None`` if none does.

        The identifier is treated as sensitive: this lookup is used server-side
        only (login / recovery) and never echoes another user's identifier back
        to a caller (R1.5).
        """
        return self._session.execute(
            select(User).where(User.auth_identifier == auth_identifier)
        ).scalar_one_or_none()

    def get_account_status(self, user_id: uuid.UUID) -> Account_Status | None:
        """Return the user's current :class:`Account_Status`, or ``None``.

        Satisfies the :class:`~app.auth.service.UserStatusLookup` protocol so the
        same repository can back :meth:`SessionService.authenticate`'s
        fail-closed status re-check (R3.6).
        """
        user = self.get_by_id(user_id)
        return user.status if user is not None else None

    # -- writes -----------------------------------------------------------

    def create(
        self,
        *,
        auth_identifier: str,
        status: Account_Status = Account_Status.ACTIVE,
        display_name: str | None = None,
        locale: str | None = None,
        timezone: str | None = None,
    ) -> User:
        """Insert a new User and return it (R1.1, R1.4).

        The row is flushed so the database-generated ``created_at`` / ``id`` are
        populated on the returned instance. If the ``auth_identifier`` already
        exists the database's UNIQUE constraint rejects the insert and this
        method raises :class:`~app.errors.IdentifierInUseError` (R1.2) — the
        authoritative, race-safe guard.

        The insert runs inside a SAVEPOINT (nested transaction) so that a
        rejected duplicate rolls back *only* this insert, leaving the
        surrounding transaction — and any work already done in it — intact and
        the session usable for subsequent operations.
        """
        user = User(
            id=uuid.uuid4(),
            auth_identifier=auth_identifier,
            status=status,
            display_name=display_name,
            locale=locale,
            timezone=timezone,
        )
        try:
            with self._session.begin_nested():
                self._session.add(user)
                self._session.flush()
        except IntegrityError as exc:
            # The SAVEPOINT is rolled back by the context manager; only this
            # insert is undone.
            if self._is_duplicate_identifier(exc):
                raise IdentifierInUseError() from exc
            raise
        return user

    def set_status(
        self,
        user_id: uuid.UUID,
        status: Account_Status,
        *,
        deleted_at: datetime | None = None,
    ) -> User | None:
        """Set a user's :class:`Account_Status` server-side and return the row.

        This is the *only* write path for account lifecycle state; it is invoked
        exclusively by server-side lifecycle operations
        (:meth:`~app.users.service.AccountService.transition_status`), never from
        a client-supplied value (R7.1, R7.4). Returns ``None`` if the user does
        not exist. When transitioning to DELETED, ``deleted_at`` stamps the
        soft-delete time (R8.3); otherwise it is left untouched.

        The row is flushed so the ORM state reflects the change; committing the
        surrounding transaction remains the caller's responsibility.
        """
        user = self.get_by_id(user_id)
        if user is None:
            return None
        user.status = status
        if deleted_at is not None:
            user.deleted_at = deleted_at
        self._session.flush()
        return user

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _is_duplicate_identifier(exc: IntegrityError) -> bool:
        """True when ``exc`` is the auth-identifier UNIQUE violation.

        Matches on the named constraint so an unrelated integrity failure is not
        misreported as a duplicate identifier. Falls back to matching the column
        name in the driver message for engines that don't surface the
        constraint name.
        """
        text = str(getattr(exc, "orig", exc))
        return (
            AUTH_IDENTIFIER_UNIQUE_CONSTRAINT in text
            or "auth_identifier" in text
        )


class DataDeletionRequestRepository:
    """Persistence for :class:`~app.users.models.DataDeletionRequest` rows.

    The account-deletion pathway record (R8.1). Like the other Foundation
    repositories it holds a :class:`~sqlalchemy.orm.Session` and leaves the
    surrounding transaction's commit to the caller (mirrors
    :class:`UserRepository`). Rows are created after a successful
    re-authentication by
    :meth:`~app.users.service.AccountService.request_account_deletion`; the
    deletion lifecycle itself (REQUESTED → … → COMPLETED) is progressed
    server-side.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        user_id: uuid.UUID,
        scope: str,
        status: Deletion_Status = Deletion_Status.REQUESTED,
    ) -> DataDeletionRequest:
        """Insert a new deletion request (status REQUESTED by default) (R8.1).

        The row is flushed so the DB-generated ``id`` / ``requested_at`` are
        populated on the returned instance.
        """
        request = DataDeletionRequest(
            id=uuid.uuid4(),
            user_id=user_id,
            scope=scope,
            status=status,
        )
        self._session.add(request)
        self._session.flush()
        return request

    def list_for_user(self, user_id: uuid.UUID) -> list[DataDeletionRequest]:
        """Return every deletion request recorded for ``user_id`` (newest is not ordered).

        Used to inspect a user's deletion history; the account-deletion flow
        reads it back in tests to confirm a REQUESTED record was created.
        """
        return list(
            self._session.execute(
                select(DataDeletionRequest).where(
                    DataDeletionRequest.user_id == user_id
                )
            )
            .scalars()
            .all()
        )


__all__ = [
    "UserRepository",
    "DataDeletionRequestRepository",
    "AUTH_IDENTIFIER_UNIQUE_CONSTRAINT",
]
