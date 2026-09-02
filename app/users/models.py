"""Users module ORM models.

Design data models (design.md "Data Models"):

* :class:`User` — the account record. Credential material is delegated to the
  managed identity provider and is deliberately **not** stored here
  (08-technology-stack.md §9); ``auth_identifier`` is the only identity coordinate
  persisted and is treated as sensitive (R1.2, R1.5).
* :class:`DataDeletionRequest` — the account-deletion pathway record (R8.x).

SQLAlchemy 2.0 declarative-typed mapping (``Mapped`` / ``mapped_column``). Enum
columns are backed by the shared value sets in :mod:`app.enums`. Uniqueness,
indexes, and other table constraints are authored in the initial migration
(task 2.3); immutability expectations are documented inline here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Enum as SAEnum
from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.enums import Account_Status, Deletion_Status


class User(Base):
    """A user account (design.md "User", 02-database-schema.md §5).

    ``auth_identifier`` is unique and sensitive: it is never exposed for other
    users (R1.2, R1.5) and its uniqueness (enforced by a DB constraint added in
    task 2.3) is what rejects duplicate registration. Credential material lives
    with the identity provider, not in this table.

    ``status`` is server-controlled only; clients never supply it (R7.4).
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Unique + sensitive; the UNIQUE constraint is added in the initial
    # migration (task 2.3, R1.2). Not exposed to other users (R1.5).
    auth_identifier: Mapped[str] = mapped_column(String(320), nullable=False)

    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    locale: Mapped[str | None] = mapped_column(String(35), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Account_Status — server-controlled lifecycle (R7.1, R7.4).
    status: Mapped[Account_Status] = mapped_column(
        SAEnum(Account_Status, name="account_status"),
        nullable=False,
        default=Account_Status.ACTIVE,
    )

    created_at: Mapped[datetime] = mapped_column(  # R1.4
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(  # R6.2
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    # Set when the account is soft-deleted; the lifecycle move to DELETED is
    # server-side only (R8.3).
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User id={self.id!s} status={self.status!s}>"


class DataDeletionRequest(Base):
    """A request to delete a user's account/data (design.md "DataDeletionRequest").

    Created with ``status = REQUESTED`` after a successful re-authentication
    (R8.1); progresses server-side through the :class:`~app.enums.Deletion_Status`
    lifecycle. ``failure_reason`` captures why processing failed, if it did.
    """

    __tablename__ = "data_deletion_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Deletion scope descriptor (e.g. full account). Constrained by product
    # rules at the service layer; a free-form label at the storage layer.
    scope: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[Deletion_Status] = mapped_column(
        SAEnum(Deletion_Status, name="deletion_status"),
        nullable=False,
        default=Deletion_Status.REQUESTED,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failure_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DataDeletionRequest id={self.id!s} user_id={self.user_id!s} "
            f"status={self.status!s}>"
        )


__all__ = ["User", "DataDeletionRequest"]
