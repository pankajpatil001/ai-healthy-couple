"""Couples module ORM models.

Design data models (design.md "Data Models"):

* :class:`Couple` — the couple as an *authorization relationship*, never an
  account identity (R9.4), with its PENDING → ACTIVE → DISCONNECTED lifecycle
  timestamps.
* :class:`CoupleMember` — a user's membership in a couple. ``role`` is
  **immutable** once assigned (06-authorization-matrix.md §8, §20).
* :class:`CoupleInvitation` — a single-purpose, time-limited invitation that
  stores only a secure ``token_hash`` of an unpredictable token (R10.1); the raw
  token is returned once and never persisted.
* :class:`PrivateReflection` — the private-data boundary example the
  authorization layer must protect. ``user_id`` is the immutable **owner**
  (Pattern A); ``couple_id`` is context only and never makes content shared
  (R16.4); ``visibility_scope`` is always ``PRIVATE_PARTNER`` in the Foundation
  (R16.5).

SQLAlchemy 2.0 declarative-typed mapping. Enum columns are backed by the shared
value sets in :mod:`app.enums`. Uniqueness (e.g. ``UNIQUE(couple_id, user_id)``,
the partial unique index for at-most-one-ACTIVE-couple, and the unique
``token_hash`` index) is authored in the initial migration (task 2.3);
immutability expectations are documented inline here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Enum as SAEnum
from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.enums import (
    Couple_Status,
    Invitation_Status,
    Member_Role,
    Member_Status,
    Visibility_Scope,
)


class Couple(Base):
    """A couple relationship (design.md "Couple", 02-database-schema.md §6).

    A couple is treated strictly as an authorization relationship and never as
    an account (R9.4). ``status`` is server-controlled only (R13.7): it starts
    PENDING on creation, becomes ACTIVE when an invitation is accepted, and moves
    to DISCONNECTED on disconnect, with the corresponding timestamps recorded.
    """

    __tablename__ = "couples"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[Couple_Status] = mapped_column(
        SAEnum(Couple_Status, name="couple_status"),
        nullable=False,
        default=Couple_Status.PENDING,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    # Set when the couple transitions to ACTIVE / DISCONNECTED respectively.
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Couple id={self.id!s} status={self.status!s}>"


class CoupleMember(Base):
    """Membership of a user in a couple (design.md "CoupleMember", §7).

    ``role`` (:class:`~app.enums.Member_Role`) is **immutable** once assigned —
    couple roles are not transferable in this slice
    (06-authorization-matrix.md §8, §20). ``UNIQUE(couple_id, user_id)`` and the
    partial unique index on ``user_id WHERE status = ACTIVE`` (at-most-one-ACTIVE
    couple, R9.2/R9.3/R11.2) are added in task 2.3.
    """

    __tablename__ = "couple_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    couple_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # IMMUTABLE once assigned (06-authorization-matrix.md §8, §20). No update
    # path sets this after creation; enforced by convention + review here and
    # documented in the migration (task 2.3).
    role: Mapped[Member_Role] = mapped_column(
        SAEnum(Member_Role, name="member_role"), nullable=False
    )
    status: Mapped[Member_Status] = mapped_column(
        SAEnum(Member_Status, name="member_status"),
        nullable=False,
        default=Member_Status.ACTIVE,
    )

    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    left_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<CoupleMember id={self.id!s} couple_id={self.couple_id!s} "
            f"user_id={self.user_id!s} role={self.role!s} status={self.status!s}>"
        )


class CoupleInvitation(Base):
    """A couple invitation (design.md "CoupleInvitation", §8, §36, §37).

    Only a secure hash of an unpredictable token is stored in ``token_hash``
    (R10.1); the raw token is returned once at creation and never persisted. A
    unique index on ``token_hash`` (one invitation per token) is added in
    task 2.3. ``expires_at`` is set in the future at creation (R10.2); acceptance
    and terminal transitions record their timestamps.
    """

    __tablename__ = "couple_invitations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    couple_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    inviter_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    # Clearly identifies the invitee (R10.4).
    invitee_identifier: Mapped[str] = mapped_column(String(320), nullable=False)

    # Only a secure hash is stored (R10.1); the raw token is never persisted.
    # A unique index is added in task 2.3.
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    status: Mapped[Invitation_Status] = mapped_column(
        SAEnum(Invitation_Status, name="invitation_status"),
        nullable=False,
        default=Invitation_Status.PENDING,
    )

    expires_at: Mapped[datetime] = mapped_column(  # future at creation (R10.2)
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    declined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Stamped when a PENDING invitation is lazily materialised as EXPIRED on
    # access (R12.3); mirrors accepted_at/declined_at/revoked_at.
    expired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<CoupleInvitation id={self.id!s} couple_id={self.couple_id!s} "
            f"status={self.status!s}>"
        )


class PrivateReflection(Base):
    """Private-data boundary example (design.md "PrivateReflection", §9).

    Present only to give the authorization layer a concrete private resource to
    protect; authoring workflows are Phase 2.

    * ``user_id`` is the **immutable OWNER** — the authorization key for
      Pattern A (PRIVATE_PARTNER owner check). Ownership does not change after
      creation (06-authorization-matrix.md §8, §20).
    * ``couple_id`` is nullable and **context only**; its presence never makes
      the content shared (R16.4).
    * ``visibility_scope`` is resolved from this row and is always
      ``PRIVATE_PARTNER`` in the Foundation (R16.5); it is never inferred from
      ``couple_id``.
    * Content is stored as ciphertext (``content_ciphertext``) with searchable
      metadata kept separate (``content_metadata``).
    """

    __tablename__ = "private_reflections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # OWNER — IMMUTABLE authorization key (Pattern A). No update path changes
    # this after creation (06-authorization-matrix.md §8, §20).
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Context only; nullable. Does NOT make the content shared (R16.4).
    couple_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Always PRIVATE_PARTNER in the Foundation (R16.5). Resolved from the row,
    # never inferred from couple_id.
    visibility_scope: Mapped[Visibility_Scope] = mapped_column(
        SAEnum(Visibility_Scope, name="visibility_scope"),
        nullable=False,
        default=Visibility_Scope.PRIVATE_PARTNER,
    )

    # Encrypted at rest; metadata kept separate from ciphertext.
    content_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<PrivateReflection id={self.id!s} user_id={self.user_id!s} "
            f"visibility_scope={self.visibility_scope!s}>"
        )


__all__ = ["Couple", "CoupleMember", "CoupleInvitation", "PrivateReflection"]
