"""Shared enumerations for the Foundation slice.

These are the Foundation-constrained value sets referenced throughout the
design's "Enumerations" section. They live in one shared module so every
domain module (users, couples, authorization, audit) and the test strategies
depend on a single source of truth rather than redefining literals.

All enums subclass ``str`` (via ``str, Enum``) so their members serialize as
plain strings and map cleanly onto SQLAlchemy ``Enum`` columns and Pydantic
schemas: ``Account_Status.ACTIVE == "ACTIVE"`` and the value stored in the
database is the member name.

Design references:
- design.md "Enumerations" (Foundation-constrained value sets)
- R7.1  — Account_Status is exactly one of ACTIVE | SUSPENDED | DELETED
- R13.1 — Couple_Status is exactly one of PENDING | ACTIVE | DISCONNECTED
- R15.1 — Visibility_Zone is exactly one of PRIVATE_PARTNER | SHARED_COUPLE |
          PROFESSIONAL_SHARED | SYSTEM_ONLY

Each set is intentionally the *Foundation subset*; broader product states
(e.g. subscription or professional-support lifecycle) are out of scope here.
"""

from __future__ import annotations

from enum import Enum


class Account_Status(str, Enum):
    """Lifecycle state of a User account (Foundation subset). R7.1.

    Server-controlled only; clients never supply this value (R7.4).
    """

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DELETED = "DELETED"


class Couple_Status(str, Enum):
    """Lifecycle state of a Couple (Foundation subset). R13.1.

    A couple starts PENDING on creation, becomes ACTIVE when an invitation is
    accepted, and moves to DISCONNECTED on disconnect. Server-controlled only.
    """

    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"


class Member_Role(str, Enum):
    """Role of a member within a Couple. Immutable once assigned.

    PARTNER_A is the couple creator; PARTNER_B is the invitee who accepts.
    """

    PARTNER_A = "PARTNER_A"
    PARTNER_B = "PARTNER_B"


class Member_Status(str, Enum):
    """Membership state of a CoupleMember (Foundation subset).

    Mirrors the couple lifecycle: ACTIVE while collaborating, DISCONNECTED
    once the couple is disconnected.
    """

    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"


class Invitation_Status(str, Enum):
    """Lifecycle state of a Couple_Invitation.

    PENDING invitations may be accepted (ACCEPTED), declined by the invitee
    (DECLINED), revoked by the inviter (REVOKED), or lazily expired (EXPIRED)
    once ``expires_at`` has passed.
    """

    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class Visibility_Scope(str, Enum):
    """Visibility zone classifying every sensitive resource. R15.1.

    Exactly one zone applies to each resource. The authorization pipeline
    resolves this from the resource row itself and never infers "shared" from
    the presence of a ``couple_id`` (R16.4). PROFESSIONAL_SHARED and SYSTEM_ONLY
    are deny-by-default in the Foundation slice.
    """

    PRIVATE_PARTNER = "PRIVATE_PARTNER"
    SHARED_COUPLE = "SHARED_COUPLE"
    PROFESSIONAL_SHARED = "PROFESSIONAL_SHARED"
    SYSTEM_ONLY = "SYSTEM_ONLY"


class Deletion_Status(str, Enum):
    """Lifecycle state of a DataDeletionRequest."""

    REQUESTED = "REQUESTED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


__all__ = [
    "Account_Status",
    "Couple_Status",
    "Member_Role",
    "Member_Status",
    "Invitation_Status",
    "Visibility_Scope",
    "Deletion_Status",
]
