"""Authorization module value objects.

The Authorization layer owns no database tables (design.md "Logical modules":
*"a distinct logical layer, not a module owning tables"*). This module holds the
value objects the policy pipeline consumes and produces:

* :class:`AuthenticatedActor` — the session-resolved actor: a ``user_id`` plus
  the server-side :class:`~app.enums.Account_Status`. This is the *only* trusted
  identity input; client-supplied identity claims are never used (R14.2, R17.1).
* :class:`ResourceDescriptor` — the sensitive resource's authorization-relevant
  facts, **resolved from server state**: its ``visibility_scope`` (read from the
  resource row, never inferred from ``couple_id`` — R16.4), the immutable
  ``owner_id`` (Pattern A key), and the associated ``couple_id`` (context for
  Pattern B).
* :class:`Decision` — the single ALLOW / DENY outcome, DENY carrying a
  machine-readable :class:`DenyReason` and an ``http_hint``.

These are plain, immutable dataclasses: the pipeline is a pure decision function
over well-defined domain state (design.md "Testing Strategy"), so its inputs and
output are values, not ORM rows. Mapping a :class:`Decision` to a concrete HTTP
response / typed error is task 4.3; here the :class:`Decision` merely *carries*
an ``http_hint`` so that mapping has a stable, privacy-safe signal to translate.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass

from app.enums import Account_Status, Visibility_Scope


class Action(str, enum.Enum):
    """The action an actor attempts against a resource.

    The Foundation zone rules (Pattern A / Pattern B) are the same for every
    action — ownership / active-membership gate read *and* write alike (R16.1–
    R16.3). ``action`` is carried through the pipeline for auditing and for
    future per-action refinement, not to relax the zone rule.
    """

    READ = "READ"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class DenyReason(str, enum.Enum):
    """Why a request was denied — a stable, content-free classification.

    These are *internal* reasons the pipeline emits; the API layer (task 4.3)
    maps them to privacy-safe HTTP semantics. They never leak ownership or
    existence, and are safe to record in an audit event (R19.3, R19.4).
    """

    #: Actor's account is not ACTIVE (SUSPENDED / DELETED) — pipeline step 1
    #: denies before any resource is resolved (R7.2, R7.3, R3.6).
    ACCOUNT_NOT_ACTIVE = "ACCOUNT_NOT_ACTIVE"

    #: The resource could not be resolved from server state (missing / unknown).
    #: Treated as a privacy-safe not-found (R17.3, R17.4).
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"

    #: PRIVATE_PARTNER zone and actor is not the owner (Pattern A). Privacy-safe
    #: not-found so ownership/existence is never disclosed (R15.3, R16.x, R17.2).
    NOT_OWNER = "NOT_OWNER"

    #: SHARED_COUPLE zone and actor is not an active member of the couple
    #: (Pattern B). Privacy-safe not-found for non-members (R15.4, R17.4).
    NOT_ACTIVE_MEMBER = "NOT_ACTIVE_MEMBER"

    #: SHARED_COUPLE zone but the couple is not ACTIVE (PENDING / DISCONNECTED):
    #: lifecycle denies collaborative access (R13.4, R13.5).
    COUPLE_NOT_ACTIVE = "COUPLE_NOT_ACTIVE"

    #: SYSTEM_ONLY zone — never reachable by a normal user (R15.5).
    SYSTEM_ONLY = "SYSTEM_ONLY"

    #: PROFESSIONAL_SHARED zone — the consent workflow is out of scope in the
    #: Foundation, so the zone denies unconditionally (R15.6).
    PROFESSIONAL_SHARED = "PROFESSIONAL_SHARED"

    #: The decision could not be established with confidence — default-deny
    #: (R15.2). Covers unknown/unclassifiable zones and any gap in the pipeline.
    UNDECIDABLE = "UNDECIDABLE"


# HTTP hints the pipeline attaches to a Decision. The endpoint layer (task 4.3)
# performs the authoritative mapping to typed errors / response bodies; these
# constants keep the hint privacy-safe and consistent at the source.
HTTP_UNAUTHENTICATED = 401  # no/invalid/expired session (R18.1)
HTTP_FORBIDDEN = 403  # authenticated but forbidden, existence safe (R18.2)
HTTP_NOT_FOUND = 404  # Privacy_Safe_Response — existence would leak (R17.3/4, R18.3)


@dataclass(frozen=True, slots=True)
class AuthenticatedActor:
    """The session-resolved actor: a server-side identity, never client-claimed.

    ``user_id`` is resolved from the session server-side (never from a request
    body / URL), and ``account_status`` is re-read from the server on each
    request so SUSPENDED / DELETED accounts fail closed (R7.2, R7.3). No other
    identity claim influences authorization (R14.2, R17.1).
    """

    user_id: uuid.UUID
    account_status: Account_Status

    @property
    def is_account_active(self) -> bool:
        """True only when the account is ACTIVE (pipeline step 1, R7.2/R7.3)."""
        return self.account_status == Account_Status.ACTIVE


@dataclass(frozen=True, slots=True)
class ResourceDescriptor:
    """Authorization-relevant facts about a resource, resolved from server state.

    Every field here is derived from the authoritative server row, not from the
    request:

    * ``visibility_scope`` is read directly from the resource row. It is the
      single source of truth for the zone; the pipeline NEVER infers "shared"
      from the mere presence of a ``couple_id`` (R16.4).
    * ``owner_id`` is the resource's immutable owner (Pattern A key). Required
      for PRIVATE_PARTNER; may be ``None`` for zones without a personal owner.
    * ``couple_id`` is the couple the resource belongs to (Pattern B context);
      resolved from the row, and only meaningful for SHARED_COUPLE.
    * ``resource_id`` / ``resource_type`` are carried for auditing only and have
      no bearing on the decision — mutating a client-supplied id cannot widen
      access (R17.1, R17.2).
    """

    visibility_scope: Visibility_Scope
    owner_id: uuid.UUID | None = None
    couple_id: uuid.UUID | None = None
    resource_id: uuid.UUID | None = None
    resource_type: str | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """The single ALLOW / DENY outcome of the authorization pipeline.

    An ALLOW carries no reason. A DENY carries a content-free :class:`DenyReason`
    and an ``http_hint`` (one of :data:`HTTP_UNAUTHENTICATED`,
    :data:`HTTP_FORBIDDEN`, :data:`HTTP_NOT_FOUND`) that the endpoint layer
    (task 4.3) translates into a privacy-safe response.
    """

    allowed: bool
    reason: DenyReason | None = None
    http_hint: int | None = None

    @classmethod
    def allow(cls) -> "Decision":
        """Construct an ALLOW decision."""
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: DenyReason, http_hint: int) -> "Decision":
        """Construct a DENY decision carrying a reason and an HTTP hint."""
        return cls(allowed=False, reason=reason, http_hint=http_hint)

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        """A Decision is truthy iff it ALLOWs, so ``if decision:`` reads naturally."""
        return self.allowed


__all__ = [
    "Action",
    "DenyReason",
    "AuthenticatedActor",
    "ResourceDescriptor",
    "Decision",
    "HTTP_UNAUTHENTICATED",
    "HTTP_FORBIDDEN",
    "HTTP_NOT_FOUND",
]
