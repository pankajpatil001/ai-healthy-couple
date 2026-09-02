"""Couples module request/response schemas (Pydantic).

Couple view, invitation create/accept payloads, and the raw-token response
(returned once, never persisted). This task (9.1) defines :class:`CoupleView` —
the response projection returned by
:meth:`~app.couples.service.CoupleService.get_couple` and ``create_couple``.

``Couple_Status`` is **server-controlled only** (R13.7): it is created PENDING,
becomes ACTIVE on invitation acceptance, and DISCONNECTED on disconnect, always
through server-side lifecycle operations. :class:`CoupleView` is therefore a
read-only *response* view — it carries the current status so callers can render
it, but there is **no create/update request schema here that accepts a
client-supplied status**. A couple is an authorization relationship, never an
account (R9.4), so the view exposes only relationship facts.

Design references:
- design.md "Couples module" — CoupleService (R9.1, R9.5, R17.3)
- 02-database-schema.md §6 (couples)
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.enums import Couple_Status


class InvitationCreate(BaseModel):
    """Request payload to create a couple invitation (R10.4).

    Carries *only* the invitee reference (``invitee_identifier``) — the thing
    that "clearly identifies the Invitee" (R10.4). Everything else about an
    invitation is server-controlled and therefore deliberately absent from this
    schema:

    * there is **no** ``status`` field — status is server-set to PENDING (R10.2,
      R13.7 style);
    * there is **no** ``token``/``token_hash`` field — the token is generated
      server-side, only its hash is persisted, and the raw value is returned
      exactly once (R10.1);
    * there is **no** ``expires_at`` field — the expiry is assigned server-side
      in the future (R10.2).

    A client can never smuggle any of those in: they are not modelled here and
    ``extra`` inputs are ignored by the service, which reads only
    ``invitee_identifier``.
    """

    model_config = ConfigDict(extra="forbid")

    #: Clearly identifies the invitee (R10.4); e.g. the partner's email/handle.
    invitee_identifier: str = Field(min_length=1, max_length=320)


class RawInvitationToken(BaseModel):
    """The raw invitation token, returned to the inviter exactly once (R10.1).

    The System stores only a secure *hash* of the token
    (:class:`~app.couples.models.CoupleInvitation.token_hash`); the reusable raw
    value is never persisted. This response is the single moment the raw token
    exists outside the client's hands — the inviter shares it out-of-band with
    the invitee, who presents it back on acceptance. ``invitation_id`` and
    ``expires_at`` are included so the inviter can reference and reason about the
    invitation without re-deriving the token.
    """

    model_config = ConfigDict(from_attributes=True)

    #: The unpredictable raw token. Present only in this response; never stored.
    raw_token: str
    invitation_id: uuid.UUID
    expires_at: datetime


class CoupleView(BaseModel):
    """A couple as returned to an active member (R9.1, R17.3).

    A read-only projection built from the :class:`~app.couples.models.Couple`
    row (``from_attributes``). ``status`` is included as a server-controlled,
    read-only field — the client can never *set* it (R13.7); there is no request
    schema that accepts it. Only an active member ever receives this view; the
    membership check in
    :meth:`~app.couples.service.CoupleService.get_couple` guarantees that, and a
    non-member gets a privacy-safe not-found instead (R17.3).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: Couple_Status
    created_at: datetime
    activated_at: datetime | None = None
    disconnected_at: datetime | None = None


__all__ = ["CoupleView", "InvitationCreate", "RawInvitationToken"]
