"""Couple and invitation endpoints.

These routes drive the :class:`~app.couples.service.CoupleService` and
:class:`~app.couples.service.InvitationService` through the request pipeline.
Every route is sensitive and requires a resolved :class:`CurrentActor`; the
couple *disconnect* additionally requires a re-auth grant (a Sensitive_Operation,
R13.2/R5.3). Every response uses the ``{"data": ...}`` success envelope.

Authorization is decided inside the services from server state alone: a
non-member — and, identically, a caller naming a couple / invitation that does
not exist — receives a privacy-safe 404, so a route never confirms a resource's
existence to someone not entitled to know (R17.3). No route accepts a
client-supplied ``status`` or token hash: statuses are server-controlled (R13.7)
and only the secure hash of an invitation token is ever stored (R10.1).

State-transition routes are modelled as explicit operations
(``POST .../disconnect``, ``POST .../decline``, ``POST .../cancel``) rather than
a client-set status, per 03-api-contracts.md §2.2.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.dependencies import (
    CurrentActor,
    DbSession,
    RequestId,
    get_couple_service,
    get_invitation_service,
    rate_limit,
)
from app.api.envelope import envelope
from app.api.grants import parse_reauth_grant
from app.auth.service import Sensitive_Operation
from app.couples.schemas import InvitationCreate
from app.couples.service import CoupleService, InvitationService
from app.errors import ReauthRequiredError

router = APIRouter(tags=["couples"])


# ---------------------------------------------------------------------------
# Request models — statuses/tokens are server-controlled, never client input.
# ---------------------------------------------------------------------------


class _DisconnectBody(BaseModel):
    """Body for a couple disconnect: only the re-auth grant string (R13.2)."""

    model_config = ConfigDict(extra="forbid")

    reauth_grant: str = Field(min_length=1)


class _AcceptInvitationBody(BaseModel):
    """Body to accept an invitation: the raw token received out-of-band (R11.1).

    Only the raw token is accepted; the server looks the invitation up by the
    *hash* of this value (the raw token is never persisted, R10.1) and decides
    acceptability entirely from server state.
    """

    model_config = ConfigDict(extra="forbid")

    raw_token: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Couples
# ---------------------------------------------------------------------------


@router.post("/couples", status_code=status.HTTP_201_CREATED)
def create_couple(
    actor: CurrentActor,
    couples: Annotated[CoupleService, Depends(get_couple_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Create a PENDING couple with the caller enrolled as PARTNER_A (R9.1).

    An actor who already has an ACTIVE couple is rejected with 409
    ``ACTIVE_COUPLE_EXISTS`` (R9.2/R9.3, enforced by the database index).
    """
    view = couples.create_couple(actor, request_id=request_id)
    session.commit()
    return envelope(view)


@router.get(
    "/couples/{couple_id}",
    dependencies=[Depends(rate_limit("resource-read"))],
)
def get_couple(
    couple_id: uuid.UUID,
    actor: CurrentActor,
    couples: Annotated[CoupleService, Depends(get_couple_service)],
) -> dict:
    """Return a couple only to an active member; else a privacy-safe 404 (R17.3).

    The path ``couple_id`` is untrusted: it only ever narrows to a couple the
    actor is already an active member of, so a guessed / swapped id cannot widen
    access. The resource-read rate limit bounds id-enumeration bursts (R17.5).
    """
    view = couples.get_couple(actor, couple_id)
    return envelope(view)


@router.post("/couples/{couple_id}/disconnect")
def disconnect_couple(
    couple_id: uuid.UUID,
    body: _DisconnectBody,
    actor: CurrentActor,
    couples: Annotated[CoupleService, Depends(get_couple_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Disconnect an ACTIVE couple after re-authentication (R13.2).

    Two server-side gates must both pass: the actor must be an ACTIVE member
    (non-members get a privacy-safe 404, so the re-auth path never leaks a
    couple's existence), and a valid single-use re-auth grant minted for
    ``COUPLE_DISCONNECTION`` must be presented. A missing / malformed grant is
    denied with 403 ``REAUTH_REQUIRED`` (R5.2).
    """
    grant = parse_reauth_grant(
        body.reauth_grant, Sensitive_Operation.COUPLE_DISCONNECTION
    )
    if grant is None:
        raise ReauthRequiredError()
    view = couples.disconnect_couple(actor, couple_id, grant, request_id=request_id)
    session.commit()
    return envelope(view)


# ---------------------------------------------------------------------------
# Invitations
# ---------------------------------------------------------------------------


@router.post("/couples/{couple_id}/invitations", status_code=status.HTTP_201_CREATED)
def create_invitation(
    couple_id: uuid.UUID,
    body: InvitationCreate,
    actor: CurrentActor,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Create a PENDING invitation for a couple and return the raw token once.

    Only an ACTIVE member of a PENDING couple may invite (R10.1); non-members
    get a privacy-safe 404. The raw token is returned exactly once here — only
    its hash is persisted (R10.1).
    """
    raw = invitations.create_invitation(
        actor, couple_id, body.invitee_identifier, request_id=request_id
    )
    session.commit()
    return envelope(raw)


@router.post("/invitations/accept")
def accept_invitation(
    body: _AcceptInvitationBody,
    actor: CurrentActor,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Accept an invitation by its raw token, joining the couple as PARTNER_B (R11.1).

    A bad / expired / already-decided token yields an identical privacy-safe 404
    with no membership added (R11.3/R12.3/R12.4). If the actor already has an
    ACTIVE couple the acceptance is rejected with 409 and the invitation stays
    PENDING (R11.2).
    """
    view = invitations.accept_invitation(actor, body.raw_token, request_id=request_id)
    session.commit()
    return envelope(view)


@router.post("/invitations/{invitation_id}/decline")
def decline_invitation(
    invitation_id: uuid.UUID,
    actor: CurrentActor,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Decline a PENDING invitation as its intended invitee (R12.1).

    Only the named invitee may decline; every failure (unknown / non-PENDING
    invitation, or a non-invitee actor) is the identical privacy-safe 404 so
    declining never confirms an invitation's existence to a stranger. No
    membership is added.
    """
    invitations.decline_invitation(actor, invitation_id, request_id=request_id)
    session.commit()
    return envelope({"status": "declined"})


@router.post("/invitations/{invitation_id}/cancel")
def cancel_invitation(
    invitation_id: uuid.UUID,
    actor: CurrentActor,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Cancel (revoke) a PENDING invitation as its inviter (R12.2).

    Only the inviter may cancel; anyone else (the invitee or a stranger) gets
    the identical privacy-safe 404.
    """
    invitations.cancel_invitation(actor, invitation_id, request_id=request_id)
    session.commit()
    return envelope({"status": "cancelled"})


__all__ = ["router"]
