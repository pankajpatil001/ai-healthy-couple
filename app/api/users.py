"""Account endpoints: own profile, settings, and deletion request.

These routes drive the :class:`~app.users.service.AccountService` through the
request pipeline. All three are sensitive and require a resolved
:class:`CurrentActor`; the account-deletion request additionally requires a
re-auth grant (a Sensitive_Operation, R8.1/R5.3). Every response uses the
``{"data": ...}`` success envelope.

The service decides authorization from the *server-resolved* actor alone: profile
and settings are always the caller's own (there is no path to name another user,
R6.1/R6.4), and no endpoint accepts a client-supplied ``account_status`` — the
settings schema rejects it outright (R7.4).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.dependencies import (
    CurrentActor,
    DbSession,
    RequestId,
    get_account_service,
    rate_limit,
)
from app.api.envelope import envelope
from app.api.grants import parse_reauth_grant
from app.auth.service import Sensitive_Operation
from app.errors import ReauthRequiredError
from app.users.schemas import SettingsUpdate
from app.users.service import AccountService

router = APIRouter(prefix="/account", tags=["account"])


class _DeletionRequestBody(BaseModel):
    """Body for an account-deletion request.

    Carries only the re-auth grant string minted by ``/auth/reauth`` for the
    ``ACCOUNT_DELETION_REQUEST`` operation. Nothing else is accepted — the
    deletion is server-orchestrated (R8.1); the client supplies only the proof
    that it recently re-authenticated.
    """

    model_config = ConfigDict(extra="forbid")

    reauth_grant: str = Field(min_length=1)


@router.get(
    "/profile",
    dependencies=[Depends(rate_limit("resource-read"))],
)
def get_profile(
    actor: CurrentActor,
    account: Annotated[AccountService, Depends(get_account_service)],
) -> dict:
    """Return the caller's own profile (R6.1).

    The profile is resolved by the actor's own server-side ``user_id``, so a
    caller can only ever read themselves; the ``auth_identifier`` is never
    included (R1.5).
    """
    profile = account.get_own_profile(actor)
    return envelope(profile)


@router.patch("/settings")
def update_settings(
    body: SettingsUpdate,
    actor: CurrentActor,
    account: Annotated[AccountService, Depends(get_account_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Update the caller's own settings (R6.2, R6.4).

    Only product-mutable fields are accepted; a client-supplied
    ``account_status`` (or any unknown field) is rejected by the schema (R7.4).
    The updated profile is returned.
    """
    profile = account.update_own_settings(actor, body, request_id=request_id)
    session.commit()
    return envelope(profile)


@router.post("/deletion-request", status_code=status.HTTP_202_ACCEPTED)
def request_deletion(
    body: _DeletionRequestBody,
    actor: CurrentActor,
    account: Annotated[AccountService, Depends(get_account_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Request account deletion after re-authentication (R8.1).

    Account deletion is a Sensitive_Operation (R5.3): the caller must present a
    re-auth grant minted for ``ACCOUNT_DELETION_REQUEST``. A missing / malformed
    grant is treated as no re-auth and denied with 403 ``REAUTH_REQUIRED``
    (R5.2) before any request row is created; the service consumes a valid grant
    (single-use) and records a content-free ``DATA_DELETION_REQUESTED`` event.
    """
    grant = parse_reauth_grant(
        body.reauth_grant, Sensitive_Operation.ACCOUNT_DELETION_REQUEST
    )
    if grant is None:
        # No usable grant presented — fail closed exactly like a bad grant.
        raise ReauthRequiredError()
    deletion = account.request_account_deletion(actor, grant, request_id=request_id)
    session.commit()
    return envelope(
        {"deletion_request_id": str(deletion.id), "status": deletion.status.value}
    )


__all__ = ["router"]
