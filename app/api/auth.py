"""Auth endpoints: registration, login, logout, recovery, re-authentication.

These routes drive the :class:`~app.auth.service.AuthenticationService` /
:class:`~app.auth.service.SessionService` through the request pipeline. The
public routes (register, login, recovery initiate/complete) require **no**
session but are rate limited so brute-force / probing is bounded; the
authenticated routes (logout, reauth) require a resolved :class:`CurrentActor`.

Every response uses the ``{"data": ...}`` success envelope
(:func:`app.api.envelope.envelope`); failures are mapped centrally by the
:class:`~app.errors.AppError` handler in :mod:`app.main`, so nothing here builds
an error body.

Token transport conventions (both opaque, server-side references):

* **Session token** — returned by login as ``{"session_token":
  "<session_id>.<token>"}``, matching the ``Authorization: Bearer
  <session_id>.<token>`` scheme the pipeline parses (R2.3/R2.4).
* **Re-auth grant** — returned by ``/auth/reauth`` as ``{"reauth_grant":
  "<grant_id>.<token>", "operation_type": "..."}``. A Sensitive_Operation
  endpoint (account deletion, couple disconnect) takes that grant string back in
  its body and the server reconstructs and *consumes* it (single-use, R5.1).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.dependencies import (
    CurrentActor,
    DbSession,
    RequestId,
    get_authentication_service,
    get_session_service,
    rate_limit,
)
from app.api.envelope import envelope
from app.api.pipeline import parse_session_token
from app.auth.service import (
    AuthenticationService,
    SessionService,
    Sensitive_Operation,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Request models — never accept server-controlled fields (status/token_hash).
# ---------------------------------------------------------------------------


class _CredentialsBody(BaseModel):
    """Registration / login credentials.

    Carries only the two coordinates the identity flow needs: the
    ``auth_identifier`` and the opaque ``credential_material``. There is no
    ``status`` (accounts are created ACTIVE server-side, R7.4) and no session /
    token field — a client can never smuggle server-controlled state in.
    """

    model_config = ConfigDict(extra="forbid")

    auth_identifier: str = Field(min_length=1, max_length=320)
    credential_material: str = Field(min_length=1)


class _RecoveryInitiateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_identifier: str = Field(min_length=1, max_length=320)


class _RecoveryCompleteBody(BaseModel):
    """Complete recovery with a challenge reference + secret + new credential.

    ``challenge_id`` / ``secret`` are the two halves of the single-use challenge
    the account owner received; ``new_credential_material`` replaces the
    credential. No account status or session field is accepted.
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1)
    secret: str = Field(min_length=1)
    new_credential_material: str = Field(min_length=1)


class _ReauthBody(BaseModel):
    """Request a re-auth grant for a Sensitive_Operation (R5.1, R5.3).

    ``reauth_proof`` is a *fresh* credential proof — session possession is never
    sufficient (R5.1). ``operation_type`` names which Sensitive_Operation the
    grant will authorise; it is validated against the server-side enum.
    """

    model_config = ConfigDict(extra="forbid")

    reauth_proof: str = Field(min_length=1)
    operation_type: Sensitive_Operation


# ---------------------------------------------------------------------------
# Public routes (no session; rate limited)
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("auth-register"))],
)
def register(
    body: _CredentialsBody,
    auth: Annotated[AuthenticationService, Depends(get_authentication_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Register a new ACTIVE account (R1.1). Rate limited; no session required.

    The service validates the identifier (R1.3) and rejects a duplicate (R1.2,
    409). On success the account row is committed and a minimal view (the new
    account id — never the auth_identifier, R1.5) is returned.
    """
    user = auth.register(
        body.auth_identifier, body.credential_material, request_id=request_id
    )
    session.commit()
    return envelope({"user_id": str(user.id)})


@router.post(
    "/login",
    dependencies=[Depends(rate_limit("auth-login"))],
)
def login(
    body: _CredentialsBody,
    auth: Annotated[AuthenticationService, Depends(get_authentication_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Verify credentials and issue a session token (R2.1). Rate limited.

    On any failure a generic 401 ``AUTHENTICATION_FAILED`` is raised that never
    discloses whether the identifier exists (R2.2). On success the opaque
    session token is returned as ``<session_id>.<token>`` for the Bearer scheme.
    """
    token = auth.login(
        body.auth_identifier, body.credential_material, request_id=request_id
    )
    session.commit()
    return envelope({"session_token": f"{token.session_id}.{token.token}"})


@router.post(
    "/recovery/initiate",
    dependencies=[Depends(rate_limit("auth-recovery"))],
)
def recovery_initiate(
    body: _RecoveryInitiateBody,
    auth: Annotated[AuthenticationService, Depends(get_authentication_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Begin account recovery with an identity-non-disclosing response (R4.2).

    The response is identical whether or not the identifier maps to an account:
    a generic acknowledgement. When an account exists a single-use, time-limited
    challenge is issued and returned so a delivery channel could route it to the
    account owner; when it does not, no challenge is issued — but the caller sees
    the same shape either way (R4.2). Returning the challenge here stands in for
    the out-of-band delivery a production system performs.
    """
    challenge = auth.initiate_recovery(body.auth_identifier, request_id=request_id)
    session.commit()
    if challenge is None:
        # R4.2: identical acknowledgement for an unknown identifier.
        return envelope({"status": "recovery_initiated"})
    return envelope(
        {
            "status": "recovery_initiated",
            "challenge_id": challenge.challenge_id,
            "secret": challenge.secret,
        }
    )


@router.post(
    "/recovery/complete",
    dependencies=[Depends(rate_limit("auth-recovery"))],
)
def recovery_complete(
    body: _RecoveryCompleteBody,
    auth: Annotated[AuthenticationService, Depends(get_authentication_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Complete recovery with a valid single-use challenge (R4.3–R4.6).

    A missing / expired / already-used challenge or a mismatched secret raises a
    generic 401. On success the credential is re-established, all existing
    sessions are revoked (R4.5), and a CREDENTIAL_CHANGE event is audited.
    """
    auth.complete_recovery(
        body.challenge_id,
        body.secret,
        body.new_credential_material,
        request_id=request_id,
    )
    session.commit()
    return envelope({"status": "recovery_completed"})


# ---------------------------------------------------------------------------
# Authenticated routes (require a resolved actor)
# ---------------------------------------------------------------------------


@router.post("/logout")
def logout(
    actor: CurrentActor,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    session: DbSession,
    request_id: RequestId,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Revoke the caller's current session so its token can no longer authenticate.

    The session id is taken from the *same* Bearer credential the pipeline used
    to resolve the actor — server-side, never a client claim. Revoking deletes
    the session record so the token cannot authenticate again (R3.3) and audits
    a SESSION_REVOKED event (R3.7); it is idempotent.
    """
    token = parse_session_token(authorization)
    # get_current_actor already guaranteed a valid token resolved to this actor,
    # so parsing here yields the presenting session id.
    session_service.revoke_session(
        token.session_id, actor, request_id=request_id, reason="LOGOUT"
    )
    session.commit()
    return envelope({"status": "logged_out"})


@router.post("/reauth")
def reauth(
    body: _ReauthBody,
    actor: CurrentActor,
    auth: Annotated[AuthenticationService, Depends(get_authentication_service)],
    session: DbSession,
    request_id: RequestId,
) -> dict:
    """Verify a fresh proof and mint a single-operation re-auth grant (R5.1).

    Session possession alone is never sufficient for a Sensitive_Operation
    (R5.1): the actor must present a fresh credential proof. A missing / failing
    proof raises 403 ``REAUTH_REQUIRED`` (R5.2). On success a short-lived,
    single-operation grant bound to the actor and operation is returned as
    ``<grant_id>.<token>``; the gated endpoint presents it back and the server
    consumes it (single-use).
    """
    grant = auth.require_reauthentication(
        actor, body.reauth_proof, body.operation_type, request_id=request_id
    )
    session.commit()
    return envelope(
        {
            "reauth_grant": f"{grant.grant_id}.{grant.token}",
            "operation_type": grant.operation_type.value,
        }
    )


__all__ = ["router"]
