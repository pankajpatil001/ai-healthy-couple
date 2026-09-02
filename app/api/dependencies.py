"""FastAPI request-pipeline dependencies.

These dependencies wire the pieces from :mod:`app.api.pipeline` and the domain
services into the ordering the design mandates for every sensitive request
(design.md "Layered request pipeline")::

    Rate limiter -> Authentication middleware -> Authorization policy layer
                 -> Domain service layer -> authorized repository

Task 12.1 owns the first three stages plus the request-id correlation. The
authorization policy layer still runs *per request* inside each endpoint (via
:class:`~app.authorization.service.AuthorizationService` /
:func:`app.authorization.enforcement.enforce`) — a valid session is **never**
sufficient authorization on its own (R14.3). Endpoints and their per-resource
authorization are mounted in task 12.2.

Everything here is dependency-injectable so the pipeline is testable end to end
with a FastAPI ``TestClient`` and in-memory/fake stores:

* :func:`get_settings_dep` / :func:`get_redis` / :func:`get_db_session` —
  overridable providers for config, Redis, and the SQLAlchemy session.
* :func:`get_audit_service`, :func:`get_session_service` — service factories
  built on the above (SessionService resolves the actor server-side, R2.3/R3.6).
* :func:`get_request_id` — the per-request correlation id (R17.5).
* :func:`get_rate_limiter` — a :class:`~app.api.pipeline.RateLimiter`.
* :func:`rate_limit` — a parametrised dependency factory enforcing the limiter
  for a given scope (fails open if Redis is down; emits the enumeration signal).
* :func:`get_current_actor` — the authenticated-actor dependency: parses the
  Session_Token, resolves it via SessionService, and raises
  :class:`~app.errors.UnauthenticatedError` (401) on any failure (R2.3, R3.2,
  R3.6).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Annotated, Callable

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.api.pipeline import (
    RateLimiter,
    RateLimitResult,
    extract_request_id,
    parse_session_token,
)
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.auth.service import SessionService
from app.authorization.models import AuthenticatedActor
from app.config import Settings, get_settings
from app.db import get_session
from app.errors import AppError, UnauthenticatedError
from app.redis import get_redis_client
from app.users.repository import UserRepository


class RateLimitedError(AppError):
    """Too many requests for a rate-limited scope.

    Not part of the authorization failure table (which is 401/403/404 only); a
    429 is a transport-level protective response and its generic body reveals
    nothing about the actor or any resource. The enumeration *signal* itself is
    recorded server-side by the limiter (R17.5), never surfaced to the client.
    """

    code = "RATE_LIMITED"
    http_status = 429
    message = "Too many requests. Please retry later."

# ---------------------------------------------------------------------------
# Request state keys
# ---------------------------------------------------------------------------

#: Attribute on ``request.state`` where the middleware stashes the request id so
#: dependencies and handlers share one value per request (R17.5 correlation).
REQUEST_ID_STATE_ATTR = "request_id"

#: Rate-limit scope for authenticated resource access. Bursts on this scope look
#: like id-enumeration and so trigger the R17.5 signal (see RateLimiter).
RESOURCE_READ_SCOPE = "resource-read"


# ---------------------------------------------------------------------------
# Infrastructure providers (overridable in tests via app.dependency_overrides)
# ---------------------------------------------------------------------------


def get_settings_dep() -> Settings:
    """Provide application :class:`Settings` (overridable in tests)."""
    return get_settings()


def get_redis(
    settings: Annotated[Settings, Depends(get_settings_dep)],
):
    """Provide a Redis client for the request (overridable in tests).

    Returns the shared client built from settings. The rate limiter guards every
    call, so a returned-but-unreachable client degrades gracefully rather than
    failing the request.
    """
    return get_redis_client(settings)


def get_db_session() -> Iterator[Session]:
    """Provide a SQLAlchemy session, delegating to :func:`app.db.get_session`."""
    yield from get_session()


# ---------------------------------------------------------------------------
# Service factories
# ---------------------------------------------------------------------------


def get_audit_service(
    session: Annotated[Session, Depends(get_db_session)],
) -> AuditService:
    """Build the append-only :class:`AuditService` on the request's DB session."""
    return AuditService(AuditRepository(session))


def get_session_service(
    session: Annotated[Session, Depends(get_db_session)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> SessionService:
    """Build the :class:`SessionService` used to resolve the actor server-side.

    The session store is imported lazily so this module carries no import-time
    dependency on a live Redis connection (keeps ``app.main`` importable, and
    health checks Redis-independent). Account status is re-read from PostgreSQL
    via :class:`UserRepository` so SUSPENDED/DELETED accounts fail closed (R3.6).
    """
    from app.auth.service import RedisSessionStore

    store = RedisSessionStore(get_redis_client(settings), settings)
    return SessionService(
        store=store,
        audit_service=audit,
        user_status_lookup=UserRepository(session),
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Identity provider (process-wide for this slice)
# ---------------------------------------------------------------------------
#
# Credential material is owned by the identity provider, never the User row
# (08-technology-stack.md §9). A managed IdP replaces this in production; for the
# Foundation slice a single process-wide :class:`InMemoryIdentityProvider` is
# shared across requests so a credential registered at ``/auth/register`` is
# verifiable at ``/auth/login`` and ``/auth/reauth`` within the same process.
# It is exposed through a dependency so tests can override it with their own
# instance for isolation.

_process_identity_provider = None


def get_identity_provider():
    """Provide the process-wide identity provider (overridable in tests).

    Lazily constructs a single :class:`InMemoryIdentityProvider` shared for the
    life of the process. Tests override this via ``app.dependency_overrides`` to
    supply an isolated provider (and typically the matching in-memory stores).
    """
    global _process_identity_provider
    if _process_identity_provider is None:
        from app.auth.service import InMemoryIdentityProvider

        _process_identity_provider = InMemoryIdentityProvider()
    return _process_identity_provider


def get_authentication_service(
    session: Annotated[Session, Depends(get_db_session)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    identity_provider: Annotated[object, Depends(get_identity_provider)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
):
    """Build the :class:`AuthenticationService` for the request.

    Wires the shared identity provider with the request's DB-backed
    :class:`UserRepository`, the :class:`SessionService`, the audit service, and
    Redis-backed single-use recovery / short-lived re-auth grant stores. The
    stores are imported lazily so this module keeps no import-time Redis
    dependency (health stays Redis-independent).
    """
    from app.auth.service import (
        AuthenticationService,
        RedisReauthGrantStore,
        RedisRecoveryChallengeStore,
    )

    redis_client = get_redis_client(settings)
    return AuthenticationService(
        user_repository=UserRepository(session),
        identity_provider=identity_provider,
        session_service=session_service,
        audit_service=audit,
        recovery_store=RedisRecoveryChallengeStore(redis_client, settings),
        reauth_store=RedisReauthGrantStore(redis_client, settings),
        settings=settings,
    )


def get_account_service(
    session: Annotated[Session, Depends(get_db_session)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    authentication: Annotated[object, Depends(get_authentication_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
):
    """Build the :class:`AccountService` for the request (own profile/settings,
    deletion request)."""
    from app.users.repository import DataDeletionRequestRepository
    from app.users.service import AccountService

    return AccountService(
        user_repository=UserRepository(session),
        deletion_repository=DataDeletionRequestRepository(session),
        session_service=session_service,
        authentication_service=authentication,
        audit_service=audit,
        session=session,
    )


def get_couple_service(
    session: Annotated[Session, Depends(get_db_session)],
    authentication: Annotated[object, Depends(get_authentication_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
):
    """Build the :class:`CoupleService` for the request (create/get/disconnect)."""
    from app.couples.repository import CoupleRepository
    from app.couples.service import CoupleService

    return CoupleService(
        couple_repository=CoupleRepository(session),
        audit_service=audit,
        authentication_service=authentication,
    )


def get_invitation_service(
    session: Annotated[Session, Depends(get_db_session)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
):
    """Build the :class:`InvitationService` for the request.

    The invitee-identifier lookup is the request's :class:`UserRepository`, which
    exposes ``get_by_id`` so ``decline_invitation`` can resolve the actor's own
    ``auth_identifier`` from server state (never from the request).
    """
    from app.couples.repository import CoupleRepository
    from app.couples.service import InvitationService

    return InvitationService(
        couple_repository=CoupleRepository(session),
        audit_service=audit,
        settings=settings,
        user_lookup=UserRepository(session),
    )


# ---------------------------------------------------------------------------
# Request id (R17.5)
# ---------------------------------------------------------------------------


def get_request_id(request: Request) -> str:
    """Return this request's correlation id (R17.5).

    Prefers the value the middleware placed on ``request.state`` so the whole
    request shares one id; falls back to deriving it from the ``X-Request-ID``
    header (or a fresh uuid4) if the middleware is not installed — which keeps
    the dependency usable in isolation.
    """
    existing = getattr(request.state, REQUEST_ID_STATE_ATTR, None)
    if existing:
        return existing
    request_id = extract_request_id(request.headers.get("x-request-id"))
    setattr(request.state, REQUEST_ID_STATE_ATTR, request_id)
    return request_id


# ---------------------------------------------------------------------------
# Rate limiter (R17.5)
# ---------------------------------------------------------------------------


def get_rate_limiter(
    redis_client: Annotated[object, Depends(get_redis)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> RateLimiter:
    """Provide a :class:`RateLimiter` bound to Redis + audit + settings."""
    return RateLimiter(redis_client, audit, settings=settings)


def _client_identifier(request: Request) -> str:
    """Best-effort per-caller identifier for rate-limit bucketing.

    Uses the client host when available (the window is per source); falls back to
    a constant so a missing peer address still shares one bucket rather than
    silently disabling the limit.
    """
    client = request.client
    return client.host if client is not None else "unknown"


def rate_limit(scope: str) -> Callable[..., RateLimitResult]:
    """Build a dependency that enforces the rate limiter for ``scope``.

    Mount as the *first* dependency on a sensitive/auth route so it runs ahead of
    authentication (pipeline ordering: rate limit -> auth -> authz). The returned
    dependency:

    * registers one hit for ``(scope, client-identifier)``,
    * raises :class:`RateLimitedError` (429) on a rejected hit — a 429 is a
      transport-level protective response with a generic, privacy-safe body,
    * emits the R17.5 enumeration signal via the limiter for resource scopes,
    * and **fails open** (allows) when Redis is unavailable.

    The scope is captured per route, so different routes get independent windows.
    """

    def _dependency(
        request: Request,
        limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
        request_id: Annotated[str, Depends(get_request_id)],
    ) -> RateLimitResult:
        result = limiter.check(
            scope,
            _client_identifier(request),
            resource_type=scope,
            request_id=request_id,
        )
        if not result.allowed:
            raise RateLimitedError()
        return result

    return _dependency


# ---------------------------------------------------------------------------
# Authentication (R2.3, R3.2, R3.6, R14.3)
# ---------------------------------------------------------------------------


def get_current_actor(
    request: Request,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    authorization: Annotated[str | None, Header()] = None,
) -> AuthenticatedActor:
    """Resolve the authenticated actor from the presented Session_Token, or 401.

    Parses ``Authorization: Bearer <session_id>.<token>`` and resolves it via
    :meth:`SessionService.authenticate`, which returns ``None`` for a missing /
    invalid / expired (R3.2) / revoked session and for a non-ACTIVE account
    (R3.6). Any ``None`` — no credential, bad credential, or failed resolution —
    is mapped to :class:`~app.errors.UnauthenticatedError` (401).

    Identity comes *only* from the server-side session, never a client claim
    (R2.3). This dependency establishes *authentication*; the authorization
    policy layer still runs per request in the endpoint (R14.3) — being
    authenticated is not authorization.
    """
    token = parse_session_token(authorization)
    if token is None:
        raise UnauthenticatedError()

    actor = session_service.authenticate(token)
    if actor is None:
        raise UnauthenticatedError()
    return actor


# Convenience type aliases for endpoint signatures (task 12.2 will use these).
CurrentActor = Annotated[AuthenticatedActor, Depends(get_current_actor)]
RequestId = Annotated[str, Depends(get_request_id)]
DbSession = Annotated[Session, Depends(get_db_session)]


__all__ = [
    "REQUEST_ID_STATE_ATTR",
    "RESOURCE_READ_SCOPE",
    "RateLimitedError",
    "get_settings_dep",
    "get_redis",
    "get_db_session",
    "get_audit_service",
    "get_session_service",
    "get_identity_provider",
    "get_authentication_service",
    "get_account_service",
    "get_couple_service",
    "get_invitation_service",
    "get_request_id",
    "get_rate_limiter",
    "rate_limit",
    "get_current_actor",
    "CurrentActor",
    "RequestId",
    "DbSession",
]
