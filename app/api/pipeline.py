"""Request-pipeline primitives: rate limiting, token parsing, and request ids.

This module implements the front of the design's "Layered request pipeline"
(design.md): **Rate limiter -> Authentication middleware -> Authorization policy
layer -> Domain service layer**. It holds the pieces that are pure enough to
unit-test in isolation; the FastAPI wiring that turns them into request
dependencies lives in :mod:`app.api.dependencies`.

Three concerns live here:

* :class:`RateLimiter` — a Redis-backed **fixed-window** limiter keyed via
  :func:`app.redis.rate_limit_key`, sized by
  :attr:`~app.config.Settings.rate_limit_window_seconds` /
  :attr:`~app.config.Settings.rate_limit_max_requests`. On a *repeated*
  over-limit for a resource scope it emits
  :meth:`~app.audit.service.AuditService.record_enumeration_suspected` — the
  enumeration-abuse signal (R17.5). It **degrades gracefully**: if Redis is
  unavailable the limiter fails *open* (allows the request) rather than taking
  the API down, so liveness/health never depends on the rate-limit store.

* :func:`parse_session_token` — extracts the opaque
  :class:`~app.auth.service.SessionToken` from the request. The wire scheme is
  ``Authorization: Bearer <session_id>.<token>`` (see :data:`AUTH_SCHEME`): both
  halves are the opaque, server-side-only references issued by
  :class:`~app.auth.service.SessionService`; neither carries account data (R2.4).
  Identity is *never* taken from a client-supplied body/claim — only from the
  server-side session the token resolves to (R2.3, R14.3).

* :func:`extract_request_id` — reads/propagates an ``X-Request-ID`` for audit
  correlation, generating a uuid4 when absent (R17.5 correlation).

Requirements: R2.3, R3.2, R3.6 (auth resolution), R14.3 (auth != authz),
R17.5 (enumeration signal + request-id correlation).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.audit.service import AuditService
from app.auth.service import SessionToken
from app.config import Settings, get_settings
from app.redis import rate_limit_key

# ---------------------------------------------------------------------------
# Wire conventions
# ---------------------------------------------------------------------------

#: Authorization scheme carrying the opaque Session_Token. The credential is
#: ``<session_id>.<token>`` — the two opaque halves issued by SessionService,
#: joined by a single dot. Both are server-side-only references (R2.3/R2.4).
AUTH_SCHEME = "Bearer"

#: Header used to propagate a request id for audit correlation (R17.5). If the
#: client does not supply one, the pipeline generates a uuid4.
REQUEST_ID_HEADER = "X-Request-ID"

#: Separator between the session id and the token inside the bearer credential.
_TOKEN_SEPARATOR = "."


# ---------------------------------------------------------------------------
# Request id (R17.5 correlation)
# ---------------------------------------------------------------------------


def extract_request_id(header_value: str | None) -> str:
    """Return a request id for audit correlation.

    Propagates a client-supplied ``X-Request-ID`` when present and non-empty;
    otherwise generates a fresh uuid4. The value is opaque and used only to
    correlate audit events for one request (R17.5) — it never influences
    authentication or authorization.
    """
    if header_value:
        trimmed = header_value.strip()
        if trimmed:
            return trimmed
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Session-token parsing (R2.3, R14.3)
# ---------------------------------------------------------------------------


def parse_session_token(authorization_header: str | None) -> SessionToken | None:
    """Parse ``Authorization: Bearer <session_id>.<token>`` into a SessionToken.

    Returns ``None`` when the header is missing, uses a different scheme, or is
    malformed (no dot, or an empty half). A ``None`` result means *no usable
    credential was presented*; the caller treats that as unauthenticated for a
    protected route. Parsing never trusts the contents for identity — the token
    is opaque and must still be resolved server-side by
    :meth:`SessionService.authenticate` (R2.3).
    """
    if not authorization_header:
        return None

    parts = authorization_header.split(" ", 1)
    if len(parts) != 2:
        return None

    scheme, credential = parts[0].strip(), parts[1].strip()
    if scheme.lower() != AUTH_SCHEME.lower() or not credential:
        return None

    session_id, sep, token = credential.partition(_TOKEN_SEPARATOR)
    if not sep or not session_id or not token:
        return None

    return SessionToken(session_id=session_id, token=token)


# ---------------------------------------------------------------------------
# Rate limiting (R17.5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of one :meth:`RateLimiter.check` call.

    ``allowed`` is the gate the dependency enforces. ``count`` is the number of
    hits observed in the current window (post-increment) and ``degraded`` marks
    the fail-open path taken when the rate-limit store was unreachable, so a
    caller/test can distinguish "under limit" from "limiter unavailable".
    """

    allowed: bool
    count: int
    degraded: bool = False


class RateLimiter:
    """Redis-backed fixed-window rate limiter with an enumeration-abuse signal.

    A fixed window of :attr:`Settings.rate_limit_window_seconds` seconds allows
    up to :attr:`Settings.rate_limit_max_requests` hits per ``(scope,
    identifier)`` pair. The counter lives at
    :func:`app.redis.rate_limit_key(scope, identifier)` and is created with a TTL
    equal to the window on first hit, so the window rolls forward on its own.

    **Enumeration signal (R17.5):** repeated over-limit hits on a *resource*
    scope look like id-guessing/enumeration. Once the count crosses the limit the
    limiter records
    :meth:`AuditService.record_enumeration_suspected` — but only for scopes in
    :attr:`enumeration_scopes` and only *once per window* (on the first hit past
    the limit) so a flood produces one signal, not thousands.

    **Graceful degradation:** every Redis interaction is guarded; on any error
    the limiter **fails open** (``allowed=True``, ``degraded=True``). Rate
    limiting is a protective overlay, not a correctness gate, and health/liveness
    must never depend on Redis being up.
    """

    #: Scopes whose over-limit bursts are treated as possible enumeration and so
    #: raise the R17.5 audit signal. Auth scopes (login/recovery) are rate
    #: limited too but are brute-force, not enumeration, so they are excluded.
    DEFAULT_ENUMERATION_SCOPES = frozenset({"resource-read", "resource"})

    def __init__(
        self,
        redis_client,
        audit_service: AuditService,
        *,
        settings: Settings | None = None,
        enumeration_scopes: frozenset[str] | None = None,
    ) -> None:
        self._redis = redis_client
        self._audit = audit_service
        self._settings = settings or get_settings()
        self._enumeration_scopes = (
            enumeration_scopes
            if enumeration_scopes is not None
            else self.DEFAULT_ENUMERATION_SCOPES
        )

    @property
    def enumeration_scopes(self) -> frozenset[str]:
        """Scopes for which an over-limit burst raises the enumeration signal."""
        return self._enumeration_scopes

    def check(
        self,
        scope: str,
        identifier: str,
        *,
        actor_id: uuid.UUID | None = None,
        resource_type: str | None = None,
        request_id: str | None = None,
    ) -> RateLimitResult:
        """Register one hit for ``(scope, identifier)`` and report if it's allowed.

        Increments the fixed-window counter (creating it with the window TTL on
        the first hit). Returns ``allowed=False`` once the count exceeds
        :attr:`Settings.rate_limit_max_requests`. On the *first* rejected hit of
        a window for an enumeration-relevant scope, records the R17.5
        enumeration-suspected audit event with the running ``attempt_count``.

        Fails **open** (``allowed=True, degraded=True``) if the rate-limit store
        cannot be reached, so the API stays available when Redis is down.
        """
        window = self._settings.rate_limit_window_seconds
        limit = self._settings.rate_limit_max_requests
        key = rate_limit_key(scope, identifier, self._settings)

        try:
            count = int(self._redis.incr(key))
            if count == 1:
                # First hit in a new window — arm the TTL so the window expires.
                self._redis.expire(key, window)
        except Exception:  # noqa: BLE001 — any client/connection error: fail open.
            # Degrade gracefully: never let the protective overlay break requests
            # or health checks when Redis is unavailable.
            return RateLimitResult(allowed=True, count=0, degraded=True)

        if count <= limit:
            return RateLimitResult(allowed=True, count=count)

        # Over the limit. Emit the enumeration signal once per window (exactly on
        # the first hit past the limit) for enumeration-relevant scopes (R17.5).
        if count == limit + 1 and scope in self._enumeration_scopes:
            self._audit.record_enumeration_suspected(
                actor_id=actor_id,
                resource_type=resource_type or scope,
                request_id=request_id,
                attempt_count=count,
            )

        return RateLimitResult(allowed=False, count=count)


__all__ = [
    "AUTH_SCHEME",
    "REQUEST_ID_HEADER",
    "RateLimiter",
    "RateLimitResult",
    "extract_request_id",
    "parse_session_token",
]
