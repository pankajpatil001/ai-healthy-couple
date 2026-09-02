"""Map authorization :class:`Decision` outcomes to privacy-safe HTTP semantics.

Task 4.3. The :class:`~app.authorization.service.AuthorizationService` renders a
content-free ALLOW / DENY :class:`~app.authorization.models.Decision`; this
module is the single, authoritative place that translates a DENY into the typed
:class:`~app.errors.AppError` the API layer (task 12) raises. Keeping the
translation here — not scattered across endpoints — is what makes the failure
semantics *consistent across every sensitive endpoint* (R18.4).

The mapping follows the design's "Error Handling" and "IDOR / enumeration
prevention and 401/403/404 semantics" sections:

* **401 UNAUTHENTICATED** — no / invalid / expired / revoked session. The actor
  is not (or no longer) authenticated (R3.2, R18.1).
* **403 FORBIDDEN** — authenticated but disallowed, where revealing that the
  resource exists is safe (R6.4, R18.2). In the Foundation this is the
  account-lifecycle denial: a SUSPENDED / DELETED account is a *known* actor
  being refused; no third party's existence leaks.
* **404 RESOURCE_NOT_FOUND (Privacy_Safe_Response)** — when distinguishing
  "does not exist" from "exists but forbidden" would leak sensitive
  information: a private resource requested by a non-owner, or a couple /
  shared resource requested by a non-member (R17.2, R17.3, R17.4, R18.3). The
  same 404 also covers SYSTEM_ONLY / PROFESSIONAL_SHARED zones and any
  undecidable (default-deny) outcome, so a probe can never distinguish those
  internal reasons from an ordinary miss.

Every :class:`~app.authorization.models.DenyReason` maps to exactly one status,
and every mapped error carries only a generic, code-driven message: bodies never
reveal ownership ("belongs to your partner"), account existence, or resource
existence (design "Error Handling" general rules).

The pipeline also attaches an ``http_hint`` to each DENY. This module treats the
per-reason table below as authoritative but *asserts* that the hint agrees with
it, so a future drift between the pipeline and this mapping fails loudly in tests
rather than silently leaking a wrong status.
"""

from __future__ import annotations

from app.authorization.models import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    HTTP_UNAUTHENTICATED,
    Decision,
    DenyReason,
)
from app.errors import (
    AppError,
    AuthorizationError,
    ResourceNotFoundError,
    UnauthenticatedError,
)

# Authoritative DenyReason -> typed AppError mapping.
#
# Each entry names the privacy-safe error the API layer raises for that reason.
# The chosen error's ``http_status`` / ``code`` are what reach the client; the
# reason itself is internal and never serialised (R18 general rules).
_REASON_TO_ERROR: dict[DenyReason, type[AppError]] = {
    # Authenticated-but-forbidden lifecycle denial. The actor is a known,
    # authenticated user whose account is not ACTIVE — refusing them reveals no
    # third party's existence, so 403 is appropriate and existence-safe (R18.2).
    DenyReason.ACCOUNT_NOT_ACTIVE: AuthorizationError,
    # Privacy-safe not-found family (R17.2-R17.4, R18.3): every one of these
    # would leak ownership / membership / existence if answered with a 403, so
    # they are indistinguishable from an ordinary 404 miss.
    DenyReason.RESOURCE_NOT_FOUND: ResourceNotFoundError,
    DenyReason.NOT_OWNER: ResourceNotFoundError,
    DenyReason.NOT_ACTIVE_MEMBER: ResourceNotFoundError,
    DenyReason.COUPLE_NOT_ACTIVE: ResourceNotFoundError,
    DenyReason.SYSTEM_ONLY: ResourceNotFoundError,
    DenyReason.PROFESSIONAL_SHARED: ResourceNotFoundError,
    DenyReason.UNDECIDABLE: ResourceNotFoundError,
}

# The HTTP status each typed error yields, keyed for the hint cross-check below.
_ERROR_STATUS: dict[type[AppError], int] = {
    UnauthenticatedError: HTTP_UNAUTHENTICATED,
    AuthorizationError: HTTP_FORBIDDEN,
    ResourceNotFoundError: HTTP_NOT_FOUND,
}


def decision_to_error(decision: Decision) -> AppError:
    """Translate a DENY :class:`Decision` into the privacy-safe typed error.

    Returns the :class:`~app.errors.AppError` instance the API layer should
    raise. The returned error's ``http_status`` is exactly one of 401 / 403 /
    404 and its ``message`` is generic (never revealing ownership or existence).

    Args:
        decision: A DENY decision (``allowed`` is ``False``). Its ``reason`` is
            required; the ``http_hint`` is cross-checked for consistency.

    Raises:
        ValueError: If ``decision`` is an ALLOW (nothing to map) or carries no
            reason. These are programming errors — an ALLOW must never reach the
            failure path — and are surfaced loudly rather than defaulting to a
            (potentially wrong, potentially leaking) status.
    """
    if decision.allowed:
        raise ValueError("decision_to_error called on an ALLOW decision")
    if decision.reason is None:
        raise ValueError("DENY decision is missing a reason")

    error_cls = _REASON_TO_ERROR.get(decision.reason)
    if error_cls is None:  # pragma: no cover - guards against a new, unmapped reason
        # Fail closed: an unmapped reason must never leak a 403/existence signal.
        # Treat it as a privacy-safe not-found, the most conservative outcome.
        error_cls = ResourceNotFoundError

    # Consistency guard: the pipeline's own hint must agree with the mapping so a
    # future divergence is caught in tests instead of shipping a wrong status.
    expected_status = _ERROR_STATUS[error_cls]
    if decision.http_hint is not None and decision.http_hint != expected_status:
        raise ValueError(
            "Decision http_hint does not match the reason mapping: "
            f"reason={decision.reason.value} hint={decision.http_hint} "
            f"expected={expected_status}"
        )

    return error_cls()


def enforce(decision: Decision) -> None:
    """Raise the mapped privacy-safe error when ``decision`` is a DENY.

    A no-op for an ALLOW, so endpoints (task 12) can guard a sensitive operation
    with a single call::

        enforce(authz.authorize(actor, action, resource))
        # ... proceed; control only reaches here on ALLOW ...

    Raises:
        AppError: One of :class:`~app.errors.UnauthenticatedError` (401),
            :class:`~app.errors.AuthorizationError` (403), or
            :class:`~app.errors.ResourceNotFoundError` (404), per
            :func:`decision_to_error`.
    """
    if decision.allowed:
        return
    raise decision_to_error(decision)


__all__ = ["decision_to_error", "enforce"]
