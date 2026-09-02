"""Typed error classes for the Foundation slice.

Services raise these typed errors; the API layer maps them to the privacy-safe
HTTP failure semantics defined in the design's Error Handling section:

| Situation                                              | HTTP | error.code           |
|--------------------------------------------------------|------|----------------------|
| No/invalid/expired/revoked session                     | 401  | UNAUTHENTICATED      |
| Invalid login credentials                              | 401  | AUTHENTICATION_FAILED|
| Authenticated but forbidden, existence safe to reveal  | 403  | FORBIDDEN            |
| Re-authentication required/failed                      | 403  | REAUTH_REQUIRED      |
| Existence would leak sensitive info (privacy-safe)     | 404  | RESOURCE_NOT_FOUND   |
| Duplicate auth identifier at registration              | 409  | IDENTIFIER_IN_USE    |
| Already has an ACTIVE couple                           | 409  | ACTIVE_COUPLE_EXISTS |
| Malformed / missing input                              | 422  | VALIDATION_ERROR     |

Design references:
- 06-authorization-matrix.md §18 (privacy-safe error semantics)
- 03-api-contracts.md §6 (response envelope), §2.3 (fail closed)

Error bodies MUST NOT reveal ownership ("belongs to your partner"), account
existence, or resource existence where that would leak sensitive information.
The human-readable ``message`` stays generic; ``code`` gives clients an
actionable branch.
"""

from __future__ import annotations


class AppError(Exception):
    """Base class for all typed Foundation errors.

    Attributes:
        code: A stable, machine-readable error code for client branching.
        http_status: The HTTP status the API layer should return.
        message: A generic, privacy-safe human-readable message.
    """

    code: str = "INTERNAL_ERROR"
    http_status: int = 500
    message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)


# --- Validation -----------------------------------------------------------


class ValidationError(AppError):
    """Malformed or missing input (e.g. malformed auth identifier). R1.3."""

    code = "VALIDATION_ERROR"
    http_status = 422
    message = "The request was invalid."


# --- Authentication (401) --------------------------------------------------


class UnauthenticatedError(AppError):
    """No, invalid, expired, or revoked session. R3.2, R18.1."""

    code = "UNAUTHENTICATED"
    http_status = 401
    message = "Authentication is required."


class AuthenticationFailedError(AppError):
    """Invalid login credentials. Must not disclose identifier existence. R2.2."""

    code = "AUTHENTICATION_FAILED"
    http_status = 401
    message = "Authentication failed."


# --- Authorization (403) ---------------------------------------------------


class AuthorizationError(AppError):
    """Authenticated but forbidden, where revealing existence is safe. R18.2."""

    code = "FORBIDDEN"
    http_status = 403
    message = "You do not have permission to perform this action."


class ReauthRequiredError(AuthorizationError):
    """Re-authentication required or failed for a Sensitive_Operation. R5.2."""

    code = "REAUTH_REQUIRED"
    http_status = 403
    message = "Re-authentication is required for this operation."


# --- Privacy-safe not-found (404) -----------------------------------------


class ResourceNotFoundError(AppError):
    """Privacy_Safe_Response.

    Used when distinguishing "does not exist" from "exists but forbidden"
    would leak sensitive information: a private resource requested by a
    non-owner, or a couple / shared resource requested by a non-member.
    R17.3, R17.4, R18.3.
    """

    code = "RESOURCE_NOT_FOUND"
    http_status = 404
    message = "The requested resource was not found."


# --- Conflict (409) --------------------------------------------------------


class IdentifierInUseError(AppError):
    """Duplicate auth identifier at registration; must not leak partner data. R1.2."""

    code = "IDENTIFIER_IN_USE"
    http_status = 409
    message = "That identifier cannot be used."


class ActiveCoupleExistsError(AppError):
    """Actor already has an ACTIVE couple (create/accept). R9.2, R11.2."""

    code = "ACTIVE_COUPLE_EXISTS"
    http_status = 409
    message = "An active couple already exists for this account."


__all__ = [
    "AppError",
    "ValidationError",
    "UnauthenticatedError",
    "AuthenticationFailedError",
    "AuthorizationError",
    "ReauthRequiredError",
    "ResourceNotFoundError",
    "IdentifierInUseError",
    "ActiveCoupleExistsError",
]
