"""Re-auth grant wire encoding.

A :class:`~app.auth.service.ReauthToken` is minted by ``/auth/reauth`` and must
travel to the client and back before a Sensitive_Operation (account deletion,
couple disconnect) runs. Both halves — ``grant_id`` and ``token`` — are opaque,
server-side references, so they are joined with a single dot (mirroring the
session-token scheme) into one string the client echoes back in the operation's
request body.

The gated endpoint knows which :class:`~app.auth.service.Sensitive_Operation`
it performs, so ``operation_type`` is *not* trusted from the client: the
reconstructed :class:`ReauthToken` is stamped with the endpoint's own operation,
and the service still verifies the grant was minted for exactly that operation
and belongs to the acting actor before consuming it (R5.1).
"""

from __future__ import annotations

from app.auth.service import ReauthToken, Sensitive_Operation

_GRANT_SEPARATOR = "."


def parse_reauth_grant(
    grant_value: str | None, operation_type: Sensitive_Operation
) -> ReauthToken | None:
    """Parse a ``<grant_id>.<token>`` string into a :class:`ReauthToken`.

    Returns ``None`` when the value is missing or malformed (no dot, or an empty
    half) so the caller can treat an absent/garbled grant as "no re-auth" and
    fail closed with a 403. ``operation_type`` is supplied by the endpoint — the
    grant's binding to an operation is re-verified server-side on consume, so a
    client cannot influence it.
    """
    if not grant_value:
        return None
    grant_id, sep, token = grant_value.partition(_GRANT_SEPARATOR)
    if not sep or not grant_id or not token:
        return None
    return ReauthToken(
        grant_id=grant_id, token=token, operation_type=operation_type
    )


__all__ = ["parse_reauth_grant"]
