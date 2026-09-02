"""Invitation-token generation and hashing primitives (R10.1).

A :class:`CoupleInvitation` stores only a secure *hash* of an unpredictable
token, never the reusable raw value (design.md "CoupleInvitation"; design
Property 14). This module provides the two primitives that guarantee that
invariant so the same logic can be reused by ``InvitationService.create_invitation``
(task 10.1):

* :func:`generate_invitation_token` — produce an unpredictable, high-entropy raw
  token using :func:`secrets.token_urlsafe` (a CSPRNG).
* :func:`hash_invitation_token` — compute the ``token_hash`` that is persisted,
  via a secure one-way hash (SHA-256). The digest is hex-encoded (64 chars),
  which fits the ``CoupleInvitation.token_hash`` column and is stable for lookup.

Only the hash is ever stored. The raw token is returned once at creation and
never persisted.
"""

from __future__ import annotations

import hashlib
import secrets

# Number of random bytes of entropy in a raw invitation token. 32 bytes = 256
# bits, well beyond any brute-force / guessing budget for a short-lived,
# single-purpose token. ``token_urlsafe`` encodes this as URL-safe base64.
TOKEN_ENTROPY_BYTES = 32


def generate_invitation_token(entropy_bytes: int = TOKEN_ENTROPY_BYTES) -> str:
    """Return an unpredictable, high-entropy raw invitation token.

    Uses :func:`secrets.token_urlsafe`, backed by the operating system's CSPRNG,
    so tokens are unguessable and effectively never collide (R10.1).
    """
    if entropy_bytes < 1:
        raise ValueError("entropy_bytes must be a positive integer")
    return secrets.token_urlsafe(entropy_bytes)


def hash_invitation_token(raw_token: str) -> str:
    """Return the secure hash to persist for ``raw_token`` (R10.1).

    Computes a SHA-256 digest and hex-encodes it. The result is deterministic
    (same input → same hash, enabling lookup-by-hash on acceptance) and one-way
    (the raw token cannot be recovered from it). The digest never equals the raw
    token value.
    """
    if not isinstance(raw_token, str):
        raise TypeError("raw_token must be a str")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def new_invitation_token() -> tuple[str, str]:
    """Convenience: generate a raw token and its stored hash together.

    Returns ``(raw_token, token_hash)``. The caller persists only ``token_hash``
    and returns ``raw_token`` to the inviter exactly once.
    """
    raw = generate_invitation_token()
    return raw, hash_invitation_token(raw)


__all__ = [
    "TOKEN_ENTROPY_BYTES",
    "generate_invitation_token",
    "hash_invitation_token",
    "new_invitation_token",
]
