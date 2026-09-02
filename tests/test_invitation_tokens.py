"""Property + unit tests for invitation-token hashing (task 2.5).

Feature: foundation-auth-couples, Property 14: Invitation tokens are stored only
as unpredictable hashes.

The invariant (design.md Property 14, R10.1): *for any* created
``CoupleInvitation``, no stored field equals the raw token value; only
``token_hash`` is persisted, and ``token_hash`` equals the secure hash of the
unpredictable raw token. Tokens are also unpredictable/high-entropy — distinct
across generations.

These tests exercise the shared token primitives in :mod:`app.couples.tokens`
(reused by ``InvitationService.create_invitation`` in task 10.1). They are pure
— no database needed — because Property 14 is a property of the stored *values*,
not of persistence: a ``CoupleInvitation`` is constructed in memory and every
string-valued attribute is inspected to prove the raw token never appears.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from hypothesis import given
from hypothesis import strategies as st

from app.couples.models import CoupleInvitation
from app.couples.tokens import (
    generate_invitation_token,
    hash_invitation_token,
    new_invitation_token,
)

# The reference "secure hash" the property is stated against.
import hashlib


def _secure_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_invitation(raw_token: str) -> CoupleInvitation:
    """Construct an in-memory invitation as create_invitation (task 10.1) will.

    Only ``token_hash`` — never the raw token — is placed on the row.
    """
    return CoupleInvitation(
        id=uuid.uuid4(),
        couple_id=uuid.uuid4(),
        inviter_user_id=uuid.uuid4(),
        invitee_identifier="invitee@example.test",
        token_hash=hash_invitation_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )


def _stored_string_values(invitation: CoupleInvitation) -> list[str]:
    """All persisted string-valued attributes of the invitation row."""
    values: list[str] = []
    for column in CoupleInvitation.__table__.columns:
        value = getattr(invitation, column.name)
        if isinstance(value, str):
            values.append(value)
    return values


# ---------------------------------------------------------------------------
# Property 14 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------

@given(seed=st.integers())
def test_property_invitation_stores_only_unpredictable_hash(seed):
    """Property 14: no stored field equals the raw token; token_hash == secure_hash(raw).

    For an unpredictable, freshly generated raw token, the constructed
    ``CoupleInvitation`` persists only its secure hash: every stored string
    field differs from the raw token, and ``token_hash`` reproduces
    ``secure_hash(raw)`` exactly.

    Feature: foundation-auth-couples, Property 14.
    **Validates: Requirements 10.1**
    """
    # ``seed`` only drives Hypothesis's example count; the token itself is drawn
    # from the CSPRNG so we assert over genuinely unpredictable values.
    raw_token = generate_invitation_token()

    invitation = _build_invitation(raw_token)

    # (1) No stored field equals the raw token value.
    assert raw_token not in _stored_string_values(invitation)
    assert invitation.token_hash != raw_token

    # (2) Only the hash is persisted, and it is the secure hash of the raw token.
    assert invitation.token_hash == _secure_hash(raw_token)

    # (3) Hashing is reproducible (same raw → same hash, enabling lookup).
    assert hash_invitation_token(raw_token) == invitation.token_hash


@given(count=st.integers(min_value=2, max_value=50))
def test_property_generated_tokens_are_unpredictable_and_distinct(count):
    """Property 14: raw tokens are high-entropy and distinct across generations.

    Feature: foundation-auth-couples, Property 14.
    **Validates: Requirements 10.1**
    """
    tokens = [generate_invitation_token() for _ in range(count)]

    # Unpredictable ⇒ no collisions across independent generations.
    assert len(set(tokens)) == count
    # High-entropy ⇒ each token carries substantial length (256 bits → >40 chars
    # url-safe base64) and their hashes are likewise all distinct.
    assert all(len(token) >= 40 for token in tokens)
    assert len({hash_invitation_token(t) for t in tokens}) == count


# ---------------------------------------------------------------------------
# Unit tests — concrete examples and edge cases
# ---------------------------------------------------------------------------

def test_hash_is_deterministic_and_one_way():
    """The same raw token always hashes to the same value, never the raw value."""
    raw = "a-fixed-raw-token"
    first = hash_invitation_token(raw)
    second = hash_invitation_token(raw)

    assert first == second == _secure_hash(raw)
    assert first != raw
    # SHA-256 hex digests are 64 characters and fit the token_hash column.
    assert len(first) == 64
    assert len(first) <= 128


def test_different_tokens_hash_differently():
    """Distinct raw tokens produce distinct hashes."""
    assert hash_invitation_token("token-one") != hash_invitation_token("token-two")


def test_new_invitation_token_returns_raw_and_matching_hash():
    """new_invitation_token() returns a raw token and its own secure hash."""
    raw, token_hash = new_invitation_token()

    assert token_hash != raw
    assert token_hash == _secure_hash(raw)
    assert len(raw) >= 40


def test_built_invitation_never_carries_raw_token():
    """A concrete constructed invitation exposes only the hash, never the raw token."""
    raw, _ = new_invitation_token()
    invitation = _build_invitation(raw)

    assert raw not in _stored_string_values(invitation)
    assert invitation.token_hash == _secure_hash(raw)
