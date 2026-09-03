"""Auth module ORM models.

The Foundation slice stored credentials in the identity-provider abstraction
only (an in-memory dev provider); the User row never holds credential material
(08-technology-stack.md §9). Phase 2 introduces **production** application-managed
credentials (Argon2id) and needs somewhere durable to keep the *hash* — never
the plaintext.

:class:`Credential` is that store: one row per ``auth_identifier`` holding the
Argon2id-encoded hash string (which already embeds the algorithm, version, and
per-hash parameters/salt). It is deliberately separate from the ``users`` table
so credential material stays isolated from account/profile data, mirroring the
"credentials live with the identity provider, not the User row" boundary — the
identity provider is now application-managed but the isolation is preserved.

Only the hash is stored. The plaintext password is never persisted or logged.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Credential(Base):
    """A user's Argon2id credential hash, keyed by ``auth_identifier``.

    The identity provider owns this table exclusively. ``auth_identifier`` is the
    primary key (one credential per identifier); ``password_hash`` is the full
    Argon2id encoded string (``$argon2id$v=19$m=...,t=...,p=...$salt$hash``),
    which is self-describing so verification needs no separately stored
    parameters. ``updated_at`` moves on a recovery/password reset.

    The plaintext is never stored. There is no ``user_id`` foreign key here: the
    identifier is the shared coordinate between this table and ``users`` and the
    provider is addressed purely by identifier (matching the existing
    :class:`~app.auth.authentication.IdentityProvider` interface).
    """

    __tablename__ = "credentials"

    auth_identifier: Mapped[str] = mapped_column(
        String(320), primary_key=True
    )
    #: Full Argon2id encoded hash string (embeds version, params, and salt).
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        # Never render the hash; identify by identifier only.
        return f"<Credential auth_identifier={self.auth_identifier!r}>"


__all__ = ["Credential"]
