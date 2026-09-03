"""Auth module repository — persistence for credential hashes.

The only path to the ``credentials`` table. Holds a SQLAlchemy session and
leaves the surrounding transaction's commit to the caller (mirrors the other
Foundation repositories). It stores/returns only the Argon2id **hash** string;
the plaintext password never reaches this layer as stored state.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.models import Credential


class CredentialRepository:
    """Persistence for :class:`~app.auth.models.Credential` rows."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_hash(self, auth_identifier: str) -> str | None:
        """Return the stored Argon2id hash for ``auth_identifier`` or ``None``."""
        return self._session.execute(
            select(Credential.password_hash).where(
                Credential.auth_identifier == auth_identifier
            )
        ).scalar_one_or_none()

    def upsert(self, auth_identifier: str, password_hash: str) -> None:
        """Create or replace the credential hash for ``auth_identifier``.

        Used at registration (create) and recovery/reset (replace). The row is
        flushed so the change is visible within the transaction; committing is
        the caller's responsibility.
        """
        existing = self._session.get(Credential, auth_identifier)
        if existing is None:
            self._session.add(
                Credential(
                    auth_identifier=auth_identifier, password_hash=password_hash
                )
            )
        else:
            existing.password_hash = password_hash
        self._session.flush()


__all__ = ["CredentialRepository"]
