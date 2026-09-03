"""Private Reflection persistence — the crypto/persistence boundary.

This repository is the only place that turns reflection *plaintext* into stored
*ciphertext* and back. Encryption happens here (not in the service and not in
the API) so every persistence path is covered by exactly one boundary
(04-Architecture responsibility boundaries):

    ReflectionService -> AuthorizedRepository (authorize) -> ReflectionRepository (encrypt) -> DB

Reads never resolve a soft-deleted row (``deleted_at IS NULL``). Soft-delete
both stamps ``deleted_at`` **and** clears ``content_ciphertext`` so the deleted
plaintext is unrecoverable through the application while the tombstone row
remains for future retention/account-deletion accounting (Deletion plan §11).

The repository holds a SQLAlchemy :class:`~sqlalchemy.orm.Session`; committing
the surrounding transaction is the caller's responsibility (mirrors the other
Foundation repositories).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.couples.models import PrivateReflection
from app.crypto.encryption import ContentCipher, get_content_cipher
from app.enums import Visibility_Scope


def _now() -> datetime:
    """Timezone-aware current time (UTC), centralised for deterministic tests."""
    return datetime.now(timezone.utc)


class ReflectionRepository:
    """Persistence for :class:`~app.couples.models.PrivateReflection` rows.

    Args:
        session: the request-scoped SQLAlchemy session.
        cipher: the content cipher used at the persistence boundary. Defaults to
            the process-wide :func:`~app.crypto.encryption.get_content_cipher`;
            injectable so tests can supply a cipher with a test key.
    """

    def __init__(
        self, session: Session, *, cipher: ContentCipher | None = None
    ) -> None:
        self._session = session
        self._cipher = cipher or get_content_cipher()

    # -- reads ------------------------------------------------------------

    def get_active_row(self, reflection_id: uuid.UUID) -> PrivateReflection | None:
        """Return a non-deleted reflection row by id, or ``None``.

        Soft-deleted rows (``deleted_at`` set) are treated as absent so a deleted
        reflection can never be resurrected or read. No authorization is applied
        here — that is the caller's responsibility via
        :class:`~app.authorization.repository.AuthorizedRepository`.
        """
        return self._session.execute(
            select(PrivateReflection).where(
                PrivateReflection.id == reflection_id,
                PrivateReflection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

    def decrypt_content(self, row: PrivateReflection) -> str:
        """Return the decrypted plaintext for an (already-authorized) row.

        Called only after the owner-only authorization check has passed, so
        decryption never occurs for an unauthorized caller. A row whose
        ciphertext is missing (e.g. a tombstone that slipped through) decrypts to
        empty rather than raising, but active-row reads always carry ciphertext.
        """
        if not row.content_ciphertext:
            return ""
        return self._cipher.decrypt(row.content_ciphertext)

    # -- writes -----------------------------------------------------------

    def create(
        self,
        *,
        owner_id: uuid.UUID,
        plaintext: str,
        couple_id: uuid.UUID | None = None,
    ) -> PrivateReflection:
        """Insert a new PRIVATE_PARTNER reflection with encrypted content.

        The plaintext is encrypted at this boundary; only ciphertext touches the
        database. ``visibility_scope`` is forced to ``PRIVATE_PARTNER`` (never
        client-controlled); ``owner_id`` is the server-resolved actor. The row is
        flushed so DB-generated ``id`` / ``created_at`` populate the instance.
        """
        ciphertext = self._cipher.encrypt(plaintext)
        row = PrivateReflection(
            id=uuid.uuid4(),
            user_id=owner_id,
            couple_id=couple_id,
            visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
            content_ciphertext=ciphertext,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def update_content(
        self, row: PrivateReflection, *, plaintext: str
    ) -> PrivateReflection:
        """Re-encrypt and store new content for an (already-authorized) row.

        Ownership/visibility are never changed here — only the ciphertext and the
        ``updated_at`` stamp. The row is flushed so the change is visible within
        the transaction.
        """
        row.content_ciphertext = self._cipher.encrypt(plaintext)
        row.updated_at = _now()
        self._session.flush()
        return row

    def soft_delete(self, row: PrivateReflection) -> PrivateReflection:
        """Soft-delete a reflection: stamp ``deleted_at`` and clear ciphertext.

        Clearing ``content_ciphertext`` makes the deleted plaintext unrecoverable
        through the application even though the tombstone row survives for future
        retention/account-deletion processing. Idempotent at the repository
        level: re-deleting an already-tombstoned row simply re-stamps and leaves
        ciphertext cleared.
        """
        row.deleted_at = _now()
        row.content_ciphertext = None
        self._session.flush()
        return row


__all__ = ["ReflectionRepository"]
