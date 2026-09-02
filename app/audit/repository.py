"""Audit module repository — append-only writes of AuditEvent rows.

The only path to the audit store. Writes are **append-only**: the repository
exposes exactly one mutating operation, :meth:`AuditRepository.add`, and
deliberately provides no update or delete path (design.md "Audit module";
[02-database-schema.md §30, §36](../../../documents/09-development/02-database-schema.md)).
The append-only guarantee is a structural property — there is simply no API to
mutate or remove an event once recorded.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.audit.models import AuditEvent


class AuditRepository:
    """Append-only persistence for :class:`AuditEvent` rows.

    Holds a SQLAlchemy :class:`~sqlalchemy.orm.Session` and offers a single
    ``add`` operation. There is intentionally no ``update``/``delete`` — the
    audit log is immutable once written.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
        self,
        *,
        actor_type: str,
        actor_id: uuid.UUID | None,
        event_type: str,
        resource_type: str | None,
        resource_id: uuid.UUID | None,
        outcome: str,
        event_metadata: dict[str, Any] | None,
        request_id: str | None,
    ) -> AuditEvent:
        """Persist a new immutable audit event and return it.

        The row is added and flushed so the database-generated ``id`` and
        ``created_at`` are populated on the returned instance. Committing the
        surrounding transaction is the caller's responsibility (mirrors the
        session lifecycle in :func:`app.db.get_session`).
        """
        event = AuditEvent(
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            event_metadata=event_metadata,
            request_id=request_id,
        )
        self._session.add(event)
        self._session.flush()
        return event


__all__ = ["AuditRepository"]
