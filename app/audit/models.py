"""Audit module ORM models.

Design data model :class:`AuditEvent` (design.md "AuditEvent",
02-database-schema.md §30): an append-only record of security/lifecycle events.
The ``metadata`` field carries only the **minimum necessary** for investigation
and **NEVER** any raw relationship content (R19.3, R19.4).

SQLAlchemy 2.0 declarative-typed mapping. Actor/event/resource/outcome fields are
stored as short string codes rather than enums because the covered event set
spans several domains and evolves across phases; the AuditService (task 3.1)
owns the vocabulary and the minimality guarantee. Because ``metadata`` is a
reserved attribute on the SQLAlchemy declarative base, the Python attribute is
named ``event_metadata`` and mapped to the ``metadata`` column.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AuditEvent(Base):
    """An append-only audit event (design.md "AuditEvent", §30).

    Records actor, event type, resource type, outcome, and timestamp (R19.1) for
    the security/lifecycle events enumerated in R19.2. ``event_metadata`` holds
    the minimum necessary metadata and never carries raw relationship content
    (R19.3, R19.4) — that invariant is enforced by the AuditService (task 3.1).
    ``request_id`` correlates the event with the originating request.
    """

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Nullable: some events (e.g. anonymous auth failures) have no resolved actor.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)

    # Minimum-necessary metadata ONLY; NEVER raw relationship content
    # (R19.3, R19.4). The AuditService is the sole writer and enforces this.
    # Mapped to the "metadata" column but exposed as ``event_metadata`` because
    # ``metadata`` is reserved on the declarative base.
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AuditEvent id={self.id!s} event_type={self.event_type!r} "
            f"outcome={self.outcome!r}>"
        )


__all__ = ["AuditEvent"]
