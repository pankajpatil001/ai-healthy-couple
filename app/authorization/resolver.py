"""SQLAlchemy-backed relationship resolver (task 4.2).

The :class:`~app.authorization.service.AuthorizationService` depends on a
:class:`~app.authorization.service.RelationshipResolver` for the Pattern B
relationship facts — active membership and couple lifecycle. In tests that
resolver is an in-memory fake; in the running server it must be backed by the
authoritative store.

:class:`SqlAlchemyRelationshipResolver` implements that protocol against
PostgreSQL via a SQLAlchemy :class:`~sqlalchemy.orm.Session`. Every fact it
returns is read from server state (``CoupleMember`` / ``Couple``), never from
the client (R14.2). It exposes exactly the two questions the pipeline asks:

* :meth:`get_member_status` — the actor's membership status in a couple, or
  ``None`` for a non-member.
* :meth:`get_couple_status` — the couple's lifecycle status, or ``None`` if the
  couple does not exist.

The resolver holds no state beyond the injected session, so a fresh one is
cheap to construct per request alongside the request-scoped session.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.couples.models import Couple, CoupleMember
from app.enums import Couple_Status, Member_Status


class SqlAlchemyRelationshipResolver:
    """Resolve Pattern B relationship facts from PostgreSQL server state.

    Satisfies the :class:`~app.authorization.service.RelationshipResolver`
    protocol. Reads are scoped by the identifiers the pipeline supplies and
    return only the authoritative status enums — no rows, no content — so the
    resolver cannot become a leak channel (R14.2).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_member_status(
        self, couple_id: uuid.UUID, user_id: uuid.UUID
    ) -> Member_Status | None:
        """Return the actor's membership status in the couple, or ``None``.

        ``None`` means there is no ``CoupleMember`` row for that
        ``(couple_id, user_id)`` pair — a non-member. The membership row is
        unique per couple/user (``UNIQUE(couple_id, user_id)``), so at most one
        status is returned.
        """
        return self._session.execute(
            select(CoupleMember.status).where(
                CoupleMember.couple_id == couple_id,
                CoupleMember.user_id == user_id,
            )
        ).scalar_one_or_none()

    def get_couple_status(self, couple_id: uuid.UUID) -> Couple_Status | None:
        """Return the couple's lifecycle status, or ``None`` if it doesn't exist."""
        return self._session.execute(
            select(Couple.status).where(Couple.id == couple_id)
        ).scalar_one_or_none()


__all__ = ["SqlAlchemyRelationshipResolver"]
