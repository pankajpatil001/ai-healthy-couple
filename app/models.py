"""ORM model aggregator.

Importing this module imports every Foundation ORM model so that each table is
registered on ``app.db.Base.metadata``. Alembic's environment (``migrations/env.py``)
and any tooling that needs the full metadata (e.g. ``Base.metadata.create_all``
in tests) import from here rather than knowing about each domain module.

Models are defined in their owning domain modules:

* :class:`~app.users.models.User`, :class:`~app.users.models.DataDeletionRequest`
* :class:`~app.couples.models.Couple`, :class:`~app.couples.models.CoupleMember`,
  :class:`~app.couples.models.CoupleInvitation`,
  :class:`~app.couples.models.PrivateReflection`
* :class:`~app.audit.models.AuditEvent`

(Auth stores no tables — sessions live in Redis and credentials with the
identity provider — and Authorization owns no tables.)
"""

from __future__ import annotations

from app.audit.models import AuditEvent
from app.couples.models import (
    Couple,
    CoupleInvitation,
    CoupleMember,
    PrivateReflection,
)
from app.users.models import DataDeletionRequest, User

__all__ = [
    "User",
    "DataDeletionRequest",
    "Couple",
    "CoupleMember",
    "CoupleInvitation",
    "PrivateReflection",
    "AuditEvent",
]
