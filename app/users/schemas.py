"""Users module request/response schemas (Pydantic).

Profile view and settings-update payloads. The settings-update schema must not
accept a client-supplied ``account_status`` (R7.4): lifecycle state is changed
only through server-side lifecycle operations
(:meth:`~app.users.service.AccountService.transition_status`). A payload that
carries ``account_status`` / ``status`` (or any other unknown field) is rejected
outright rather than silently ignored, so a client can never smuggle a lifecycle
change in through the settings door.

Design references:
- design.md "Users module" — AccountService (R6.1, R6.2, R7.4)
- 06-authorization-matrix.md §6.1 (own profile/settings)
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.enums import Account_Status

#: Field names a client must never be able to set through a settings update.
#: ``account_status``/``status`` are the lifecycle levers (R7.4); the rest are
#: server-owned identity/audit columns that a settings update has no business
#: mutating. Rejecting them explicitly (below) turns a smuggling attempt into a
#: loud validation error instead of a silent no-op.
_FORBIDDEN_SETTINGS_FIELDS = frozenset(
    {
        "account_status",
        "status",
        "id",
        "auth_identifier",
        "created_at",
        "updated_at",
        "deleted_at",
        "user_id",
    }
)


class ProfileView(BaseModel):
    """A user's own profile as returned by ``get_own_profile`` (R6.1).

    Deliberately excludes ``auth_identifier`` — the authentication identifier is
    sensitive and is never exposed through account-facing responses (R1.5). Only
    the owner ever receives this view; the authorization check in
    :meth:`~app.users.service.AccountService.get_own_profile` guarantees that.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    display_name: str | None = None
    locale: str | None = None
    timezone: str | None = None
    status: Account_Status
    created_at: datetime
    updated_at: datetime


class SettingsUpdate(BaseModel):
    """A settings-update payload for ``update_own_settings`` (R6.2, R7.4).

    Only the product-mutable profile fields are accepted. ``extra="forbid"``
    rejects any unknown field, so a client that tries to include
    ``account_status`` (or ``status``, ``id``, etc.) gets a validation error
    rather than having the field silently dropped — closing the door on a
    client-supplied lifecycle change (R7.4). All fields are optional so a caller
    may update a subset; unset fields are left unchanged (see
    :meth:`~pydantic.BaseModel.model_dump` with ``exclude_unset``).
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    locale: str | None = None
    timezone: str | None = None

    @field_validator("display_name", "locale", "timezone")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        """Normalise a whitespace-only string to ``None`` and trim edges."""
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None


__all__ = ["ProfileView", "SettingsUpdate", "_FORBIDDEN_SETTINGS_FIELDS"]
