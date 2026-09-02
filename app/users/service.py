"""Users module services — :class:`AccountService` (task 7).

Design "Users module" — :class:`AccountService`: own profile/settings reads and
updates, account lifecycle transitions (ACTIVE/SUSPENDED/DELETED), and account
deletion requests. **All status changes are server-side only**; a
client-supplied status is rejected (R7.4).

Requirement map:

* :meth:`AccountService.get_own_profile` — R6.1: an authorization check confirms
  the actor is the subject before any profile is returned.
* :meth:`AccountService.update_own_settings` — R6.2: apply product-rule settings
  and stamp ``updated_at``; R7.4: reject any client-supplied ``account_status``
  (enforced by the :class:`~app.users.schemas.SettingsUpdate` schema and a
  belt-and-braces check here for dict callers).
* :meth:`AccountService.transition_status` — R7.1/R7.4: the sole server-side
  lifecycle write, constrained to the :class:`~app.enums.Account_Status` set.
* :meth:`AccountService.request_account_deletion` — R8.1: requires a prior
  successful Re_Authentication (a consumed re-auth grant) before creating a
  ``REQUESTED`` :class:`~app.users.models.DataDeletionRequest`; R8.4: records a
  content-free ``DATA_DELETION_REQUESTED`` audit event; R8.5: evaluates the
  actor's ``CoupleMember`` records as part of processing.
* :meth:`AccountService.finalize_deletion` — R8.2: revokes all of the user's
  sessions; R8.3: transitions the account to DELETED so no active authorization
  path remains.

Lifecycle enforcement (R7.2/R7.3) is a *cross-cutting* concern owned by the
authentication + authorization layers, not by this service — see the module note
at the bottom of the file. This service only *changes* lifecycle state; the
layers that read it fail closed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.auth.service import (
    AuthenticationService,
    ReauthToken,
    Sensitive_Operation,
    SessionService,
)
from app.authorization.models import AuthenticatedActor
from app.couples.models import CoupleMember
from app.enums import Account_Status, Member_Status
from app.errors import (
    ReauthRequiredError,
    ResourceNotFoundError,
    ValidationError,
)
from app.users.repository import DataDeletionRequestRepository, UserRepository
from app.users.schemas import (
    _FORBIDDEN_SETTINGS_FIELDS,
    ProfileView,
    SettingsUpdate,
)

# ---------------------------------------------------------------------------
# Audit vocabulary (design.md "AccountService")
# ---------------------------------------------------------------------------

#: Recorded when an account settings update is applied (R6.2).
SETTINGS_UPDATED_EVENT = "ACCOUNT_SETTINGS_UPDATED"
#: Recorded when an account lifecycle status transition occurs (R7.1).
STATUS_TRANSITION_EVENT = "ACCOUNT_STATUS_TRANSITION"
#: Recorded when an account-deletion request is created (R8.4). Metadata is
#: content-free — only the structural operation classification, never any
#: relationship content.
DATA_DELETION_REQUESTED_EVENT = "DATA_DELETION_REQUESTED"
#: Recorded when an account is finalized to DELETED (R8.3).
ACCOUNT_DELETED_EVENT = "ACCOUNT_DELETED"

#: Audit resource type for account/user events (structural label only).
USER_RESOURCE_TYPE = "User"

#: The deletion scope recorded for a full-account deletion request. A short,
#: structural label — not free-form content.
FULL_ACCOUNT_DELETION_SCOPE = "FULL_ACCOUNT"


def _now() -> datetime:
    """Timezone-aware current time (UTC), centralised for deterministic tests."""
    return datetime.now(timezone.utc)


class AccountService:
    """Own-profile/settings, account lifecycle, and deletion requests.

    Collaborators are injected so the service is decoupled and testable:

    * ``user_repository`` — the only path to the ``users`` table; owns the
      server-side status write (:meth:`UserRepository.set_status`).
    * ``deletion_repository`` — persists :class:`DataDeletionRequest` rows (R8.1).
    * ``session_service`` — bulk-revokes sessions on finalized deletion (R8.2).
    * ``authentication_service`` — verifies a prior Re_Authentication grant before
      a deletion request proceeds (R8.1, R5.1).
    * ``audit_service`` — records lifecycle/settings/deletion events with minimal,
      content-free metadata (R6.2, R7.1, R8.4).
    * ``session`` — the SQLAlchemy session, used only to evaluate the actor's
      ``CoupleMember`` records during deletion processing (R8.5). Reads only;
      writes go through the repositories.
    """

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        deletion_repository: DataDeletionRequestRepository,
        session_service: SessionService,
        authentication_service: AuthenticationService,
        audit_service: AuditService,
        session: Session | None = None,
    ) -> None:
        self._users = user_repository
        self._deletions = deletion_repository
        self._sessions = session_service
        self._auth = authentication_service
        self._audit = audit_service
        self._session = session

    # ------------------------------------------------------------------
    # Profile / settings (R6.1, R6.2, R7.4)
    # ------------------------------------------------------------------

    def get_own_profile(self, actor: AuthenticatedActor) -> ProfileView:
        """Return the actor's *own* profile (R6.1).

        The authorization check is intrinsic: the profile is resolved by the
        actor's own ``user_id`` (server-side, never a client-supplied id), so an
        actor can only ever read themselves — there is no path to name another
        user (R6.4 is the write-side mirror). A vanished user surfaces as a
        privacy-safe not-found. ``auth_identifier`` is never included in the
        view (R1.5).
        """
        user = self._users.get_by_id(actor.user_id)
        if user is None:
            # The session resolved to a user that no longer exists — fail closed.
            raise ResourceNotFoundError()
        return ProfileView.model_validate(user)

    def update_own_settings(
        self,
        actor: AuthenticatedActor,
        changes: SettingsUpdate | dict[str, Any],
        *,
        request_id: str | None = None,
    ) -> ProfileView:
        """Apply a settings update to the actor's own account (R6.2, R7.4).

        Accepts either a validated :class:`SettingsUpdate` or a raw ``dict`` (the
        API layer passes the former; service-level callers/tests may pass the
        latter). In both cases any client-supplied ``account_status`` / ``status``
        (or other server-owned field) is **rejected with a validation error**
        (R7.4) — lifecycle state changes only through
        :meth:`transition_status`. Only fields the caller actually set are
        applied; ``updated_at`` is refreshed by the ORM ``onupdate`` and stamped
        explicitly so the change time is deterministic (R6.2).
        """
        payload = self._coerce_settings(changes)

        user = self._users.get_by_id(actor.user_id)
        if user is None:
            raise ResourceNotFoundError()

        for field, value in payload.items():
            setattr(user, field, value)
        # Stamp updated_at explicitly (R6.2) — deterministic even if no ORM
        # onupdate fires (e.g. a no-op field set to its current value).
        user.updated_at = _now()
        if self._session is not None:
            self._session.flush()

        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=SETTINGS_UPDATED_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=actor.user_id,
            outcome="SUCCESS",
            request_id=request_id,
        )
        return ProfileView.model_validate(user)

    @staticmethod
    def _coerce_settings(
        changes: SettingsUpdate | dict[str, Any],
    ) -> dict[str, Any]:
        """Return the set-only field map, rejecting forbidden fields (R7.4).

        A :class:`SettingsUpdate` has already rejected unknown/forbidden fields at
        its ``extra="forbid"`` boundary, so ``model_dump(exclude_unset=True)``
        yields exactly the caller's intended changes. A raw ``dict`` is checked
        here directly: any forbidden key (``account_status``/``status``/…) raises
        :class:`ValidationError` before a validated schema is built, so a
        lifecycle change can never slip through the settings door.
        """
        if isinstance(changes, SettingsUpdate):
            return changes.model_dump(exclude_unset=True)

        if not isinstance(changes, dict):
            raise ValidationError("Settings update payload must be an object.")

        forbidden = set(changes) & _FORBIDDEN_SETTINGS_FIELDS
        if forbidden:
            # R7.4: a client attempted to set a server-controlled lifecycle /
            # identity field via settings. Reject loudly.
            raise ValidationError(
                "Account status and other server-controlled fields cannot be "
                "changed through settings."
            )
        # Route the rest through the schema so unknown fields are rejected too
        # (extra="forbid"), giving dict callers the same guarantees as the API.
        # A pydantic validation failure (unknown field, wrong type) is surfaced
        # as the typed app-level ValidationError so callers see one error family.
        try:
            validated = SettingsUpdate.model_validate(changes)
        except PydanticValidationError as exc:
            raise ValidationError("The settings update was invalid.") from exc
        return validated.model_dump(exclude_unset=True)

    # ------------------------------------------------------------------
    # Lifecycle transitions (R7.1, R7.4)
    # ------------------------------------------------------------------

    def transition_status(
        self,
        user_id: uuid.UUID,
        new_status: Account_Status,
        reason: str,
        *,
        actor_id: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> None:
        """Change an account's lifecycle status server-side (R7.1, R7.4).

        This is the *only* lifecycle write path. ``new_status`` is constrained to
        the :class:`Account_Status` value set — a value outside {ACTIVE,
        SUSPENDED, DELETED} raises :class:`ValidationError` (defence for callers
        that pass a raw string). Transitioning to DELETED stamps ``deleted_at``
        (R8.3). A ``ACCOUNT_STATUS_TRANSITION`` audit event with a short reason
        code is recorded. Raises :class:`ResourceNotFoundError` for an unknown
        user.
        """
        status = self._coerce_status(new_status)

        deleted_at = _now() if status == Account_Status.DELETED else None
        user = self._users.set_status(user_id, status, deleted_at=deleted_at)
        if user is None:
            raise ResourceNotFoundError()

        self._audit.record(
            actor_type="USER" if actor_id is not None else "SYSTEM",
            actor_id=actor_id if actor_id is not None else user_id,
            event_type=STATUS_TRANSITION_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=user_id,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={"reason": _short_reason(reason), "reason_code": status.value},
        )

    @staticmethod
    def _coerce_status(new_status: Account_Status | str) -> Account_Status:
        """Return a valid :class:`Account_Status`, or raise (R7.1, R7.4)."""
        try:
            return Account_Status(new_status)
        except ValueError as exc:
            raise ValidationError(
                "Account status must be one of ACTIVE, SUSPENDED, or DELETED."
            ) from exc

    # ------------------------------------------------------------------
    # Account deletion request (R8.1, R8.4, R8.5)
    # ------------------------------------------------------------------

    def request_account_deletion(
        self,
        actor: AuthenticatedActor,
        reauth_grant: ReauthToken,
        *,
        request_id: str | None = None,
    ):
        """Create a REQUESTED deletion request after Re_Authentication (R8.1).

        Account deletion is a Sensitive_Operation (R5.3): the caller must present
        a re-auth grant minted for ``ACCOUNT_DELETION_REQUEST``. The grant is
        verified and *consumed* (single-use) via the authentication service; a
        missing/invalid/mismatched grant raises :class:`ReauthRequiredError`
        (403, R5.2) and **no** request is created. On success:

        * a :class:`DataDeletionRequest` with status REQUESTED is persisted
          (R8.1);
        * the actor's ``CoupleMember`` records are evaluated as part of
          processing (R8.5) — the count of active memberships is surfaced to the
          audit trail so downstream deletion processing knows a couple is
          implicated, without recording any relationship content;
        * a ``DATA_DELETION_REQUESTED`` audit event is recorded with only the
          operation classification and that structural count — never any
          relationship content (R8.4).

        Returns the created :class:`DataDeletionRequest`.
        """
        # R8.1 / R5.1: require a prior successful Re_Authentication. Consuming the
        # grant makes it single-use; failure denies the operation (R5.2).
        consumed = self._auth.consume_reauthentication(
            reauth_grant, actor, Sensitive_Operation.ACCOUNT_DELETION_REQUEST
        )
        if not consumed:
            raise ReauthRequiredError()

        # R8.5: evaluate the actor's CoupleMember records as part of processing.
        active_membership_count = self._evaluate_couple_memberships(actor.user_id)

        # R8.1: create the REQUESTED record.
        request = self._deletions.create(
            user_id=actor.user_id,
            scope=FULL_ACCOUNT_DELETION_SCOPE,
        )

        # R8.4: audit the request with content-free metadata only (operation
        # classification + a structural count; no relationship content).
        self._audit.record(
            actor_type="USER",
            actor_id=actor.user_id,
            event_type=DATA_DELETION_REQUESTED_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=actor.user_id,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={
                "operation_type": Sensitive_Operation.ACCOUNT_DELETION_REQUEST.value,
                "attempt_count": active_membership_count,
            },
        )
        return request

    def _evaluate_couple_memberships(self, user_id: uuid.UUID) -> int:
        """Return the count of the user's ACTIVE couple memberships (R8.5).

        Evaluating the actor's ``CoupleMember`` records is a required part of
        processing a deletion request (R8.5): a couple the user is still an
        active member of is implicated by their deletion. This read surfaces only
        a *count* — never any couple identifier or content — so the audit trail
        (R8.4) and downstream processing know a couple is involved while the
        privacy boundary is preserved. Returns 0 when no session is wired (pure
        unit tests) so the flow remains exercisable without a database.
        """
        if self._session is None:
            return 0
        count = self._session.execute(
            select(func.count())
            .select_from(CoupleMember)
            .where(
                CoupleMember.user_id == user_id,
                CoupleMember.status == Member_Status.ACTIVE,
            )
        ).scalar_one()
        return int(count)

    # ------------------------------------------------------------------
    # Deletion finalization (R8.2, R8.3)
    # ------------------------------------------------------------------

    def finalize_deletion(
        self,
        user_id: uuid.UUID,
        *,
        request_id: str | None = None,
    ) -> None:
        """Finalize account deletion: revoke sessions, transition to DELETED.

        Order matters and is fail-closed either way, but sessions are revoked
        first (R8.2) so that even in the instant before the status flip no live
        token survives; the transition to DELETED (R8.3) then guarantees that
        :meth:`SessionService.authenticate`'s status re-check fails closed for
        any *future* token as well. After this, the account retains no active
        authorization path to sensitive resources (R8.3): DELETED accounts are
        rejected at authentication (they never even resolve to an actor) and
        denied at authorization pipeline step 1 as a second line of defence.
        """
        # R8.2: revoke every session for the user so no token authenticates.
        self._sessions.revoke_all_sessions(
            user_id, reason="ACCOUNT_DELETION", request_id=request_id
        )
        # R8.3: transition to DELETED (stamps deleted_at). No active authz path
        # remains — see the module note below.
        self.transition_status(
            user_id,
            Account_Status.DELETED,
            reason="ACCOUNT_DELETION",
            actor_id=user_id,
            request_id=request_id,
        )
        self._audit.record(
            actor_type="SYSTEM",
            actor_id=user_id,
            event_type=ACCOUNT_DELETED_EVENT,
            resource_type=USER_RESOURCE_TYPE,
            resource_id=user_id,
            outcome="SUCCESS",
            request_id=request_id,
            metadata={"reason": "ACCOUNT_DELETION"},
        )


def _short_reason(reason: str | None) -> str:
    """Clamp a reason to a short, audit-safe code (see ALLOWED_METADATA policy).

    The audit service caps metadata string length; this keeps a caller-supplied
    reason within that bound so a lifecycle transition is never rejected by the
    minimality policy while still carrying a useful short code.
    """
    if not reason:
        return "UNSPECIFIED"
    return reason[:64]


__all__ = [
    "AccountService",
    "SETTINGS_UPDATED_EVENT",
    "STATUS_TRANSITION_EVENT",
    "DATA_DELETION_REQUESTED_EVENT",
    "ACCOUNT_DELETED_EVENT",
    "USER_RESOURCE_TYPE",
    "FULL_ACCOUNT_DELETION_SCOPE",
]


# ---------------------------------------------------------------------------
# Cross-cutting lifecycle enforcement (task 7.3 — R7.2, R7.3)
# ---------------------------------------------------------------------------
#
# Task 7.3 asks that SUSPENDED deny sensitive-resource requests (R7.2) and
# DELETED deny all authenticated requests (R7.3). This is enforced by the
# existing pipeline WITHOUT any new logic here, across two fail-closed layers:
#
#   1. SessionService.authenticate (app/auth/service.py) re-reads the account's
#      authoritative Account_Status on EVERY request and returns None (→ 401)
#      unless it is ACTIVE. So a SUSPENDED or DELETED account never even resolves
#      to an AuthenticatedActor — no authenticated request is ever attributed to
#      it (R7.3), and its sensitive-resource requests are refused at the door
#      (R7.2). This is the primary guarantee.
#
#   2. AuthorizationService.authorize (app/authorization/service.py) pipeline
#      step 1 independently denies any actor whose account is not ACTIVE
#      (DenyReason.ACCOUNT_NOT_ACTIVE), keyed on AuthenticatedActor.is_account_active
#      (status == ACTIVE, app/authorization/models.py). This is defence in depth:
#      even if an actor were constructed by some path other than
#      SessionService.authenticate, a SUSPENDED/DELETED status is denied before
#      any resource is resolved.
#
# AccountService.finalize_deletion closes the loop for the DELETED case by
# revoking all sessions (R8.2) at the moment of transition, so no *existing*
# token survives even momentarily, and transition_status flips the status so the
# re-check above rejects any *future* token. The guarantee is therefore explicit
# and duplicated across authentication (fail-closed) and authorization (step 1),
# with no third copy of the rule added here.
