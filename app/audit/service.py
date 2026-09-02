"""Audit module service.

:class:`AuditService` is the sole writer of :class:`~app.audit.models.AuditEvent`
rows (design.md "Audit module"). It provides two entry points:

- :meth:`AuditService.record` — record any covered security/lifecycle event
  with actor, event type, resource type, outcome and timestamp (R19.1, R19.2).
- :meth:`AuditService.record_enumeration_suspected` — emit an
  enumeration-suspicion signal when repeated resource-enumeration attempts are
  detected (R17.5).

The service is **append-only**: it delegates to
:class:`~app.audit.repository.AuditRepository`, which offers no update or delete
path. Its second responsibility is the *minimality guarantee* (R19.3, R19.4):
metadata is restricted to a whitelist of short, structural keys and to scalar
values, so raw relationship content can never be persisted into an audit row.
Any attempt to record disallowed keys or non-scalar / oversized values is
rejected with :class:`AuditMetadataError` rather than silently dropped, so
violations surface loudly in development and tests.
"""

from __future__ import annotations

import uuid
from typing import Any, Final

from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository

# ---------------------------------------------------------------------------
# Minimality policy (R19.3, R19.4).
# ---------------------------------------------------------------------------

#: The only metadata keys an audit event may carry. Deliberately structural and
#: content-free: reasons/codes, counts, and short identifiers for correlation —
#: never free-form text that could smuggle relationship content. The core
#: security fields (actor, event, resource, outcome, timestamp) live in their
#: own columns and are NOT part of ``metadata``.
ALLOWED_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "reason",  # short machine code, e.g. "INVALID_CREDENTIALS"
        "reason_code",  # alias for the above
        "error_code",  # application error code (see app.errors)
        "operation_type",  # e.g. re-auth operation classification (R5.4)
        "session_id",  # correlation only
        "attempt_count",  # numeric signal (e.g. enumeration attempts, R17.5)
        "http_status",  # numeric response status
        "detected_by",  # short mechanism label, e.g. "rate_limit"
    }
)

#: Maximum length of any string metadata value. Codes and labels are short;
#: this cap is a second line of defence against free-text/content smuggling.
MAX_METADATA_STRING_LENGTH: Final[int] = 64


class AuditMetadataError(ValueError):
    """Raised when supplied audit metadata violates the minimality policy.

    Signals a programming error at a call site (R19.3, R19.4): a disallowed key,
    a non-scalar value (dict/list — the shape raw content would take), or an
    over-long string. Raising rather than sanitising keeps violations visible.
    """


def _validate_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Return metadata unchanged if it satisfies the minimality policy, else raise.

    Enforces R19.3/R19.4: only whitelisted keys, only scalar values
    (``str``/``int``/``float``/``bool``/``uuid.UUID``/``None``), and strings
    within :data:`MAX_METADATA_STRING_LENGTH`. Nested structures — the natural
    container for raw relationship content — are rejected outright.
    """
    if metadata is None:
        return None

    if not isinstance(metadata, dict):  # defensive: callers must pass a mapping
        raise AuditMetadataError(
            f"Audit metadata must be a dict, got {type(metadata).__name__}."
        )

    disallowed = set(metadata) - ALLOWED_METADATA_KEYS
    if disallowed:
        raise AuditMetadataError(
            "Audit metadata contains disallowed key(s): "
            f"{sorted(disallowed)}. Allowed keys: {sorted(ALLOWED_METADATA_KEYS)}."
        )

    for key, value in metadata.items():
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float, uuid.UUID)):
            continue
        if isinstance(value, str):
            if len(value) > MAX_METADATA_STRING_LENGTH:
                raise AuditMetadataError(
                    f"Audit metadata value for {key!r} exceeds "
                    f"{MAX_METADATA_STRING_LENGTH} chars; audit logs must not "
                    "store free-form or relationship content (R19.3, R19.4)."
                )
            continue
        raise AuditMetadataError(
            f"Audit metadata value for {key!r} must be a scalar; got "
            f"{type(value).__name__}. Nested/free-form values are forbidden "
            "to keep raw relationship content out of the audit log "
            "(R19.3, R19.4)."
        )

    return metadata


class AuditService:
    """Append-only recorder of security/lifecycle audit events.

    Delegates persistence to an :class:`AuditRepository` (append-only) and owns
    the metadata-minimality guarantee (R19.3, R19.4).
    """

    #: Actor type used for events the system raises on its own behalf (e.g. an
    #: enumeration-suspicion signal) rather than in response to a known actor.
    SYSTEM_ACTOR_TYPE: Final[str] = "SYSTEM"

    #: Event type for the enumeration-suspicion signal (R17.5).
    ENUMERATION_SUSPECTED_EVENT: Final[str] = "ENUMERATION_SUSPECTED"

    def __init__(self, repository: AuditRepository) -> None:
        self._repository = repository

    def record(
        self,
        *,
        actor_type: str,
        actor_id: uuid.UUID | None,
        event_type: str,
        resource_type: str | None,
        resource_id: uuid.UUID | None,
        outcome: str,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record a security/lifecycle audit event.

        Writes an :class:`AuditEvent` capturing actor, event type, resource
        type, outcome and (server-generated) timestamp (R19.1) for any of the
        covered events (R19.2). ``metadata`` is optional and, when present, must
        satisfy the minimality policy — see :func:`_validate_metadata`; raw
        relationship content is never accepted (R19.3, R19.4).

        Raises :class:`AuditMetadataError` if ``metadata`` violates the policy.
        """
        validated = _validate_metadata(metadata)
        return self._repository.add(
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            event_metadata=validated,
            request_id=request_id,
        )

    def record_enumeration_suspected(
        self,
        *,
        actor_id: uuid.UUID | None,
        resource_type: str | None,
        request_id: str | None = None,
        attempt_count: int | None = None,
    ) -> AuditEvent:
        """Emit an enumeration-suspicion audit signal (R17.5).

        Called when repeated resource-enumeration attempts are detected (e.g. a
        rate-limit signal). Recorded as a system-originated event with a
        ``SUSPECTED`` outcome and only structural metadata — the optional
        ``attempt_count`` and a ``detected_by`` label — never any content.
        """
        metadata: dict[str, Any] = {"detected_by": "rate_limit"}
        if attempt_count is not None:
            metadata["attempt_count"] = attempt_count

        return self.record(
            actor_type=self.SYSTEM_ACTOR_TYPE,
            actor_id=actor_id,
            event_type=self.ENUMERATION_SUSPECTED_EVENT,
            resource_type=resource_type,
            resource_id=None,
            outcome="SUSPECTED",
            request_id=request_id,
            metadata=metadata,
        )


__all__ = [
    "AuditService",
    "AuditRepository",
    "AuditMetadataError",
    "ALLOWED_METADATA_KEYS",
    "MAX_METADATA_STRING_LENGTH",
]
