"""Tests for the append-only AuditService and repository (task 3.1).

Covers:
  * R19.1/R19.2 — an audit event records actor, event type, resource type,
    outcome and a server-generated timestamp for covered events.
  * R19.3/R19.4 — metadata is minimal and NEVER carries raw relationship
    content: disallowed keys, nested/free-form values and over-long strings are
    rejected; nothing is persisted when validation fails.
  * R17.5 — record_enumeration_suspected emits a content-free suspicion signal.
  * Append-only structural guarantee — the repository exposes no update/delete.

The persistence tests run against a real, ephemeral PostgreSQL schema (the
``pg_schema`` fixture) so the JSONB ``metadata`` column and server-default
timestamp are exercised for real, not mocked. The validation/append-only tests
are pure and run everywhere.
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository
from app.audit.service import (
    ALLOWED_METADATA_KEYS,
    MAX_METADATA_STRING_LENGTH,
    AuditMetadataError,
    AuditService,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_audit_table(session):
    """Create the audit_events table inside the test's ephemeral schema."""
    from app.audit.models import AuditEvent as _AE

    _AE.__table__.create(bind=session.connection())


def _service(session) -> AuditService:
    return AuditService(AuditRepository(session))


# ---------------------------------------------------------------------------
# Persistence: record() writes actor/event/resource/outcome/timestamp (R19.1/2)
# ---------------------------------------------------------------------------

def test_record_persists_core_fields_and_timestamp(pg_schema):
    """record() stores the core fields and a server-generated timestamp (R19.1)."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    actor_id = uuid.uuid4()
    resource_id = uuid.uuid4()

    event = service.record(
        actor_type="USER",
        actor_id=actor_id,
        event_type="LOGIN",
        resource_type="Session",
        resource_id=resource_id,
        outcome="SUCCESS",
        request_id="req-123",
    )

    assert event.id is not None
    assert event.actor_type == "USER"
    assert event.actor_id == actor_id
    assert event.event_type == "LOGIN"
    assert event.resource_type == "Session"
    assert event.resource_id == resource_id
    assert event.outcome == "SUCCESS"
    assert event.request_id == "req-123"
    # Timestamp is populated server-side (R19.1) — not supplied by the caller.
    assert event.created_at is not None

    # It is durably persisted and re-readable.
    fetched = pg_schema.get(AuditEvent, event.id)
    assert fetched is not None
    assert fetched.event_type == "LOGIN"


def test_record_allows_null_actor_and_resource(pg_schema):
    """Anonymous/no-resource events (e.g. failed auth) are recordable."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    event = service.record(
        actor_type="ANONYMOUS",
        actor_id=None,
        event_type="AUTH_FAILURE",
        resource_type=None,
        resource_id=None,
        outcome="DENIED",
    )

    assert event.actor_id is None
    assert event.resource_type is None
    assert event.resource_id is None
    assert event.event_metadata is None


def test_record_persists_whitelisted_metadata(pg_schema):
    """Minimal, whitelisted, scalar metadata round-trips through JSONB."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    event = service.record(
        actor_type="USER",
        actor_id=uuid.uuid4(),
        event_type="AUTH_FAILURE",
        resource_type="Couple",
        resource_id=uuid.uuid4(),
        outcome="DENIED",
        metadata={"reason": "NOT_A_MEMBER", "http_status": 404},
    )

    fetched = pg_schema.get(AuditEvent, event.id)
    assert fetched.event_metadata == {"reason": "NOT_A_MEMBER", "http_status": 404}


# ---------------------------------------------------------------------------
# Minimality guarantee (R19.3, R19.4)
# ---------------------------------------------------------------------------

def test_record_rejects_disallowed_metadata_key():
    """A key outside the whitelist (e.g. raw content) is rejected (R19.3)."""
    service = _service(session=_DummySession())
    with pytest.raises(AuditMetadataError):
        service.record(
            actor_type="USER",
            actor_id=uuid.uuid4(),
            event_type="LOGIN",
            resource_type=None,
            resource_id=None,
            outcome="SUCCESS",
            metadata={"reflection_text": "I felt hurt when..."},
        )


def test_record_rejects_nested_metadata_value():
    """Nested structures — how raw content would arrive — are rejected (R19.3)."""
    service = _service(session=_DummySession())
    with pytest.raises(AuditMetadataError):
        service.record(
            actor_type="USER",
            actor_id=uuid.uuid4(),
            event_type="LOGIN",
            resource_type=None,
            resource_id=None,
            outcome="SUCCESS",
            metadata={"reason": {"raw": "relationship content"}},
        )


def test_record_rejects_overlong_string_value():
    """Over-long strings (potential free-text content) are rejected (R19.4)."""
    service = _service(session=_DummySession())
    with pytest.raises(AuditMetadataError):
        service.record(
            actor_type="USER",
            actor_id=uuid.uuid4(),
            event_type="LOGIN",
            resource_type=None,
            resource_id=None,
            outcome="SUCCESS",
            metadata={"reason": "x" * (MAX_METADATA_STRING_LENGTH + 1)},
        )


def test_disallowed_metadata_is_never_persisted(pg_schema):
    """When metadata is invalid, nothing is written to the audit store (R19.3)."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    with pytest.raises(AuditMetadataError):
        service.record(
            actor_type="USER",
            actor_id=uuid.uuid4(),
            event_type="LOGIN",
            resource_type=None,
            resource_id=None,
            outcome="SUCCESS",
            metadata={"private_note": "secret"},
        )

    assert pg_schema.query(AuditEvent).count() == 0


@given(
    key=st.text(min_size=1, max_size=40).filter(
        lambda k: k not in ALLOWED_METADATA_KEYS
    ),
    value=st.one_of(
        st.dictionaries(st.text(max_size=8), st.text(max_size=64), max_size=3),
        st.lists(st.text(max_size=16), max_size=3),
        st.text(min_size=MAX_METADATA_STRING_LENGTH + 1, max_size=200),
    ),
)
def test_property_content_shaped_metadata_always_rejected(key, value):
    """Property: any non-whitelisted key or content-shaped value is rejected.

    Models raw relationship content, which arrives either under an arbitrary
    key or as a nested/free-text value. Such metadata must never be accepted.

    **Validates: Requirements 19.3**
    """
    service = _service(session=_DummySession())
    with pytest.raises(AuditMetadataError):
        service.record(
            actor_type="USER",
            actor_id=None,
            event_type="LOGIN",
            resource_type=None,
            resource_id=None,
            outcome="SUCCESS",
            metadata={key: value},
        )


# ---------------------------------------------------------------------------
# Enumeration-suspicion signal (R17.5)
# ---------------------------------------------------------------------------

def test_record_enumeration_suspected_emits_content_free_signal(pg_schema):
    """record_enumeration_suspected writes a system, content-free signal (R17.5)."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    actor_id = uuid.uuid4()
    event = service.record_enumeration_suspected(
        actor_id=actor_id,
        resource_type="Couple",
        request_id="req-xyz",
        attempt_count=7,
    )

    assert event.actor_type == AuditService.SYSTEM_ACTOR_TYPE
    assert event.event_type == AuditService.ENUMERATION_SUSPECTED_EVENT
    assert event.actor_id == actor_id
    assert event.resource_type == "Couple"
    assert event.outcome == "SUSPECTED"
    # Only structural metadata — no content of any kind.
    assert set(event.event_metadata) <= ALLOWED_METADATA_KEYS
    assert event.event_metadata["attempt_count"] == 7
    assert event.event_metadata["detected_by"] == "rate_limit"


def test_record_enumeration_suspected_without_count(pg_schema):
    """attempt_count is optional; the signal is still recorded."""
    _create_audit_table(pg_schema)
    service = _service(pg_schema)

    event = service.record_enumeration_suspected(
        actor_id=None,
        resource_type=None,
    )

    assert event.outcome == "SUSPECTED"
    assert "attempt_count" not in event.event_metadata


# ---------------------------------------------------------------------------
# Append-only structural guarantee
# ---------------------------------------------------------------------------

def test_repository_is_append_only():
    """The repository exposes only an append path — no update/delete surface."""
    public_ops = {
        name
        for name in dir(AuditRepository)
        if not name.startswith("_")
    }
    assert public_ops == {"add"}
    assert not any(
        op in public_ops for op in ("update", "delete", "remove", "edit", "save")
    )


def test_service_has_no_mutation_surface():
    """AuditService only records; it offers no update/delete of events."""
    public_ops = {name for name in dir(AuditService) if not name.startswith("_")}
    # Only the two record entry points plus the class-level constants.
    assert "record" in public_ops
    assert "record_enumeration_suspected" in public_ops
    assert not any(
        op in public_ops for op in ("update", "delete", "remove", "edit")
    )


# ---------------------------------------------------------------------------
# A tiny stand-in session for the pure validation tests (no DB needed).
# ---------------------------------------------------------------------------

class _DummySession:
    """Minimal Session stand-in: records add()/flush() were never reached.

    Used only by validation tests, where the AuditMetadataError must be raised
    *before* any persistence is attempted. If add() is ever called, the test
    would surface it via the assertion below.
    """

    def add(self, obj):  # pragma: no cover - must not be reached in these tests
        raise AssertionError("add() must not be called when metadata is invalid")

    def flush(self):  # pragma: no cover - must not be reached in these tests
        raise AssertionError("flush() must not be called when metadata is invalid")


# ---------------------------------------------------------------------------
# Property 22: Audit events contain no raw relationship content
# (Feature: foundation-auth-couples, Property 22)
# ---------------------------------------------------------------------------

class _RecordingSession:
    """In-memory Session stand-in that captures appended AuditEvents.

    Mirrors the append-only repository contract (add + flush) without a real
    database, so we can inspect the *stored* metadata of any event that is
    actually persisted. Populates a placeholder ``id`` on flush to match the
    real repository's post-flush invariant.
    """

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def add(self, obj: AuditEvent) -> None:
        self.events.append(obj)

    def flush(self) -> None:
        for event in self.events:
            if event.id is None:
                event.id = uuid.uuid4()


def _is_minimal_scalar(value) -> bool:
    """A stored metadata value is structural iff it is an allowed scalar.

    Nested/free-form containers (dict/list) — the shape raw relationship
    content takes — and over-long strings are NOT structural.
    """
    if isinstance(value, bool) or value is None:
        return True
    if isinstance(value, (int, float, uuid.UUID)):
        return True
    if isinstance(value, str):
        return len(value) <= MAX_METADATA_STRING_LENGTH
    return False


# Arbitrary metadata values, deliberately mixing benign scalars with the
# content-shaped shapes raw relationship content would take: nested dicts,
# lists, and long free-text strings.
_metadata_values = st.one_of(
    st.text(max_size=200),
    st.integers(),
    st.booleans(),
    st.none(),
    st.uuids(),
    st.dictionaries(st.text(max_size=8), st.text(max_size=64), max_size=3),
    st.lists(st.text(max_size=32), max_size=3),
)

# Keys mix whitelisted structural keys with arbitrary (content-carrying) keys.
_metadata_keys = st.one_of(
    st.sampled_from(sorted(ALLOWED_METADATA_KEYS)),
    st.text(min_size=1, max_size=40),
)


@given(
    actor_type=st.text(min_size=1, max_size=32),
    actor_id=st.one_of(st.none(), st.uuids()),
    event_type=st.text(min_size=1, max_size=32),
    resource_type=st.one_of(st.none(), st.text(min_size=1, max_size=32)),
    resource_id=st.one_of(st.none(), st.uuids()),
    outcome=st.text(min_size=1, max_size=16),
    metadata=st.one_of(
        st.none(),
        st.dictionaries(_metadata_keys, _metadata_values, max_size=5),
    ),
)
def test_property_audit_events_contain_no_raw_relationship_content(
    actor_type,
    actor_id,
    event_type,
    resource_type,
    resource_id,
    outcome,
    metadata,
):
    """Property 22: recorded audit metadata is structural-only, never content.

    For an arbitrary audit record (any actor/event/resource/outcome) carrying
    arbitrary metadata — which may contain raw relationship content under any
    key or as nested/free-text values — recording either:

      * rejects the record with :class:`AuditMetadataError` before any write, or
      * persists an event whose stored metadata is limited to the whitelisted
        structural keys with only short scalar values.

    In no case is raw relationship content (non-whitelisted keys, nested/list
    values, or over-long free-text) persisted into the audit log.

    Feature: foundation-auth-couples, Property 22

    **Validates: Requirements 19.1, 19.3, 19.4**
    """
    session = _RecordingSession()
    service = AuditService(AuditRepository(session))

    try:
        event = service.record(
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            metadata=metadata,
        )
    except AuditMetadataError:
        # Content-shaped metadata was rejected before persistence: nothing
        # reached the (append-only) store. Invariant upheld.
        assert session.events == []
        return

    # The record was accepted, so it must have been persisted with only
    # minimal, structural metadata (R19.1: core fields live in their own
    # columns; R19.3/R19.4: metadata carries no raw relationship content).
    assert session.events == [event]

    # Core security fields are recorded on the event itself, not smuggled
    # through metadata (R19.1).
    assert event.actor_type == actor_type
    assert event.event_type == event_type
    assert event.outcome == outcome

    stored = event.event_metadata
    if stored is None:
        return

    # Every stored key is a whitelisted structural key (R19.3) ...
    assert set(stored) <= ALLOWED_METADATA_KEYS
    # ... and every stored value is a short scalar, never nested/free-form
    # content (R19.4).
    for value in stored.values():
        assert _is_minimal_scalar(value), (
            f"Persisted audit metadata value {value!r} is not minimal/structural"
        )
