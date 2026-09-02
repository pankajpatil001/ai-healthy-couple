"""End-to-end integration test for the account-deletion request (task 13.5).

Exercises ``POST /account/deletion-request`` through the full request pipeline
with a FastAPI ``TestClient``, asserting the three properties task 13.5 calls
out (R8.1, R8.5):

1. A deletion request WITHOUT a prior valid re-authentication grant is denied
   with ``403 REAUTH_REQUIRED`` and creates no ``DataDeletionRequest`` row.
2. With a valid re-auth grant minted at ``/auth/reauth`` for
   ``ACCOUNT_DELETION_REQUEST``, the request succeeds and a
   ``DataDeletionRequest`` with status ``REQUESTED`` is persisted for the actor.
3. The actor's ``CoupleMember`` records are evaluated as part of processing —
   covered for both the no-couple case (zero active memberships) and the
   in-a-couple case (one active membership), observed via the content-free
   membership count surfaced on the ``DATA_DELETION_REQUESTED`` audit event.

Reuses the wiring harness proven in ``tests/test_api_endpoints.py`` (the
``harness`` fixture over an ephemeral PostgreSQL schema with in-memory
Redis-backed state) and its register/login/reauth helpers, following the
conventions in ``test_api_endpoints.py`` / ``test_api_error_responses.py``.
"""

from __future__ import annotations

import uuid

from app.audit.models import AuditEvent
from app.enums import Deletion_Status, Member_Status
from app.couples.models import CoupleMember
from app.users.models import DataDeletionRequest
from app.users.service import DATA_DELETION_REQUESTED_EVENT

# Reuse the wired TestClient harness and the auth flow helpers. Importing the
# ``harness`` fixture makes it available to the tests in this module; the helper
# functions drive register/login/reauth and build an ACTIVE couple exactly as
# production clients would.
from tests.test_api_endpoints import (  # noqa: F401 (harness used as a fixture)
    _bearer,
    _login,
    _make_active_couple,
    _new_identifier,
    _reauth_grant,
    _register,
    harness,
)

_DELETION_OPERATION = "ACCOUNT_DELETION_REQUEST"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deletion_rows(session, user_id: uuid.UUID) -> list[DataDeletionRequest]:
    """Return the persisted deletion requests for a user (newest ignored order)."""
    return (
        session.query(DataDeletionRequest)
        .filter(DataDeletionRequest.user_id == user_id)
        .all()
    )


def _deletion_requested_event(session, user_id: uuid.UUID) -> AuditEvent:
    """Return the single DATA_DELETION_REQUESTED audit event for a user."""
    return (
        session.query(AuditEvent)
        .filter(
            AuditEvent.event_type == DATA_DELETION_REQUESTED_EVENT,
            AuditEvent.actor_id == user_id,
        )
        .one()
    )


# ---------------------------------------------------------------------------
# (1) Re-auth is required — no grant means no request row
# ---------------------------------------------------------------------------


def test_deletion_request_without_reauth_is_denied_and_creates_nothing(harness):
    """R8.1/R5.2: without a prior valid re-auth grant the request is 403 and no-op.

    A garbled grant is treated as no re-authentication: the pipeline denies with
    ``403 REAUTH_REQUIRED`` and, critically, no ``DataDeletionRequest`` row is
    created (the re-auth gate runs before any persistence).
    """
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(harness.client, identifier))
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": "garbage-no-dot"},
    )

    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "REAUTH_REQUIRED"
    # Nothing was persisted — the gate is a true precondition (R8.1).
    assert _deletion_rows(harness.session, user_id) == []


def test_deletion_request_with_wrong_operation_grant_is_denied(harness):
    """R5.4/R8.1: a grant minted for a *different* operation does not authorize.

    A re-auth grant is scoped to the operation it was minted for. Presenting a
    ``COUPLE_DISCONNECTION`` grant to the deletion endpoint must be rejected the
    same way a missing grant is (403 ``REAUTH_REQUIRED``) with no request row.
    """
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(harness.client, identifier))
    token = _login(harness.client, identifier)
    wrong_grant = _reauth_grant(harness.client, token, "COUPLE_DISCONNECTION")

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": wrong_grant},
    )

    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "REAUTH_REQUIRED"
    assert _deletion_rows(harness.session, user_id) == []


# ---------------------------------------------------------------------------
# (2) With a valid grant: a REQUESTED record is created (no-couple case)
# ---------------------------------------------------------------------------


def test_deletion_request_with_grant_persists_requested_record_no_couple(harness):
    """R8.1/R8.5: valid re-auth creates a REQUESTED record; memberships evaluated.

    For a user who is not in any couple, the deletion request succeeds and a
    single ``DataDeletionRequest`` with status ``REQUESTED`` is persisted. The
    ``DATA_DELETION_REQUESTED`` audit event records that zero active couple
    memberships were evaluated (R8.5), with no relationship content (R8.4).
    """
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(harness.client, identifier))
    token = _login(harness.client, identifier)
    grant = _reauth_grant(harness.client, token, _DELETION_OPERATION)

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": grant},
    )

    assert resp.status_code == 202, resp.text
    body = resp.json()["data"]
    assert body["status"] == "REQUESTED"
    request_id = uuid.UUID(body["deletion_request_id"])

    # A single REQUESTED row is persisted for this user (R8.1).
    rows = _deletion_rows(harness.session, user_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.id == request_id
    assert row.status == Deletion_Status.REQUESTED
    assert row.user_id == user_id

    # R8.5: couple memberships were evaluated — zero for a user with no couple.
    event = _deletion_requested_event(harness.session, user_id)
    assert event.outcome == "SUCCESS"
    assert event.event_metadata["operation_type"] == _DELETION_OPERATION
    assert event.event_metadata["attempt_count"] == 0


# ---------------------------------------------------------------------------
# (3) With a valid grant: couple memberships are evaluated (in-a-couple case)
# ---------------------------------------------------------------------------


def test_deletion_request_evaluates_active_couple_membership(harness):
    """R8.5: a member of an ACTIVE couple has that membership evaluated.

    Build a real ACTIVE couple via the invitation flow so the actor has an
    ACTIVE ``CoupleMember`` row, then request deletion. The request still
    succeeds with a REQUESTED record, and the evaluated active-membership count
    is one — proving the actor's ``CoupleMember`` records are processed (R8.5).
    """
    couple_id, member_token, _partner_token = _make_active_couple(harness)

    # Resolve the acting member's user_id from the ACTIVE membership on the
    # couple (the inviter, who owns ``member_token``).
    couple_uuid = uuid.UUID(couple_id)
    memberships = (
        harness.session.query(CoupleMember)
        .filter(
            CoupleMember.couple_id == couple_uuid,
            CoupleMember.status == Member_Status.ACTIVE,
        )
        .all()
    )
    assert len(memberships) == 2  # an ACTIVE couple has two active members

    # Confirm the acting member can read the couple, then request deletion.
    got = harness.client.get(f"/couples/{couple_id}", headers=_bearer(member_token))
    assert got.status_code == 200

    grant = _reauth_grant(harness.client, member_token, _DELETION_OPERATION)
    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(member_token),
        json={"reauth_grant": grant},
    )

    assert resp.status_code == 202, resp.text
    assert resp.json()["data"]["status"] == "REQUESTED"
    deletion_id = uuid.UUID(resp.json()["data"]["deletion_request_id"])

    # Identify the acting member: exactly one deletion request now exists, and
    # its user_id is one of the two ACTIVE members of the couple.
    all_requests = harness.session.query(DataDeletionRequest).all()
    matching = [r for r in all_requests if r.id == deletion_id]
    assert len(matching) == 1
    row = matching[0]
    actor_id = row.user_id
    assert row.status == Deletion_Status.REQUESTED
    assert actor_id in {m.user_id for m in memberships}

    # R8.5: the evaluated active-membership count is exactly one for this actor.
    event = _deletion_requested_event(harness.session, actor_id)
    assert event.outcome == "SUCCESS"
    assert event.event_metadata["operation_type"] == _DELETION_OPERATION
    assert event.event_metadata["attempt_count"] == 1
