"""Integration tests for the domain endpoints wired through the pipeline (task 12.2).

Exercises the auth / account / couple / invitation routes end to end with a
FastAPI ``TestClient``. The goal of task 12.2 is the *wiring*: every sensitive
endpoint runs the pipeline (rate limit -> authentication -> the domain service,
which applies authorization) and returns the ``{"data": ...}`` success envelope.

Wiring strategy (no live Redis required):

* A REAL, ephemeral PostgreSQL schema (``pg_schema``) backs the ORM tables so
  the users / couples / invitations / deletion-request rows and the real
  at-most-one-ACTIVE-couple partial unique index behave authentically.
* Redis-backed state (sessions, recovery challenges, re-auth grants) is replaced
  with in-memory stores, and the rate limiter with an in-memory Redis, via
  ``app.dependency_overrides``. A single process-wide identity provider is shared
  so a credential registered at ``/auth/register`` verifies at ``/auth/login``.

These are integration tests, not exhaustive error-mapping tests: task 12.3 owns
the full 401/403/404/409/422 table. Here we assert the happy paths, the envelope
shape, that sensitive endpoints require authentication (401 without a token), and
that re-auth-gated endpoints require a grant (403 without one).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api import dependencies as deps
from app.api.pipeline import AUTH_SCHEME
from app.audit.models import AuditEvent
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    SessionService,
)
from app.couples.models import Couple, CoupleInvitation, CoupleMember
from app.couples.repository import ACTIVE_MEMBER_UNIQUE_INDEX, CoupleRepository
from app.couples.service import CoupleService, InvitationService
from app.main import create_app
from app.users.models import DataDeletionRequest, User
from app.users.repository import DataDeletionRequestRepository, UserRepository
from app.users.service import AccountService

# Reuse the in-memory store fakes proven against the real contract in the
# service tests, so these integration tests need no live Redis.
from tests.test_authentication_service import (
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
)


# ---------------------------------------------------------------------------
# Fakes for the rate-limit path (no live Redis)
# ---------------------------------------------------------------------------


class _FakeRedis:
    """In-memory Redis supporting the limiter's incr/expire contract."""

    def __init__(self) -> None:
        self._store: dict[str, int] = {}

    def incr(self, key: str, amount: int = 1) -> int:
        self._store[key] = self._store.get(key, 0) + amount
        return self._store[key]

    def expire(self, key: str, seconds: int) -> bool:
        return True


# ---------------------------------------------------------------------------
# Schema / table setup
# ---------------------------------------------------------------------------


def _create_tables(session) -> None:
    """Create every table the endpoints touch, plus the real partial unique index.

    ``Base.metadata.create_all`` builds the tables from the ORM models; the
    at-most-one-ACTIVE-couple partial unique index lives in the migration (not
    the model) so it is added explicitly, matching migration 0002.
    """
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            User.__table__,
            DataDeletionRequest.__table__,
            Couple.__table__,
            CoupleMember.__table__,
            CoupleInvitation.__table__,
            AuditEvent.__table__,
        ],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{ACTIVE_MEMBER_UNIQUE_INDEX}" '
            "ON couple_members (user_id) WHERE status = 'ACTIVE'"
        )
    )
    # The auth_identifier UNIQUE constraint (R1.2) and the invitation token-hash
    # UNIQUE index also live in the migration, not the ORM models; add them so
    # duplicate registration and token collisions fail closed as in production.
    from app.users.repository import AUTH_IDENTIFIER_UNIQUE_CONSTRAINT
    from app.couples.repository import INVITATION_TOKEN_HASH_UNIQUE_INDEX

    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{AUTH_IDENTIFIER_UNIQUE_CONSTRAINT}" '
            "ON users (auth_identifier)"
        )
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{INVITATION_TOKEN_HASH_UNIQUE_INDEX}" '
            "ON couple_invitations (token_hash)"
        )
    )
    session.flush()


# ---------------------------------------------------------------------------
# App builder: real DB session, in-memory Redis-backed state
# ---------------------------------------------------------------------------


class _Harness:
    """Holds the wired app + client + shared in-memory stores for a test."""

    def __init__(self, app, client, session):
        self.app = app
        self.client = client
        self.session = session


@pytest.fixture
def harness(pg_schema):
    """Build a TestClient over an app wired to the ephemeral schema + fakes."""
    _create_tables(pg_schema)

    session = pg_schema
    # Process-shared-within-test collaborators so a credential registered at
    # /auth/register is verifiable at /auth/login and /auth/reauth, and a session
    # created at login resolves at subsequent authenticated calls.
    identity_provider = InMemoryIdentityProvider()
    session_store = _InMemorySessionStore()
    recovery_store = _InMemoryRecoveryStore()
    reauth_store = _InMemoryReauthStore()
    fake_redis = _FakeRedis()

    def _audit() -> AuditService:
        return AuditService(AuditRepository(session))

    def _session_service() -> SessionService:
        return SessionService(
            store=session_store,
            audit_service=_audit(),
            user_status_lookup=UserRepository(session),
        )

    def _authentication_service() -> AuthenticationService:
        return AuthenticationService(
            user_repository=UserRepository(session),
            identity_provider=identity_provider,
            session_service=_session_service(),
            audit_service=_audit(),
            recovery_store=recovery_store,
            reauth_store=reauth_store,
        )

    def _account_service() -> AccountService:
        return AccountService(
            user_repository=UserRepository(session),
            deletion_repository=DataDeletionRequestRepository(session),
            session_service=_session_service(),
            authentication_service=_authentication_service(),
            audit_service=_audit(),
            session=session,
        )

    def _couple_service() -> CoupleService:
        return CoupleService(
            couple_repository=CoupleRepository(session),
            audit_service=_audit(),
            authentication_service=_authentication_service(),
        )

    def _invitation_service() -> InvitationService:
        return InvitationService(
            couple_repository=CoupleRepository(session),
            audit_service=_audit(),
            user_lookup=UserRepository(session),
        )

    app = create_app()
    # Infra + service providers -> fakes / the ephemeral-schema session. The
    # test session commits are no-ops that flush within the outer transaction;
    # the schema is dropped on teardown by the pg_schema fixture.
    app.dependency_overrides[deps.get_db_session] = lambda: session
    app.dependency_overrides[deps.get_redis] = lambda: fake_redis
    app.dependency_overrides[deps.get_audit_service] = _audit
    app.dependency_overrides[deps.get_session_service] = _session_service
    app.dependency_overrides[deps.get_authentication_service] = _authentication_service
    app.dependency_overrides[deps.get_account_service] = _account_service
    app.dependency_overrides[deps.get_couple_service] = _couple_service
    app.dependency_overrides[deps.get_invitation_service] = _invitation_service

    from tests.conftest import VersionedTestClient

    client = VersionedTestClient(app, raise_server_exceptions=True)
    yield _Harness(app, client, session)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer(session_token: str) -> dict[str, str]:
    return {"Authorization": f"{AUTH_SCHEME} {session_token}"}


def _register(client, identifier: str, password: str = "pw-secret") -> str:
    resp = client.post(
        "/auth/register",
        json={"auth_identifier": identifier, "credential_material": password},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["user_id"]


def _login(client, identifier: str, password: str = "pw-secret") -> str:
    resp = client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]["session_token"]


def _reauth_grant(client, token: str, operation: str, password: str = "pw-secret") -> str:
    resp = client.post(
        "/auth/reauth",
        headers=_bearer(token),
        json={"reauth_proof": password, "operation_type": operation},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]["reauth_grant"]


def _new_identifier() -> str:
    return f"user-{uuid.uuid4().hex}@example.test"


# ===========================================================================
# Auth: register / login / logout (happy paths + envelope + auth requirement)
# ===========================================================================


def test_register_returns_created_with_envelope(harness):
    resp = harness.client.post(
        "/auth/register",
        json={"auth_identifier": _new_identifier(), "credential_material": "pw"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"data"}
    uuid.UUID(body["data"]["user_id"])  # a real account id
    # The sensitive auth_identifier is never echoed back (R1.5).
    assert "auth_identifier" not in body["data"]


def test_register_duplicate_identifier_conflicts(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    resp = harness.client.post(
        "/auth/register",
        json={"auth_identifier": identifier, "credential_material": "pw"},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "IDENTIFIER_IN_USE"


def test_register_malformed_identifier_is_422(harness):
    resp = harness.client.post(
        "/auth/register",
        json={"auth_identifier": "not-an-email", "credential_material": "pw"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_login_returns_session_token(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)
    # Matches the Bearer scheme: "<session_id>.<token>".
    assert "." in token


def test_login_wrong_credential_is_401_generic(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    resp = harness.client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": "WRONG"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_login_unknown_identifier_is_same_401(harness):
    resp = harness.client.post(
        "/auth/login",
        json={"auth_identifier": _new_identifier(), "credential_material": "pw"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_logout_requires_authentication(harness):
    resp = harness.client.post("/auth/logout")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_logout_revokes_session_so_token_no_longer_authenticates(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    # A protected read works while the session is live.
    ok = harness.client.get("/account/profile", headers=_bearer(token))
    assert ok.status_code == 200

    out = harness.client.post("/auth/logout", headers=_bearer(token))
    assert out.status_code == 200
    assert out.json()["data"]["status"] == "logged_out"

    # After logout the same token is rejected (R3.3).
    after = harness.client.get("/account/profile", headers=_bearer(token))
    assert after.status_code == 401


# ===========================================================================
# Recovery
# ===========================================================================


def test_recovery_initiate_is_identical_shape_for_unknown_identifier(harness):
    # Unknown identifier: generic acknowledgement, no challenge fields (R4.2).
    unknown = harness.client.post(
        "/auth/recovery/initiate", json={"auth_identifier": _new_identifier()}
    )
    assert unknown.status_code == 200
    assert unknown.json()["data"]["status"] == "recovery_initiated"
    assert "challenge_id" not in unknown.json()["data"]


def test_recovery_round_trip_resets_credential(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier, "old-pw")

    init = harness.client.post(
        "/auth/recovery/initiate", json={"auth_identifier": identifier}
    )
    assert init.status_code == 200
    data = init.json()["data"]
    challenge_id, secret = data["challenge_id"], data["secret"]

    done = harness.client.post(
        "/auth/recovery/complete",
        json={
            "challenge_id": challenge_id,
            "secret": secret,
            "new_credential_material": "new-pw",
        },
    )
    assert done.status_code == 200
    assert done.json()["data"]["status"] == "recovery_completed"

    # The new credential now logs in; the old one does not.
    assert harness.client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": "new-pw"},
    ).status_code == 200
    assert harness.client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": "old-pw"},
    ).status_code == 401


# ===========================================================================
# Account: profile / settings / deletion-request
# ===========================================================================


def test_get_profile_requires_authentication(harness):
    resp = harness.client.get("/account/profile")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_get_profile_returns_own_profile_without_identifier(harness):
    identifier = _new_identifier()
    user_id = _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.get("/account/profile", headers=_bearer(token))
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["id"] == user_id
    assert data["status"] == "ACTIVE"
    assert "auth_identifier" not in data  # R1.5


def test_update_settings_applies_fields(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.patch(
        "/account/settings",
        headers=_bearer(token),
        json={"display_name": "Alex", "locale": "en-GB"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["display_name"] == "Alex"
    assert data["locale"] == "en-GB"


def test_update_settings_rejects_client_supplied_status(harness):
    """R7.4: account_status can never be set through settings (422)."""
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.patch(
        "/account/settings",
        headers=_bearer(token),
        json={"account_status": "SUSPENDED"},
    )
    assert resp.status_code == 422


def test_update_settings_requires_authentication(harness):
    resp = harness.client.patch("/account/settings", json={"display_name": "x"})
    assert resp.status_code == 401


def test_deletion_request_requires_authentication(harness):
    resp = harness.client.post(
        "/account/deletion-request", json={"reauth_grant": "grant.token"}
    )
    assert resp.status_code == 401


def test_deletion_request_without_grant_is_reauth_required(harness):
    """R8.1/R5.2: a missing/garbled re-auth grant is denied with 403."""
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": "garbage-no-dot"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "REAUTH_REQUIRED"


def test_deletion_request_with_grant_creates_request(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)
    grant = _reauth_grant(harness.client, token, "ACCOUNT_DELETION_REQUEST")

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": grant},
    )
    assert resp.status_code == 202
    data = resp.json()["data"]
    uuid.UUID(data["deletion_request_id"])
    assert data["status"] == "REQUESTED"


# ===========================================================================
# Re-auth
# ===========================================================================


def test_reauth_requires_authentication(harness):
    resp = harness.client.post(
        "/auth/reauth",
        json={"reauth_proof": "pw", "operation_type": "COUPLE_DISCONNECTION"},
    )
    assert resp.status_code == 401


def test_reauth_wrong_proof_is_403(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/auth/reauth",
        headers=_bearer(token),
        json={"reauth_proof": "WRONG", "operation_type": "COUPLE_DISCONNECTION"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "REAUTH_REQUIRED"


def test_reauth_returns_grant_for_operation(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/auth/reauth",
        headers=_bearer(token),
        json={"reauth_proof": "pw-secret", "operation_type": "COUPLE_DISCONNECTION"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "." in data["reauth_grant"]
    assert data["operation_type"] == "COUPLE_DISCONNECTION"


# ===========================================================================
# Couples: create / get / disconnect
# ===========================================================================


def test_create_couple_requires_authentication(harness):
    resp = harness.client.post("/couples")
    assert resp.status_code == 401


def test_create_and_get_couple(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    created = harness.client.post("/couples", headers=_bearer(token))
    assert created.status_code == 201
    couple = created.json()["data"]
    assert couple["status"] == "PENDING"
    couple_id = couple["id"]

    got = harness.client.get(f"/couples/{couple_id}", headers=_bearer(token))
    assert got.status_code == 200
    assert got.json()["data"]["id"] == couple_id


def test_get_couple_non_member_is_privacy_safe_not_found(harness):
    # Owner creates a couple.
    owner_id = _new_identifier()
    _register(harness.client, owner_id)
    owner_token = _login(harness.client, owner_id)
    couple_id = harness.client.post("/couples", headers=_bearer(owner_token)).json()[
        "data"
    ]["id"]

    # A stranger cannot see it — identical 404 to a non-existent couple (R17.3).
    stranger_id = _new_identifier()
    _register(harness.client, stranger_id)
    stranger_token = _login(harness.client, stranger_id)

    forbidden = harness.client.get(
        f"/couples/{couple_id}", headers=_bearer(stranger_token)
    )
    missing = harness.client.get(
        f"/couples/{uuid.uuid4()}", headers=_bearer(stranger_token)
    )
    assert forbidden.status_code == missing.status_code == 404
    assert (
        forbidden.json()["error"]["code"]
        == missing.json()["error"]["code"]
        == "RESOURCE_NOT_FOUND"
    )


def test_get_couple_requires_authentication(harness):
    resp = harness.client.get(f"/couples/{uuid.uuid4()}")
    assert resp.status_code == 401


def test_create_couple_twice_conflicts(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    assert harness.client.post("/couples", headers=_bearer(token)).status_code == 201
    second = harness.client.post("/couples", headers=_bearer(token))
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "ACTIVE_COUPLE_EXISTS"


def test_disconnect_requires_authentication(harness):
    resp = harness.client.post(
        f"/couples/{uuid.uuid4()}/disconnect", json={"reauth_grant": "g.t"}
    )
    assert resp.status_code == 401


def test_disconnect_without_grant_is_reauth_required(harness):
    """R13.2/R5.2: disconnect needs a re-auth grant; a garbled one is 403.

    The couple must be ACTIVE and the actor a member for the re-auth gate to be
    reached, so build a full couple first via the invitation flow.
    """
    couple_id, a_token, _b_token = _make_active_couple(harness)

    resp = harness.client.post(
        f"/couples/{couple_id}/disconnect",
        headers=_bearer(a_token),
        json={"reauth_grant": "garbage-no-dot"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "REAUTH_REQUIRED"


def test_disconnect_with_grant_disconnects_couple(harness):
    couple_id, a_token, _b_token = _make_active_couple(harness)
    grant = _reauth_grant(harness.client, a_token, "COUPLE_DISCONNECTION")

    resp = harness.client.post(
        f"/couples/{couple_id}/disconnect",
        headers=_bearer(a_token),
        json={"reauth_grant": grant},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "DISCONNECTED"


# ===========================================================================
# Invitations: create / accept / decline / cancel
# ===========================================================================


def _make_pending_couple_with_invite(harness):
    """Return (couple_id, inviter_token, invitee_identifier, raw_token)."""
    inviter = _new_identifier()
    _register(harness.client, inviter)
    inviter_token = _login(harness.client, inviter)
    couple_id = harness.client.post(
        "/couples", headers=_bearer(inviter_token)
    ).json()["data"]["id"]

    invitee = _new_identifier()
    _register(harness.client, invitee)

    invite = harness.client.post(
        f"/couples/{couple_id}/invitations",
        headers=_bearer(inviter_token),
        json={"invitee_identifier": invitee},
    )
    assert invite.status_code == 201, invite.text
    raw_token = invite.json()["data"]["raw_token"]
    return couple_id, inviter_token, invitee, raw_token


def _make_active_couple(harness):
    """Create + accept an invitation so a couple is ACTIVE with two members.

    Returns (couple_id, inviter_token, invitee_token).
    """
    couple_id, inviter_token, invitee, raw_token = _make_pending_couple_with_invite(
        harness
    )
    invitee_token = _login(harness.client, invitee)
    accepted = harness.client.post(
        "/invitations/accept",
        headers=_bearer(invitee_token),
        json={"raw_token": raw_token},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["data"]["status"] == "ACTIVE"
    return couple_id, inviter_token, invitee_token


def test_create_invitation_requires_authentication(harness):
    resp = harness.client.post(
        f"/couples/{uuid.uuid4()}/invitations",
        json={"invitee_identifier": "x@example.test"},
    )
    assert resp.status_code == 401


def test_create_invitation_returns_raw_token_once(harness):
    _couple_id, _t, _invitee, raw_token = _make_pending_couple_with_invite(harness)
    assert isinstance(raw_token, str) and raw_token


def test_accept_invitation_activates_couple(harness):
    couple_id, _inviter_token, invitee_token = _make_active_couple(harness)
    # The invitee, now an active member, can read the couple.
    got = harness.client.get(f"/couples/{couple_id}", headers=_bearer(invitee_token))
    assert got.status_code == 200
    assert got.json()["data"]["status"] == "ACTIVE"


def test_accept_invitation_requires_authentication(harness):
    resp = harness.client.post("/invitations/accept", json={"raw_token": "nope"})
    assert resp.status_code == 401


def test_accept_bad_token_is_privacy_safe_not_found(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)
    resp = harness.client.post(
        "/invitations/accept",
        headers=_bearer(token),
        json={"raw_token": "not-a-real-token"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_decline_invitation_by_invitee(harness):
    couple_id, _inviter_token, invitee, raw_token = _make_pending_couple_with_invite(
        harness
    )
    invitee_token = _login(harness.client, invitee)

    # Find the invitation id: decline is by id, so create resolves it via accept
    # path is not applicable; look it up from the DB session directly.
    invitation_id = (
        harness.session.query(CoupleInvitation)
        .filter(CoupleInvitation.couple_id == uuid.UUID(couple_id))
        .one()
        .id
    )
    resp = harness.client.post(
        f"/invitations/{invitation_id}/decline", headers=_bearer(invitee_token)
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "declined"


def test_decline_invitation_requires_authentication(harness):
    resp = harness.client.post(f"/invitations/{uuid.uuid4()}/decline")
    assert resp.status_code == 401


def test_cancel_invitation_by_inviter(harness):
    couple_id, inviter_token, _invitee, _raw = _make_pending_couple_with_invite(
        harness
    )
    invitation_id = (
        harness.session.query(CoupleInvitation)
        .filter(CoupleInvitation.couple_id == uuid.UUID(couple_id))
        .one()
        .id
    )
    resp = harness.client.post(
        f"/invitations/{invitation_id}/cancel", headers=_bearer(inviter_token)
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "cancelled"


def test_cancel_invitation_by_non_inviter_is_not_found(harness):
    """A stranger cannot cancel; privacy-safe 404 (R12.2)."""
    couple_id, _inviter_token, _invitee, _raw = _make_pending_couple_with_invite(
        harness
    )
    stranger = _new_identifier()
    _register(harness.client, stranger)
    stranger_token = _login(harness.client, stranger)
    invitation_id = (
        harness.session.query(CoupleInvitation)
        .filter(CoupleInvitation.couple_id == uuid.UUID(couple_id))
        .one()
        .id
    )
    resp = harness.client.post(
        f"/invitations/{invitation_id}/cancel", headers=_bearer(stranger_token)
    )
    assert resp.status_code == 404


def test_cancel_invitation_requires_authentication(harness):
    resp = harness.client.post(f"/invitations/{uuid.uuid4()}/cancel")
    assert resp.status_code == 401
