"""Session-revocation end-to-end integration test (task 13.2).

Exercises the full authentication pipeline through the FastAPI ``TestClient``
for the revocation lifecycle called out in the design's Integration tests
section:

    login -> authenticated read -> logout -> same token now 401 (revocation)

This is the endpoint-level counterpart to Property 9 ("a revoked or expired
session never authenticates"): here we assert the concrete API contract that a
logged-out Session_Token is treated as unauthenticated (401 / ``UNAUTHENTICATED``)
on subsequent requests, disclosing nothing about the account behind it.

Requirements exercised:

* **R3.3** — WHEN a User logs out, THE Authentication_Service SHALL revoke the
  associated Session so that its Session_Token can no longer authenticate
  requests.
* **R3.4** — WHEN a User revokes a Session, THE Authentication_Service SHALL
  make that Session unusable for authentication on subsequent requests.

The harness mirrors ``test_api_endpoints.py`` / ``test_api_error_responses.py``:
a real ephemeral PostgreSQL schema backs the ORM rows (with the real partial
unique index), and the Redis-backed session / recovery / re-auth stores plus the
rate limiter are replaced by in-memory fakes via ``app.dependency_overrides`` so
no live Redis is required. A single process-wide identity provider and session
store are shared within a test so a credential registered at ``/auth/register``
verifies at ``/auth/login`` and the session created at login resolves at the
subsequent authenticated calls.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.api.pipeline import AUTH_SCHEME
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    SessionService,
)
from app.couples.repository import CoupleRepository
from app.couples.service import CoupleService, InvitationService
from app.main import create_app
from app.users.repository import DataDeletionRequestRepository, UserRepository
from app.users.service import AccountService

# Reuse the schema/table builder + fake Redis proven in the task 12.2 endpoint
# tests, and the in-memory store fakes proven against the real store contract in
# the service tests, so this module needs no live Redis.
from tests.test_api_endpoints import _FakeRedis, _create_tables
from tests.test_authentication_service import (
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
)


# ---------------------------------------------------------------------------
# Harness (same wiring as test_api_endpoints.harness)
# ---------------------------------------------------------------------------


class _Harness:
    def __init__(self, app, client, session):
        self.app = app
        self.client = client
        self.session = session


@pytest.fixture
def harness(pg_schema):
    """TestClient over an app wired to an ephemeral schema + in-memory fakes."""
    _create_tables(pg_schema)
    session = pg_schema

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


def _new_identifier() -> str:
    return f"user-{uuid.uuid4().hex}@example.test"


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


# ===========================================================================
# End-to-end session revocation: login -> read -> logout -> 401
# ===========================================================================


def test_logout_revokes_session_end_to_end(harness):
    """login -> authenticated read -> logout -> same token now 401 (R3.3/R3.4).

    Walks the exact lifecycle in the design's Integration tests list, asserting
    at every step against the live pipeline (rate limit -> authentication ->
    domain service).
    """
    client = harness.client
    identifier = _new_identifier()
    user_id = _register(client, identifier)

    # 1. Login issues a Session_Token (R2.1).
    token = _login(client, identifier)
    assert "." in token  # "<session_id>.<token>" Bearer shape

    # 2. The token authenticates a protected read while the session is live.
    read = client.get("/account/profile", headers=_bearer(token))
    assert read.status_code == 200, read.text
    assert read.json()["data"]["id"] == user_id

    # 3. Logout revokes the associated session (R3.3).
    logout = client.post("/auth/logout", headers=_bearer(token))
    assert logout.status_code == 200, logout.text
    assert logout.json()["data"]["status"] == "logged_out"

    # 4. The SAME token can no longer authenticate: 401 / UNAUTHENTICATED (R3.4).
    after = client.get("/account/profile", headers=_bearer(token))
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "UNAUTHENTICATED"


def test_revoked_token_is_rejected_across_endpoints(harness):
    """R3.4: once revoked, the token is unusable for ANY authenticated request.

    Revocation is a property of the session, not of a single route, so a
    logged-out token must fail closed uniformly (401 / UNAUTHENTICATED) on every
    sensitive endpoint it is presented to.
    """
    client = harness.client
    identifier = _new_identifier()
    _register(client, identifier)
    token = _login(client, identifier)

    # Sanity: the token works before logout.
    assert client.get("/account/profile", headers=_bearer(token)).status_code == 200

    assert client.post("/auth/logout", headers=_bearer(token)).status_code == 200

    # Every subsequent authenticated call with the dead token is 401.
    probes = [
        client.get("/account/profile", headers=_bearer(token)),
        client.patch(
            "/account/settings",
            headers=_bearer(token),
            json={"display_name": "should-not-apply"},
        ),
        client.post("/couples", headers=_bearer(token)),
        client.post(
            "/auth/reauth",
            headers=_bearer(token),
            json={"reauth_proof": "pw-secret", "operation_type": "COUPLE_DISCONNECTION"},
        ),
    ]
    for resp in probes:
        assert resp.status_code == 401, resp.text
        assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_second_logout_with_revoked_token_is_unauthenticated(harness):
    """R3.4: re-presenting a revoked token (e.g. a second logout) fails closed.

    Logout itself is an authenticated operation, so a token that has already
    been revoked cannot be used to log out again — it is simply unauthenticated.
    """
    client = harness.client
    identifier = _new_identifier()
    _register(client, identifier)
    token = _login(client, identifier)

    assert client.post("/auth/logout", headers=_bearer(token)).status_code == 200

    second = client.post("/auth/logout", headers=_bearer(token))
    assert second.status_code == 401
    assert second.json()["error"]["code"] == "UNAUTHENTICATED"


def test_logout_revokes_only_the_used_session_not_other_sessions(harness):
    """R3.3/R3.4: logout revokes the *associated* session, leaving others live.

    Logging in twice yields two independent sessions; logging out of one must
    revoke exactly that session's token while the other continues to
    authenticate.
    """
    client = harness.client
    identifier = _new_identifier()
    _register(client, identifier)

    token_a = _login(client, identifier)
    token_b = _login(client, identifier)
    assert token_a != token_b

    # Log out of session A only.
    assert client.post("/auth/logout", headers=_bearer(token_a)).status_code == 200

    # A is dead...
    dead = client.get("/account/profile", headers=_bearer(token_a))
    assert dead.status_code == 401
    assert dead.json()["error"]["code"] == "UNAUTHENTICATED"

    # ...but B is untouched and still authenticates.
    alive = client.get("/account/profile", headers=_bearer(token_b))
    assert alive.status_code == 200
