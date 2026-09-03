"""Lifecycle-denial end-to-end integration test (task 13.3).

Design "Integration tests" — *Account lifecycle: SUSPENDED denies sensitive
reads (R7.2); DELETED denies all authenticated requests + sessions revoked
(R7.3, R8.2)*.

This exercises the wired pipeline (rate limit -> authentication -> domain
service) through a FastAPI ``TestClient`` against a REAL, ephemeral PostgreSQL
schema, mirroring the harness in ``tests/test_api_endpoints.py`` (``_create_tables``,
``_FakeRedis``, the in-memory Redis-backed stores, and ``app.dependency_overrides``).

What it proves end to end:

* **SUSPENDED denies sensitive reads (R7.2).** A user logs in while ACTIVE,
  then a *server-side* lifecycle transition (``AccountService.transition_status``)
  moves the account to SUSPENDED. The previously-working sensitive read
  (``GET /account/profile``) is now rejected: the authentication layer re-reads
  the authoritative ``Account_Status`` on every request and fails closed for a
  non-ACTIVE account, so the live token no longer authenticates.

* **DELETED denies all authenticated requests + sessions revoked (R7.3, R8.2).**
  A second user logs in while ACTIVE, then ``AccountService.finalize_deletion``
  revokes all of the user's sessions (R8.2) and transitions the account to
  DELETED (R8.3). Every authenticated endpoint the token is presented to is now
  rejected, and the session is gone — the token no longer authenticates.

Per the task guidance, lifecycle state is moved through the server-side
``AccountService`` transitions rather than by mutating rows directly, so the test
drives the same code paths production uses.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    SessionService,
)
from app.couples.repository import CoupleRepository
from app.couples.service import CoupleService, InvitationService
from app.enums import Account_Status
from app.main import create_app
from app.users.repository import DataDeletionRequestRepository, UserRepository
from app.users.service import AccountService

# Reuse the proven API harness building blocks from task 12.2's tests.
from tests.test_api_endpoints import (
    _FakeRedis,
    _bearer,
    _create_tables,
    _login,
    _new_identifier,
    _register,
)
from tests.test_authentication_service import (
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
)


class _LifecycleHarness:
    """Wired app + client plus the collaborators a lifecycle test needs.

    Beyond the ``test_api_endpoints`` harness this also exposes the shared
    ``AccountService`` (and its session store) so the test can drive *server-side*
    lifecycle transitions — the only way ``Account_Status`` legitimately changes
    (R7.4) — against the very same session/store the HTTP requests resolve
    through.
    """

    def __init__(self, client: TestClient, account_service: AccountService) -> None:
        self.client = client
        self.account_service = account_service


@pytest.fixture
def lifecycle_harness(pg_schema):
    """A TestClient over an app wired to the ephemeral schema + in-memory stores.

    Identical wiring to the ``test_api_endpoints`` ``harness`` fixture, with the
    shared ``AccountService`` surfaced so the test can perform the server-side
    SUSPENDED / DELETED transitions the endpoints don't expose.
    """
    _create_tables(pg_schema)

    session = pg_schema
    identity_provider = InMemoryIdentityProvider()
    # A single shared session store so a token minted at /auth/login and the
    # AccountService's revoke-all-sessions act on the same records (R8.2).
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
    yield _LifecycleHarness(client, _account_service())


# ===========================================================================
# R7.2 — SUSPENDED denies sensitive reads
# ===========================================================================


def test_suspended_account_is_denied_sensitive_reads(lifecycle_harness):
    """A live token stops authenticating the moment the account is SUSPENDED (R7.2).

    Login while ACTIVE, confirm a sensitive read works, then transition the
    account to SUSPENDED server-side and confirm the *same* token is now rejected
    for that sensitive read — the lifecycle change denies it with no new login.
    """
    client = lifecycle_harness.client
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(client, identifier))
    token = _login(client, identifier)

    # While ACTIVE, the sensitive read succeeds.
    before = client.get("/account/profile", headers=_bearer(token))
    assert before.status_code == 200
    assert before.json()["data"]["status"] == "ACTIVE"

    # Server-side lifecycle transition (the only legitimate path, R7.4).
    lifecycle_harness.account_service.transition_status(
        user_id, Account_Status.SUSPENDED, reason="policy_review"
    )

    # R7.2: the same live token no longer authenticates the sensitive read.
    after = client.get("/account/profile", headers=_bearer(token))
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "UNAUTHENTICATED"


def test_suspended_account_is_denied_other_sensitive_resources(lifecycle_harness):
    """SUSPENDED denial is not endpoint-specific — other sensitive reads deny too (R7.2)."""
    client = lifecycle_harness.client
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(client, identifier))
    token = _login(client, identifier)

    # A sensitive couple read works while ACTIVE.
    created = client.post("/couples", headers=_bearer(token))
    assert created.status_code == 201
    couple_id = created.json()["data"]["id"]
    assert client.get(f"/couples/{couple_id}", headers=_bearer(token)).status_code == 200

    lifecycle_harness.account_service.transition_status(
        user_id, Account_Status.SUSPENDED, reason="policy_review"
    )

    # Both a profile read and a couple read now fail closed for the suspended user.
    assert client.get("/account/profile", headers=_bearer(token)).status_code == 401
    assert (
        client.get(f"/couples/{couple_id}", headers=_bearer(token)).status_code == 401
    )


# ===========================================================================
# R7.3 / R8.2 — DELETED denies all authenticated requests + sessions revoked
# ===========================================================================


def test_deleted_account_denies_all_authenticated_requests_and_revokes_sessions(
    lifecycle_harness,
):
    """DELETED denies every authenticated request and its sessions are revoked (R7.3, R8.2).

    Login while ACTIVE, confirm authenticated access, then finalize deletion
    (revoke all sessions + transition to DELETED). The token must then be
    rejected on every authenticated endpoint, proving no active authorization
    path survives.
    """
    client = lifecycle_harness.client
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(client, identifier))
    token = _login(client, identifier)

    # Authenticated access works while ACTIVE.
    assert client.get("/account/profile", headers=_bearer(token)).status_code == 200

    # Finalize deletion: R8.2 revoke all sessions, R8.3 transition to DELETED.
    lifecycle_harness.account_service.finalize_deletion(user_id)

    # R7.3: every authenticated request attributed to the account is denied.
    authenticated_requests = [
        client.get("/account/profile", headers=_bearer(token)),
        client.patch(
            "/account/settings",
            headers=_bearer(token),
            json={"display_name": "whoever"},
        ),
        client.post("/couples", headers=_bearer(token)),
        client.get(f"/couples/{uuid.uuid4()}", headers=_bearer(token)),
        client.post("/auth/logout", headers=_bearer(token)),
    ]
    for resp in authenticated_requests:
        assert resp.status_code == 401, resp.text
        assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_deleted_account_token_no_longer_authenticates_even_before_status_reused(
    lifecycle_harness,
):
    """The revoked session (R8.2) is gone: the token resolves to nothing.

    Distinct from the SUSPENDED case (where the record survives but the status
    re-check fails), deletion revokes the session outright, so the token has no
    server-side record to resolve against — a second, independent line of the
    R7.3/R8.2 guarantee.
    """
    client = lifecycle_harness.client
    identifier = _new_identifier()
    user_id = uuid.UUID(_register(client, identifier))
    token = _login(client, identifier)
    assert client.get("/account/profile", headers=_bearer(token)).status_code == 200

    lifecycle_harness.account_service.finalize_deletion(user_id)

    # The session no longer exists in the store, so the token authenticates as
    # nobody (R8.2) — independent of the DELETED status re-check (R7.3).
    remaining = lifecycle_harness.account_service._sessions.list_active_sessions(
        user_id
    )
    assert remaining == []
    assert client.get("/account/profile", headers=_bearer(token)).status_code == 401
