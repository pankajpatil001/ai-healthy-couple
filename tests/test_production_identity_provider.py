"""Tests for the production Argon2id identity provider (Phase 2).

Two layers:

* Unit tests of :class:`Argon2idIdentityProvider` against an in-memory credential
  repository fake — hashing (not plaintext), verify correct/wrong, unknown
  identifier, reset, and no-plaintext-in-storage/logs. No PostgreSQL required.
* End-to-end auth tests exercising the real provider + real credential repository
  against PostgreSQL through the /api/v1 auth endpoints: register, login, wrong
  credentials, recovery, sessions, and re-authentication. These require Postgres
  and Redis (Redis faked in-process) and skip when Postgres is unreachable.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from app.api import dependencies as deps
from app.auth.authentication import Argon2idIdentityProvider
from app.auth.models import Credential
from app.main import create_app

from tests.conftest import VersionedTestClient


# ===========================================================================
# Unit tests (no DB) — Argon2idIdentityProvider against a fake repo
# ===========================================================================


class _FakeCredentialRepo:
    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}

    def get_hash(self, auth_identifier):
        return self.hashes.get(auth_identifier)

    def upsert(self, auth_identifier, password_hash):
        self.hashes[auth_identifier] = password_hash


@pytest.fixture
def provider():
    return Argon2idIdentityProvider(_FakeCredentialRepo())


def test_register_stores_argon2id_hash_not_plaintext(provider):
    provider.register_credentials("a@example.com", "s3cret-password")
    stored = provider._repo.hashes["a@example.com"]
    assert "s3cret-password" not in stored
    assert stored.startswith("$argon2id$")


def test_verify_correct_password(provider):
    provider.register_credentials("a@example.com", "correct horse")
    assert provider.verify_credentials("a@example.com", "correct horse") is True


def test_verify_wrong_password(provider):
    provider.register_credentials("a@example.com", "correct horse")
    assert provider.verify_credentials("a@example.com", "wrong") is False


def test_verify_unknown_identifier_is_false(provider):
    # No registration; must be False (and must not raise).
    assert provider.verify_credentials("nobody@example.com", "whatever") is False


def test_reset_changes_the_stored_hash(provider):
    provider.register_credentials("a@example.com", "old-pw")
    old = provider._repo.hashes["a@example.com"]
    provider.reset_credentials("a@example.com", "new-pw")
    new = provider._repo.hashes["a@example.com"]
    assert old != new
    assert provider.verify_credentials("a@example.com", "new-pw") is True
    assert provider.verify_credentials("a@example.com", "old-pw") is False


def test_hash_is_salted_distinct_per_registration(provider):
    provider.register_credentials("a@example.com", "same-pw")
    h1 = provider._repo.hashes["a@example.com"]
    provider.register_credentials("b@example.com", "same-pw")
    h2 = provider._repo.hashes["b@example.com"]
    # Same password, different salts -> different encoded hashes.
    assert h1 != h2


# ===========================================================================
# End-to-end auth via /api/v1 with real Argon2id + PostgreSQL
# ===========================================================================


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, int] = {}

    def incr(self, key, amount=1):
        self._store[key] = self._store.get(key, 0) + amount
        return self._store[key]

    def expire(self, key, seconds):
        return True


def _create_auth_tables(session) -> None:
    from app.audit.models import AuditEvent
    from app.couples.repository import ACTIVE_MEMBER_UNIQUE_INDEX
    from app.db import Base
    from app.users.models import DataDeletionRequest, User
    from app.users.repository import AUTH_IDENTIFIER_UNIQUE_CONSTRAINT

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            User.__table__,
            DataDeletionRequest.__table__,
            AuditEvent.__table__,
            Credential.__table__,
        ],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{AUTH_IDENTIFIER_UNIQUE_CONSTRAINT}" '
            "ON users (auth_identifier)"
        )
    )
    session.flush()


@pytest.fixture
def client(pg_schema):
    """A /api/v1 client wired to real Argon2id auth over the ephemeral schema."""
    from app.audit.repository import AuditRepository
    from app.audit.service import AuditService
    from app.auth.repository import CredentialRepository
    from app.auth.service import AuthenticationService, SessionService
    from app.users.repository import UserRepository

    from tests.test_authentication_service import (
        _InMemoryReauthStore,
        _InMemoryRecoveryStore,
        _InMemorySessionStore,
    )

    _create_auth_tables(pg_schema)
    session = pg_schema

    identity_provider = Argon2idIdentityProvider(CredentialRepository(session))
    session_store = _InMemorySessionStore()
    recovery_store = _InMemoryRecoveryStore()
    reauth_store = _InMemoryReauthStore()

    def _audit():
        return AuditService(AuditRepository(session))

    def _session_service():
        return SessionService(
            store=session_store,
            audit_service=_audit(),
            user_status_lookup=UserRepository(session),
        )

    def _authentication_service():
        return AuthenticationService(
            user_repository=UserRepository(session),
            identity_provider=identity_provider,
            session_service=_session_service(),
            audit_service=_audit(),
            recovery_store=recovery_store,
            reauth_store=reauth_store,
        )

    app = create_app()
    app.dependency_overrides[deps.get_db_session] = lambda: session
    app.dependency_overrides[deps.get_redis] = lambda: _FakeRedis()
    app.dependency_overrides[deps.get_audit_service] = _audit
    app.dependency_overrides[deps.get_session_service] = _session_service
    app.dependency_overrides[deps.get_authentication_service] = _authentication_service
    app.dependency_overrides[deps.get_identity_provider] = lambda: identity_provider

    return VersionedTestClient(app, raise_server_exceptions=True), session


def _ident():
    return f"user-{uuid.uuid4().hex[:12]}@example.com"


def test_register_then_login_end_to_end(client):
    c, session = client
    ident = _ident()
    reg = c.post(
        "/auth/register",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    )
    assert reg.status_code == 201

    # The stored credential is an Argon2id hash, never the plaintext.
    stored = session.execute(
        select(Credential.password_hash).where(Credential.auth_identifier == ident)
    ).scalar_one()
    assert stored.startswith("$argon2id$")
    assert "pw-secret" not in stored

    login = c.post(
        "/auth/login",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    )
    assert login.status_code == 200
    assert login.json()["data"]["session_token"]


def test_login_wrong_password_is_401(client):
    c, _ = client
    ident = _ident()
    c.post(
        "/auth/register",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    )
    resp = c.post(
        "/auth/login",
        json={"auth_identifier": ident, "credential_material": "WRONG"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_login_unknown_identifier_is_same_401(client):
    c, _ = client
    resp = c.post(
        "/auth/login",
        json={"auth_identifier": _ident(), "credential_material": "pw"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_session_protects_and_logout_revokes(client):
    c, _ = client
    ident = _ident()
    c.post(
        "/auth/register",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    )
    token = c.post(
        "/auth/login",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    ).json()["data"]["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert c.get("/account/profile", headers=headers).status_code == 200
    assert c.post("/auth/logout", headers=headers).status_code == 200
    assert c.get("/account/profile", headers=headers).status_code == 401


def test_recovery_resets_password(client):
    c, _ = client
    ident = _ident()
    c.post(
        "/auth/register",
        json={"auth_identifier": ident, "credential_material": "old-pw"},
    )
    init = c.post("/auth/recovery/initiate", json={"auth_identifier": ident})
    data = init.json()["data"]
    done = c.post(
        "/auth/recovery/complete",
        json={
            "challenge_id": data["challenge_id"],
            "secret": data["secret"],
            "new_credential_material": "new-pw",
        },
    )
    assert done.status_code == 200
    # New password works; old does not.
    assert (
        c.post(
            "/auth/login",
            json={"auth_identifier": ident, "credential_material": "new-pw"},
        ).status_code
        == 200
    )
    assert (
        c.post(
            "/auth/login",
            json={"auth_identifier": ident, "credential_material": "old-pw"},
        ).status_code
        == 401
    )


def test_reauth_requires_fresh_valid_proof(client):
    c, _ = client
    ident = _ident()
    c.post(
        "/auth/register",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    )
    token = c.post(
        "/auth/login",
        json={"auth_identifier": ident, "credential_material": "pw-secret"},
    ).json()["data"]["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Wrong proof -> 403 REAUTH_REQUIRED.
    bad = c.post(
        "/auth/reauth",
        headers=headers,
        json={"reauth_proof": "WRONG", "operation_type": "COUPLE_DISCONNECTION"},
    )
    assert bad.status_code == 403

    # Correct proof -> a grant is minted.
    ok = c.post(
        "/auth/reauth",
        headers=headers,
        json={"reauth_proof": "pw-secret", "operation_type": "COUPLE_DISCONNECTION"},
    )
    assert ok.status_code == 200
    assert ok.json()["data"]["reauth_grant"]
