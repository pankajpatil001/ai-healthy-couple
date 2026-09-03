"""API/integration tests for Private Reflection endpoints (requires PostgreSQL).

Exercises the full stack under /api/v1: FastAPI route -> service -> owner-only
authorization pipeline -> encryption boundary -> PostgreSQL, and the reverse
read path. Proves the privacy boundary end to end (owner-only; partner and
former partner denied; couple membership grants nothing), that stored content
is ciphertext (not plaintext), and the deletion invariants.

Skips automatically when PostgreSQL is unreachable (via the ``pg_schema``
fixture). Redis is faked in-process; encryption uses a test key.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
from sqlalchemy import select, text

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
from app.authorization.repository import AuthorizedRepository
from app.authorization.resolver import SqlAlchemyRelationshipResolver
from app.authorization.service import AuthorizationService
from app.couples.models import (
    Couple,
    CoupleInvitation,
    CoupleMember,
    PrivateReflection,
)
from app.couples.repository import ACTIVE_MEMBER_UNIQUE_INDEX, CoupleRepository
from app.couples.service import CoupleService, InvitationService
from app.crypto.encryption import ContentCipher, _secret_name_for_key_id
from app.main import create_app
from app.reflections.repository import ReflectionRepository
from app.reflections.service import ReflectionService
from app.users.models import DataDeletionRequest, User
from app.users.repository import (
    AUTH_IDENTIFIER_UNIQUE_CONSTRAINT,
    DataDeletionRequestRepository,
    UserRepository,
)

from tests.conftest import VersionedTestClient
from tests.test_authentication_service import (
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
)

_TEST_KEY_ID = "reflection-test"


class _FakeRedis:
    """In-memory Redis supporting the limiter's incr/expire contract."""

    def __init__(self) -> None:
        self._store: dict[str, int] = {}

    def incr(self, key: str, amount: int = 1) -> int:
        self._store[key] = self._store.get(key, 0) + amount
        return self._store[key]

    def expire(self, key: str, seconds: int) -> bool:
        return True


class _DictSecrets:
    def __init__(self, secrets):
        self._secrets = secrets

    def get_secret(self, name):
        from app.config import SecretNotFoundError

        try:
            return self._secrets[name]
        except KeyError as exc:
            raise SecretNotFoundError(name) from exc

    def try_get_secret(self, name):
        return self._secrets.get(name)


def _test_cipher() -> ContentCipher:
    key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    return ContentCipher(
        active_key_id=_TEST_KEY_ID,
        secrets_provider=_DictSecrets({_secret_name_for_key_id(_TEST_KEY_ID): key}),
    )


def _create_tables(session) -> None:
    from app.db import Base

    Base.metadata.create_all(
        bind=session.get_bind(),
        tables=[
            User.__table__,
            DataDeletionRequest.__table__,
            Couple.__table__,
            CoupleMember.__table__,
            CoupleInvitation.__table__,
            PrivateReflection.__table__,
            AuditEvent.__table__,
        ],
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{ACTIVE_MEMBER_UNIQUE_INDEX}" '
            "ON couple_members (user_id) WHERE status = 'ACTIVE'"
        )
    )
    session.execute(
        text(
            f'CREATE UNIQUE INDEX "{AUTH_IDENTIFIER_UNIQUE_CONSTRAINT}" '
            "ON users (auth_identifier)"
        )
    )
    session.flush()


class _Harness:
    def __init__(self, app, client, session, cipher):
        self.app = app
        self.client = client
        self.session = session
        self.cipher = cipher


@pytest.fixture
def harness(pg_schema):
    _create_tables(pg_schema)
    session = pg_schema

    identity_provider = InMemoryIdentityProvider()
    session_store = _InMemorySessionStore()
    recovery_store = _InMemoryRecoveryStore()
    reauth_store = _InMemoryReauthStore()
    fake_redis = _FakeRedis()
    cipher = _test_cipher()

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

    def _reflection_service() -> ReflectionService:
        authorization = AuthorizationService(SqlAlchemyRelationshipResolver(session))
        return ReflectionService(
            reflection_repository=ReflectionRepository(session, cipher=cipher),
            authorized_repository=AuthorizedRepository(session, authorization),
            couple_repository=CoupleRepository(session),
            audit_service=_audit(),
        )

    app = create_app()
    app.dependency_overrides[deps.get_db_session] = lambda: session
    app.dependency_overrides[deps.get_redis] = lambda: fake_redis
    app.dependency_overrides[deps.get_audit_service] = _audit
    app.dependency_overrides[deps.get_session_service] = _session_service
    app.dependency_overrides[deps.get_authentication_service] = _authentication_service
    app.dependency_overrides[deps.get_couple_service] = _couple_service
    app.dependency_overrides[deps.get_invitation_service] = _invitation_service
    app.dependency_overrides[deps.get_reflection_service] = _reflection_service

    client = VersionedTestClient(app, raise_server_exceptions=True)
    yield _Harness(app, client, session, cipher)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"{AUTH_SCHEME} {token}"}


def _new_identifier() -> str:
    return f"user-{uuid.uuid4().hex[:12]}@example.com"


def _register_and_login(client, identifier=None, password="pw-secret") -> str:
    identifier = identifier or _new_identifier()
    client.post(
        "/auth/register",
        json={"auth_identifier": identifier, "credential_material": password},
    )
    resp = client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": password},
    )
    return resp.json()["data"]["session_token"]


def _create_reflection(client, token, content="my private note", couple_id=None):
    body = {"content": content}
    if couple_id is not None:
        body["couple_id"] = couple_id
    return client.post("/reflections", headers=_bearer(token), json=body)


# ---------------------------------------------------------------------------
# Owner CRUD
# ---------------------------------------------------------------------------


def test_create_read_update_delete_as_owner(harness):
    c = harness.client
    token = _register_and_login(c)

    created = _create_reflection(c, token, "first version")
    assert created.status_code == 201
    rid = created.json()["data"]["id"]
    assert created.json()["data"]["content"] == "first version"

    got = c.get(f"/reflections/{rid}", headers=_bearer(token))
    assert got.status_code == 200
    assert got.json()["data"]["content"] == "first version"

    patched = c.patch(
        f"/reflections/{rid}", headers=_bearer(token), json={"content": "second"}
    )
    assert patched.status_code == 200
    assert patched.json()["data"]["content"] == "second"
    assert c.get(f"/reflections/{rid}", headers=_bearer(token)).json()["data"][
        "content"
    ] == "second"

    deleted = c.delete(f"/reflections/{rid}", headers=_bearer(token))
    assert deleted.status_code == 200
    assert deleted.json()["data"]["status"] == "deleted"


def test_create_requires_authentication(harness):
    resp = harness.client.post("/reflections", json={"content": "x"})
    assert resp.status_code == 401


def test_create_validation_empty_content_is_422(harness):
    token = _register_and_login(harness.client)
    resp = harness.client.post(
        "/reflections", headers=_bearer(token), json={"content": ""}
    )
    assert resp.status_code == 422


def test_create_rejects_unknown_field(harness):
    token = _register_and_login(harness.client)
    resp = harness.client.post(
        "/reflections",
        headers=_bearer(token),
        json={"content": "x", "user_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 422


def test_unicode_and_large_content_round_trip(harness):
    c = harness.client
    token = _register_and_login(c)
    content = "😊 नमस्ते 日本語 " + ("x" * 20000)
    rid = _create_reflection(c, token, content).json()["data"]["id"]
    assert c.get(f"/reflections/{rid}", headers=_bearer(token)).json()["data"][
        "content"
    ] == content


# ---------------------------------------------------------------------------
# Privacy boundary
# ---------------------------------------------------------------------------


def test_partner_cannot_access(harness):
    c = harness.client
    owner_token = _register_and_login(c)
    rid = _create_reflection(c, owner_token, "secret").json()["data"]["id"]

    partner_token = _register_and_login(c)
    # Read, update, delete as a different user -> identical privacy-safe 404.
    assert c.get(f"/reflections/{rid}", headers=_bearer(partner_token)).status_code == 404
    assert (
        c.patch(
            f"/reflections/{rid}",
            headers=_bearer(partner_token),
            json={"content": "hax"},
        ).status_code
        == 404
    )
    assert (
        c.delete(f"/reflections/{rid}", headers=_bearer(partner_token)).status_code
        == 404
    )
    # Owner content untouched.
    assert c.get(f"/reflections/{rid}", headers=_bearer(owner_token)).json()["data"][
        "content"
    ] == "secret"


def test_unknown_id_and_non_owner_are_indistinguishable(harness):
    c = harness.client
    owner_token = _register_and_login(c)
    rid = _create_reflection(c, owner_token, "secret").json()["data"]["id"]
    stranger_token = _register_and_login(c)

    non_owner = c.get(f"/reflections/{rid}", headers=_bearer(stranger_token))
    missing = c.get(f"/reflections/{uuid.uuid4()}", headers=_bearer(stranger_token))
    assert non_owner.status_code == missing.status_code == 404
    assert non_owner.json()["error"]["code"] == missing.json()["error"]["code"]


def test_couple_membership_does_not_grant_access(harness):
    """Even active couple members cannot read each other's private reflections."""
    c = harness.client
    # Partner A creates a couple and invites B; B accepts -> active couple.
    a_token = _register_and_login(c)
    couple_id = c.post("/couples", headers=_bearer(a_token)).json()["data"]["id"]
    invite = c.post(
        f"/couples/{couple_id}/invitations",
        headers=_bearer(a_token),
        json={"invitee_identifier": "partner-b@example.com"},
    )
    raw_token = invite.json()["data"]["raw_token"]
    b_token = _register_and_login(c, "partner-b@example.com")
    accept = c.post(
        "/invitations/accept", headers=_bearer(b_token), json={"raw_token": raw_token}
    )
    assert accept.status_code == 200

    # A writes a private reflection tagged with the shared couple context.
    rid = _create_reflection(
        c, a_token, "A's private thoughts", couple_id=couple_id
    ).json()["data"]["id"]

    # B is an ACTIVE member of the same couple but must NOT access it.
    assert c.get(f"/reflections/{rid}", headers=_bearer(b_token)).status_code == 404


def test_create_with_couple_id_non_member_is_404(harness):
    c = harness.client
    token = _register_and_login(c)
    resp = _create_reflection(c, token, "x", couple_id=str(uuid.uuid4()))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------


def test_database_stores_ciphertext_not_plaintext(harness):
    c = harness.client
    token = _register_and_login(c)
    plaintext = "PLAINTEXT-MARKER-12345"
    rid = _create_reflection(c, token, plaintext).json()["data"]["id"]

    row = harness.session.execute(
        select(PrivateReflection).where(PrivateReflection.id == uuid.UUID(rid))
    ).scalar_one()
    assert row.content_ciphertext is not None
    assert plaintext not in row.content_ciphertext
    assert row.content_ciphertext.startswith("v1:")
    # And the round trip via API still yields the plaintext.
    assert c.get(f"/reflections/{rid}", headers=_bearer(token)).json()["data"][
        "content"
    ] == plaintext


# ---------------------------------------------------------------------------
# Deletion invariants
# ---------------------------------------------------------------------------


def test_deleted_reflection_cannot_be_retrieved_or_resurrected(harness):
    c = harness.client
    token = _register_and_login(c)
    rid = _create_reflection(c, token, "to be deleted").json()["data"]["id"]

    assert c.delete(f"/reflections/{rid}", headers=_bearer(token)).status_code == 200
    # GET -> 404
    assert c.get(f"/reflections/{rid}", headers=_bearer(token)).status_code == 404
    # PATCH cannot resurrect -> 404
    assert (
        c.patch(
            f"/reflections/{rid}", headers=_bearer(token), json={"content": "back"}
        ).status_code
        == 404
    )
    # Ciphertext cleared in the DB.
    row = harness.session.execute(
        select(PrivateReflection).where(PrivateReflection.id == uuid.UUID(rid))
    ).scalar_one()
    assert row.deleted_at is not None
    assert row.content_ciphertext is None


def test_repeated_delete_is_safe(harness):
    c = harness.client
    token = _register_and_login(c)
    rid = _create_reflection(c, token, "x").json()["data"]["id"]
    assert c.delete(f"/reflections/{rid}", headers=_bearer(token)).status_code == 200
    # Second delete: privacy-safe 404, no error.
    assert c.delete(f"/reflections/{rid}", headers=_bearer(token)).status_code == 404


def test_couple_disconnect_does_not_delete_reflections(harness):
    c = harness.client
    # Build an active couple (A + B).
    a_token = _register_and_login(c)
    couple_id = c.post("/couples", headers=_bearer(a_token)).json()["data"]["id"]
    invite = c.post(
        f"/couples/{couple_id}/invitations",
        headers=_bearer(a_token),
        json={"invitee_identifier": "partner-b2@example.com"},
    )
    raw_token = invite.json()["data"]["raw_token"]
    b_token = _register_and_login(c, "partner-b2@example.com")
    c.post(
        "/invitations/accept", headers=_bearer(b_token), json={"raw_token": raw_token}
    )

    rid = _create_reflection(
        c, a_token, "survives disconnect", couple_id=couple_id
    ).json()["data"]["id"]

    # Disconnect the couple (re-auth gated).
    grant_resp = c.post(
        "/auth/reauth",
        headers=_bearer(a_token),
        json={"reauth_proof": "pw-secret", "operation_type": "COUPLE_DISCONNECTION"},
    )
    grant = grant_resp.json()["data"]["reauth_grant"]
    disc = c.post(
        f"/couples/{couple_id}/disconnect",
        headers=_bearer(a_token),
        json={"reauth_grant": grant},
    )
    assert disc.status_code == 200

    # A's private reflection still exists and is readable by A.
    got = c.get(f"/reflections/{rid}", headers=_bearer(a_token))
    assert got.status_code == 200
    assert got.json()["data"]["content"] == "survives disconnect"
