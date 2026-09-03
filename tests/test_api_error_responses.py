"""Privacy-safe error-response tests across all endpoints (task 12.3).

Task 12.2 wired the endpoints and their happy paths; task 12.3 owns the full
error contract: every failure across every sensitive endpoint maps to the
design's Error Handling table with a generic ``message`` and an actionable
``error.code``, disclosing nothing about ownership, account existence, or
resource existence.

| Situation                                            | HTTP | error.code            |
|------------------------------------------------------|------|-----------------------|
| No/invalid/expired/revoked session                   | 401  | UNAUTHENTICATED       |
| Invalid login credentials                            | 401  | AUTHENTICATION_FAILED |
| Authenticated but forbidden (existence safe)         | 403  | FORBIDDEN             |
| Re-authentication required/failed                    | 403  | REAUTH_REQUIRED       |
| Existence would leak sensitive info (privacy-safe)   | 404  | RESOURCE_NOT_FOUND    |
| Duplicate auth identifier at registration            | 409  | IDENTIFIER_IN_USE     |
| Already has an ACTIVE couple                         | 409  | ACTIVE_COUPLE_EXISTS  |
| Malformed / missing input                            | 422  | VALIDATION_ERROR      |

The central concern this module locks in is *uniformity* (R18.4): the error
body is always exactly ``{"error": {"code", "message"}}`` — never FastAPI's
default ``{"detail": [...]}`` shape, which would leak field names / types /
constraints — and the same DENY situation always yields the same status + code
regardless of which endpoint produced it.

The harness mirrors ``test_api_endpoints.py``: a real ephemeral PostgreSQL
schema for the ORM rows + the real partial unique index, with Redis-backed state
(sessions, recovery, re-auth grants) and the rate limiter replaced by in-memory
fakes via ``app.dependency_overrides``.
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

# Reuse the proven in-memory store fakes and the schema/table builder + fake
# Redis from the task 12.2 endpoint tests so this module needs no live Redis.
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


def _assert_error_envelope(resp, status: int, code: str) -> None:
    """Assert a response is the privacy-safe error envelope with ``status``/``code``.

    Locks in the three guarantees task 12.3 provides on *every* failure:

    * the HTTP status matches the design's table,
    * the body is exactly ``{"error": {"code", "message"}}`` (never FastAPI's
      default ``{"detail": [...]}``), and
    * the ``message`` is a non-empty generic string that never names a field, an
      identifier, or a resource — only ``code`` carries actionable branching.
    """
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"}, body
    assert set(body["error"]) == {"code", "message"}, body
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]
    # No field-leaking / existence-leaking substrings in the generic message.
    lowered = body["error"]["message"].lower()
    for leak in ("field required", "value is not", "partner", "does not exist"):
        assert leak not in lowered, body


# ===========================================================================
# 422 VALIDATION_ERROR — the gap task 12.3 closes
# ===========================================================================
#
# FastAPI's default request-validation handler returns 422 with a
# ``{"detail": [...]}`` body that names the offending fields. The app installs a
# handler that normalises *every* such failure to the privacy-safe envelope with
# a generic message (R1.3, R18.4). These assert the envelope shape, not just the
# status.


def test_missing_body_field_is_privacy_safe_validation_error(harness):
    # credential_material omitted -> Pydantic "field required".
    resp = harness.client.post(
        "/auth/register", json={"auth_identifier": _new_identifier()}
    )
    _assert_error_envelope(resp, 422, "VALIDATION_ERROR")


def test_empty_body_is_privacy_safe_validation_error(harness):
    resp = harness.client.post("/auth/register", json={})
    _assert_error_envelope(resp, 422, "VALIDATION_ERROR")


def test_extra_forbidden_field_is_privacy_safe_validation_error(harness):
    # _CredentialsBody forbids unknown fields; a smuggled `status` is rejected.
    resp = harness.client.post(
        "/auth/register",
        json={
            "auth_identifier": _new_identifier(),
            "credential_material": "pw",
            "status": "ACTIVE",
        },
    )
    _assert_error_envelope(resp, 422, "VALIDATION_ERROR")


def test_settings_client_supplied_status_is_privacy_safe_validation_error(harness):
    """R7.4: account_status can never be set through settings, and the 422 body
    is the privacy-safe envelope — not FastAPI's field-naming default."""
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.patch(
        "/account/settings",
        headers=_bearer(token),
        json={"account_status": "SUSPENDED"},
    )
    _assert_error_envelope(resp, 422, "VALIDATION_ERROR")


def test_malformed_identifier_is_privacy_safe_validation_error(harness):
    # Passes the schema (non-empty string) but the service rejects it (R1.3).
    resp = harness.client.post(
        "/auth/register",
        json={"auth_identifier": "not-an-email", "credential_material": "pw"},
    )
    _assert_error_envelope(resp, 422, "VALIDATION_ERROR")


# ===========================================================================
# 401 — unauthenticated / bad credentials
# ===========================================================================


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/account/profile"),
        ("patch", "/account/settings"),
        ("post", "/auth/logout"),
        ("post", "/couples"),
        ("post", "/invitations/accept"),
    ],
)
def test_protected_endpoints_without_token_are_unauthenticated(harness, method, path):
    # No Authorization header -> 401 UNAUTHENTICATED, uniformly. Body-carrying
    # methods get an empty JSON body so the route is reached; GET takes none.
    kwargs = {"json": {}} if method in {"post", "patch"} else {}
    resp = getattr(harness.client, method)(path, **kwargs)
    _assert_error_envelope(resp, 401, "UNAUTHENTICATED")


def test_garbage_token_is_unauthenticated(harness):
    resp = harness.client.get("/account/profile", headers=_bearer("not.a.token"))
    _assert_error_envelope(resp, 401, "UNAUTHENTICATED")


def test_login_bad_and_unknown_credentials_are_identical_401(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)

    wrong = harness.client.post(
        "/auth/login",
        json={"auth_identifier": identifier, "credential_material": "WRONG"},
    )
    unknown = harness.client.post(
        "/auth/login",
        json={"auth_identifier": _new_identifier(), "credential_material": "pw"},
    )
    # R2.2: a wrong password and an unknown identifier are indistinguishable.
    _assert_error_envelope(wrong, 401, "AUTHENTICATION_FAILED")
    _assert_error_envelope(unknown, 401, "AUTHENTICATION_FAILED")
    assert wrong.json() == unknown.json()


# ===========================================================================
# 403 — authenticated but forbidden / re-auth required
# ===========================================================================


def test_reauth_wrong_proof_is_forbidden(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/auth/reauth",
        headers=_bearer(token),
        json={"reauth_proof": "WRONG", "operation_type": "COUPLE_DISCONNECTION"},
    )
    _assert_error_envelope(resp, 403, "REAUTH_REQUIRED")


def test_deletion_request_without_grant_is_reauth_required(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/account/deletion-request",
        headers=_bearer(token),
        json={"reauth_grant": "garbage-no-dot"},
    )
    _assert_error_envelope(resp, 403, "REAUTH_REQUIRED")


# ===========================================================================
# 404 — privacy-safe not found (non-member / non-existent are identical)
# ===========================================================================


def test_get_couple_non_member_and_missing_are_identical_not_found(harness):
    owner = _new_identifier()
    _register(harness.client, owner)
    owner_token = _login(harness.client, owner)
    couple_id = harness.client.post("/couples", headers=_bearer(owner_token)).json()[
        "data"
    ]["id"]

    stranger = _new_identifier()
    _register(harness.client, stranger)
    stranger_token = _login(harness.client, stranger)

    forbidden = harness.client.get(
        f"/couples/{couple_id}", headers=_bearer(stranger_token)
    )
    missing = harness.client.get(
        f"/couples/{uuid.uuid4()}", headers=_bearer(stranger_token)
    )
    # R17.3: existing-but-forbidden is indistinguishable from non-existent.
    _assert_error_envelope(forbidden, 404, "RESOURCE_NOT_FOUND")
    _assert_error_envelope(missing, 404, "RESOURCE_NOT_FOUND")
    assert forbidden.json() == missing.json()


def test_accept_bad_token_is_privacy_safe_not_found(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        "/invitations/accept",
        headers=_bearer(token),
        json={"raw_token": "not-a-real-token"},
    )
    _assert_error_envelope(resp, 404, "RESOURCE_NOT_FOUND")


def test_decline_unknown_invitation_is_not_found(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    resp = harness.client.post(
        f"/invitations/{uuid.uuid4()}/decline", headers=_bearer(token)
    )
    _assert_error_envelope(resp, 404, "RESOURCE_NOT_FOUND")


# ===========================================================================
# 409 — conflict (duplicate identifier / already-active couple)
# ===========================================================================


def test_duplicate_registration_is_conflict(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    resp = harness.client.post(
        "/auth/register",
        json={"auth_identifier": identifier, "credential_material": "pw"},
    )
    _assert_error_envelope(resp, 409, "IDENTIFIER_IN_USE")


def test_second_couple_is_conflict(harness):
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    assert harness.client.post("/couples", headers=_bearer(token)).status_code == 201
    second = harness.client.post("/couples", headers=_bearer(token))
    _assert_error_envelope(second, 409, "ACTIVE_COUPLE_EXISTS")


# ===========================================================================
# Uniformity (R18.4): the same DENY situation yields one status + code
# ===========================================================================


def test_privacy_safe_not_found_is_uniform_across_endpoints(harness):
    """A privacy-safe miss is the identical 404 body on every endpoint that
    can produce one, so a probe cannot distinguish endpoints or reasons."""
    identifier = _new_identifier()
    _register(harness.client, identifier)
    token = _login(harness.client, identifier)

    responses = [
        harness.client.get(f"/couples/{uuid.uuid4()}", headers=_bearer(token)),
        harness.client.post(
            "/invitations/accept",
            headers=_bearer(token),
            json={"raw_token": "nope"},
        ),
        harness.client.post(
            f"/invitations/{uuid.uuid4()}/decline", headers=_bearer(token)
        ),
        harness.client.post(
            f"/invitations/{uuid.uuid4()}/cancel", headers=_bearer(token)
        ),
    ]
    bodies = {r.json()["error"]["code"] for r in responses}
    statuses = {r.status_code for r in responses}
    assert statuses == {404}
    assert bodies == {"RESOURCE_NOT_FOUND"}
    # Byte-identical bodies across endpoints (same generic message).
    assert len({r.text for r in responses}) == 1
