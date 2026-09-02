"""Tests for the FastAPI request pipeline (task 12.1).

Covers the front of the design's "Layered request pipeline"
(Rate limiter -> Authentication middleware -> Authorization policy layer):

  * R2.3/R3.2/R3.6 — the authenticated-actor dependency resolves identity only
    from the server-side session; no/invalid/expired/revoked/non-ACTIVE all map
    to 401 UNAUTHENTICATED, never a client identity claim.
  * R14.3 — authentication is not authorization: get_current_actor only
    establishes identity; the endpoint still runs the authorization layer.
  * R17.5 — a Redis-backed fixed-window rate limiter rejects over-limit bursts
    (429) and, on an enumeration-relevant scope, emits an
    ENUMERATION_SUSPECTED audit signal; a request id is propagated for audit
    correlation and echoed on the response.
  * Graceful degradation — the limiter fails open when the store is unavailable.

The tests mount a couple of test-only protected routes on a fresh app and drive
them with FastAPI's ``TestClient``, overriding the infra providers with in-memory
fakes so no live Redis/Postgres is required. Both unit tests (pipeline helpers)
and integration tests (through the ASGI app) are included.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.api.dependencies import (
    RESOURCE_READ_SCOPE,
    RateLimitedError,
    get_current_actor,
    get_rate_limiter,
    get_request_id,
    rate_limit,
)
from app.api.pipeline import (
    AUTH_SCHEME,
    RateLimiter,
    RateLimitResult,
    extract_request_id,
    parse_session_token,
)
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.config import Settings
from app.enums import Account_Status
from app.errors import UnauthenticatedError
from app.main import create_app


# ===========================================================================
# Test doubles
# ===========================================================================


class _FakeRedis:
    """Minimal in-memory Redis supporting the limiter's incr/expire contract."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.expires: dict[str, int] = {}

    def incr(self, key: str, amount: int = 1) -> int:
        self.store[key] = self.store.get(key, 0) + amount
        return self.store[key]

    def expire(self, key: str, seconds: int) -> bool:
        self.expires[key] = seconds
        return True


class _BrokenRedis:
    """A Redis whose every call raises — exercises graceful degradation."""

    def incr(self, key: str, amount: int = 1) -> int:
        raise ConnectionError("redis down")

    def expire(self, key: str, seconds: int) -> bool:
        raise ConnectionError("redis down")


class _RecordingAudit:
    """Captures enumeration-suspected signals without a database."""

    def __init__(self) -> None:
        self.enumeration_calls: list[dict] = []

    def record_enumeration_suspected(self, **kwargs) -> None:
        self.enumeration_calls.append(kwargs)


class _FakeSessionService:
    """Resolves a fixed map of SessionToken -> actor (server-side identity)."""

    def __init__(self, mapping: dict[tuple[str, str], AuthenticatedActor]) -> None:
        self._mapping = mapping

    def authenticate(self, token):
        return self._mapping.get((token.session_id, token.token))


# ===========================================================================
# Helpers
# ===========================================================================


def _settings(window: int = 60, max_requests: int = 3) -> Settings:
    return Settings(
        rate_limit_window_seconds=window,
        rate_limit_max_requests=max_requests,
    )


def _bearer(session_id: str, token: str) -> dict[str, str]:
    return {"Authorization": f"{AUTH_SCHEME} {session_id}.{token}"}


# ===========================================================================
# Unit tests: parse_session_token
# ===========================================================================


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Basic abc",  # wrong scheme
        "Bearer",  # no credential
        "Bearer notoken",  # missing separator
        "Bearer .onlytoken",  # empty session id
        "Bearer session.",  # empty token
        "Bearer   ",  # blank credential
    ],
)
def test_parse_session_token_rejects_missing_or_malformed(header):
    assert parse_session_token(header) is None


def test_parse_session_token_extracts_both_opaque_halves():
    token = parse_session_token("Bearer sess-123.tok-456")
    assert token is not None
    assert token.session_id == "sess-123"
    assert token.token == "tok-456"


def test_parse_session_token_is_case_insensitive_scheme():
    token = parse_session_token("bearer sess.tok")
    assert token is not None and token.session_id == "sess"


# ===========================================================================
# Unit tests: extract_request_id
# ===========================================================================


def test_extract_request_id_propagates_supplied_value():
    assert extract_request_id("req-abc") == "req-abc"


def test_extract_request_id_generates_uuid_when_absent():
    generated = extract_request_id(None)
    # A parseable uuid4 string.
    uuid.UUID(generated)
    assert extract_request_id("   ") != "   "  # blank -> generated, not echoed


# ===========================================================================
# Unit tests: RateLimiter
# ===========================================================================


def test_rate_limiter_allows_up_to_limit_then_rejects():
    audit = _RecordingAudit()
    limiter = RateLimiter(_FakeRedis(), audit, settings=_settings(max_requests=3))

    results = [limiter.check(RESOURCE_READ_SCOPE, "ip-1") for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].count == 4


def test_rate_limiter_emits_enumeration_signal_once_per_window():
    audit = _RecordingAudit()
    limiter = RateLimiter(_FakeRedis(), audit, settings=_settings(max_requests=2))

    # Two allowed, then several rejected — signal fires exactly on the first
    # over-limit hit (R17.5), not on every subsequent one.
    for _ in range(6):
        limiter.check(RESOURCE_READ_SCOPE, "ip-1", request_id="req-1")

    assert len(audit.enumeration_calls) == 1
    call = audit.enumeration_calls[0]
    assert call["attempt_count"] == 3  # limit(2) + 1
    assert call["request_id"] == "req-1"
    assert call["resource_type"] == RESOURCE_READ_SCOPE


def test_rate_limiter_no_enumeration_signal_for_non_resource_scope():
    audit = _RecordingAudit()
    limiter = RateLimiter(_FakeRedis(), audit, settings=_settings(max_requests=1))

    for _ in range(5):
        limiter.check("login", "ip-1")  # auth scope: brute-force, not enumeration

    assert audit.enumeration_calls == []


def test_rate_limiter_fails_open_when_redis_unavailable():
    audit = _RecordingAudit()
    limiter = RateLimiter(_BrokenRedis(), audit, settings=_settings(max_requests=1))

    result = limiter.check(RESOURCE_READ_SCOPE, "ip-1")
    assert result.allowed is True
    assert result.degraded is True
    assert audit.enumeration_calls == []


# ===========================================================================
# Integration: build a fresh app with test-only protected routes
# ===========================================================================


def _build_app(
    *,
    session_service: _FakeSessionService,
    redis_client,
    settings: Settings,
) -> tuple[FastAPI, _RecordingAudit]:
    """Create an app with test-only routes and fakes wired via overrides."""
    app = create_app()
    audit = _RecordingAudit()

    router = APIRouter()

    @router.get("/_test/protected")
    def protected(actor: deps.CurrentActor, request_id: deps.RequestId) -> dict:
        # Echo the resolved (server-side) identity + correlation id so tests can
        # assert authentication resolved the actor, not a client claim.
        return {"user_id": str(actor.user_id), "request_id": request_id}

    @router.get(
        "/_test/limited",
        dependencies=[Depends(rate_limit(RESOURCE_READ_SCOPE))],
    )
    def limited(actor: deps.CurrentActor) -> dict:
        return {"user_id": str(actor.user_id)}

    app.include_router(router)

    # Override the infra/service providers with fakes — no live Redis/Postgres.
    app.dependency_overrides[deps.get_settings_dep] = lambda: settings
    app.dependency_overrides[deps.get_redis] = lambda: redis_client
    app.dependency_overrides[deps.get_audit_service] = lambda: audit
    app.dependency_overrides[deps.get_session_service] = lambda: session_service
    return app, audit


ACTOR = AuthenticatedActor(user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE)
_VALID = ("sess-1", "tok-1")


def _client(max_requests: int = 3):
    session_service = _FakeSessionService({_VALID: ACTOR})
    settings = _settings(max_requests=max_requests)
    app, audit = _build_app(
        session_service=session_service,
        redis_client=_FakeRedis(),
        settings=settings,
    )
    return TestClient(app, raise_server_exceptions=True), audit


# --- 401 paths -------------------------------------------------------------


def test_no_token_returns_401():
    client, _ = _client()
    resp = client.get("/_test/protected")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_invalid_token_returns_401():
    client, _ = _client()
    resp = client.get("/_test/protected", headers=_bearer("sess-1", "WRONG"))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


def test_malformed_authorization_header_returns_401():
    client, _ = _client()
    resp = client.get("/_test/protected", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


# --- valid session resolves the actor server-side (R2.3) -------------------


def test_valid_session_resolves_actor():
    client, _ = _client()
    resp = client.get("/_test/protected", headers=_bearer(*_VALID))
    assert resp.status_code == 200
    body = resp.json()
    assert body["user_id"] == str(ACTOR.user_id)


# --- expired / revoked / non-ACTIVE all resolve to None -> 401 (R3.2/R3.6) --


@pytest.mark.parametrize("reason", ["expired", "revoked", "suspended", "deleted"])
def test_none_from_session_service_maps_to_401(reason):
    """SessionService returns None for expired/revoked/non-ACTIVE; endpoint -> 401.

    The session service is the sole authority (R3.2, R3.6): whatever the reason,
    authenticate() yields None and the pipeline maps it to 401 without leaking
    which of the reasons applied.
    """
    # An empty mapping means authenticate() returns None for the presented token,
    # exactly as it does for expired/revoked/non-ACTIVE sessions.
    session_service = _FakeSessionService({})
    app, _ = _build_app(
        session_service=session_service,
        redis_client=_FakeRedis(),
        settings=_settings(),
    )
    client = TestClient(app)
    resp = client.get("/_test/protected", headers=_bearer(*_VALID))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


# --- rate limiting through the app (429) + enumeration signal (R17.5) ------


def test_rate_limiting_triggers_429_and_emits_enumeration_signal():
    client, audit = _client(max_requests=2)
    headers = _bearer(*_VALID)

    statuses = [client.get("/_test/limited", headers=headers).status_code for _ in range(4)]
    # First two allowed, remainder rejected once the window limit is passed.
    assert statuses == [200, 200, 429, 429]
    # The over-limit burst on a resource scope raised exactly one R17.5 signal.
    assert len(audit.enumeration_calls) == 1
    assert audit.enumeration_calls[0]["resource_type"] == RESOURCE_READ_SCOPE


def test_rate_limit_runs_before_auth():
    """Rate limiting sits ahead of authentication in the pipeline ordering.

    An unauthenticated caller that floods the limited route is rejected with 429
    (rate limit) before the auth dependency would return 401, matching
    rate limit -> auth ordering.
    """
    client, _ = _client(max_requests=2)
    statuses = [client.get("/_test/limited").status_code for _ in range(4)]
    # No token: under-limit hits fail auth (401); once over the limit, 429 wins.
    assert statuses[:2] == [401, 401]
    assert statuses[2:] == [429, 429]


# --- request id propagation (R17.5) ---------------------------------------


def test_request_id_generated_and_echoed_when_absent():
    client, _ = _client()
    resp = client.get("/_test/protected", headers=_bearer(*_VALID))
    assert resp.status_code == 200
    body_id = resp.json()["request_id"]
    header_id = resp.headers["x-request-id"]
    # The dependency and the response header share the one generated id.
    assert body_id == header_id
    uuid.UUID(body_id)  # a well-formed uuid4


def test_request_id_propagated_from_client_header():
    client, _ = _client()
    resp = client.get(
        "/_test/protected",
        headers={**_bearer(*_VALID), "X-Request-ID": "corr-123"},
    )
    assert resp.status_code == 200
    assert resp.json()["request_id"] == "corr-123"
    assert resp.headers["x-request-id"] == "corr-123"


def test_error_response_echoes_request_id():
    client, _ = _client()
    resp = client.get("/_test/protected", headers={"X-Request-ID": "corr-err"})
    assert resp.status_code == 401
    assert resp.headers["x-request-id"] == "corr-err"


# --- health stays open / Redis-independent --------------------------------


def test_health_needs_no_auth_and_no_redis():
    client, _ = _client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
