"""Shared pytest configuration and fixtures for the Foundation test suite.

Provides:
  * A Hypothesis profile ("foundation") with a minimum of 100 iterations per
    property, registered and loaded at import time (design.md "Property-based
    testing configuration").
  * ``pg_schema`` — an ephemeral PostgreSQL schema created per test and dropped
    afterwards, with a Session bound to it, so tests never touch shared tables.
  * ``redis_ns`` — a Redis client scoped to a unique per-test key namespace,
    flushed on teardown so tests never collide or leak state.

Both service-backed fixtures skip (rather than error) when the backing service
is unreachable, so the harness is usable in environments without Postgres/Redis
while still exercising the real stores in CI. Tests requiring a service should
depend on the corresponding fixture and/or carry the matching marker.
"""

from __future__ import annotations

import os
import uuid

import pytest
from hypothesis import HealthCheck, settings

# ---------------------------------------------------------------------------
# Hypothesis profile: minimum 100 iterations per property.
# ---------------------------------------------------------------------------

settings.register_profile(
    "foundation",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "foundation"))


# ---------------------------------------------------------------------------
# Ephemeral PostgreSQL schema fixture.
# ---------------------------------------------------------------------------

@pytest.fixture
def pg_schema():
    """Yield a SQLAlchemy Session bound to a fresh, isolated PostgreSQL schema.

    A uniquely named schema is created before the test and dropped (CASCADE)
    afterwards. The session's ``search_path`` is set to that schema so any
    tables created during the test live there and vanish on teardown. Skips if
    PostgreSQL is not reachable.
    """
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    from app.db import engine

    schema_name = f"test_{uuid.uuid4().hex}"

    try:
        connection = engine.connect()
    except SQLAlchemyError as exc:  # pragma: no cover - infra-dependent
        pytest.skip(f"PostgreSQL not reachable: {exc}")

    try:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
        connection.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - infra-dependent
        connection.close()
        pytest.skip(f"Could not create ephemeral schema: {exc}")

    from sqlalchemy.orm import Session

    session = Session(bind=connection)
    session.execute(text(f'SET search_path TO "{schema_name}"'))

    try:
        yield session
    finally:
        session.close()
        try:
            connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
            connection.commit()
        except SQLAlchemyError:  # pragma: no cover - best-effort cleanup
            connection.rollback()
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Redis test-namespace fixture.
# ---------------------------------------------------------------------------

class NamespacedRedis:
    """Thin wrapper prefixing every key with a per-test namespace.

    Only the handful of operations the Foundation needs (sessions, rate limits,
    short-lived recovery/re-auth state) are proxied; extend as needed. Keeps
    tests from colliding on shared keys and enables a scoped flush on teardown.
    """

    def __init__(self, client, namespace: str) -> None:
        self._client = client
        self._namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    def set(self, key: str, value, **kwargs):
        return self._client.set(self._key(key), value, **kwargs)

    def get(self, key: str):
        return self._client.get(self._key(key))

    def delete(self, *keys: str):
        return self._client.delete(*(self._key(k) for k in keys))

    def exists(self, *keys: str):
        return self._client.exists(*(self._key(k) for k in keys))

    def incr(self, key: str, amount: int = 1):
        return self._client.incr(self._key(key), amount)

    def expire(self, key: str, seconds: int):
        return self._client.expire(self._key(key), seconds)

    def ttl(self, key: str):
        return self._client.ttl(self._key(key))

    # -- hashes (session records) -----------------------------------------

    def hset(self, key: str, *args, **kwargs):
        return self._client.hset(self._key(key), *args, **kwargs)

    def hgetall(self, key: str):
        return self._client.hgetall(self._key(key))

    # -- sets (per-user session index) ------------------------------------

    def sadd(self, key: str, *values):
        return self._client.sadd(self._key(key), *values)

    def srem(self, key: str, *values):
        return self._client.srem(self._key(key), *values)

    def smembers(self, key: str):
        return self._client.smembers(self._key(key))

    def flush_namespace(self) -> None:
        keys = list(self._client.scan_iter(match=f"{self._namespace}:*"))
        if keys:
            self._client.delete(*keys)


@pytest.fixture
def redis_ns():
    """Yield a Redis client scoped to a unique per-test key namespace.

    All keys are prefixed with a unique namespace and flushed on teardown, so
    tests are isolated and leave no residue. Skips if Redis is unreachable.
    """
    from redis.exceptions import RedisError

    from app.redis import get_redis_client

    client = get_redis_client()
    try:
        client.ping()
    except RedisError as exc:  # pragma: no cover - infra-dependent
        pytest.skip(f"Redis not reachable: {exc}")

    namespaced = NamespacedRedis(client, f"test:{uuid.uuid4().hex}")
    try:
        yield namespaced
    finally:
        namespaced.flush_namespace()
        client.close()


# ---------------------------------------------------------------------------
# Versioned API test client (Phase 2: public API served under /api/v1).
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient as _FastAPITestClient

#: Public API version prefix (mirrors app.api.API_V1_PREFIX). Kept as a literal
#: here so a change to the app's prefix surfaces as a visible test update.
_API_V1_PREFIX = "/api/v1"

#: Paths that are intentionally NOT versioned (served at the application root).
_UNVERSIONED_PATHS = frozenset({"/health"})


class VersionedTestClient(_FastAPITestClient):
    """A :class:`TestClient` that serves the API under ``/api/v1``.

    Phase 2 moved the public API behind ``/api/v1`` (approved Decision A). The
    existing endpoint tests were written against unversioned paths (``/auth/...``,
    ``/couples/...``, ``/account/...``); rather than rewrite every literal, this
    client transparently prepends the version prefix to root-absolute request
    paths (except the unversioned liveness probe). New tests may also use plain
    paths like ``/reflections`` and get the same treatment.

    Only path-only, root-absolute URLs are rewritten; absolute URLs and
    already-prefixed paths are passed through unchanged so nothing double-prefixes.
    """

    def request(self, method: str, url, *args, **kwargs):  # type: ignore[override]
        url = self._versioned(url)
        return super().request(method, url, *args, **kwargs)

    @staticmethod
    def _versioned(url):
        if not isinstance(url, str):
            return url
        if not url.startswith("/"):
            return url  # absolute URL — leave as-is
        if url in _UNVERSIONED_PATHS:
            return url
        if url.startswith(_API_V1_PREFIX + "/") or url == _API_V1_PREFIX:
            return url  # already versioned
        return f"{_API_V1_PREFIX}{url}"
