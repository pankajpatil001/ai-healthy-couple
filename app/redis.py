"""Redis client and key wiring.

Redis backs sessions, rate limiting, and short-lived recovery / re-auth state
(08-technology-stack.md §5). It is never the authoritative source for permanent
relationship data.

Configuration is now sourced from :mod:`app.config` (task 1.2): the connection
URL and the key-namespace prefixes come from :class:`~app.config.Settings`
rather than being read ad hoc from the environment. The module still imports
cleanly with local defaults because ``Settings`` provides them.

The key-builder helpers below give each concern its own namespace so the four
Redis use-cases stay cleanly separated within a single instance:

- **sessions** — ``{prefix}:session:{session_id}`` (server-side session records;
  TTL mirrors the session expiry, supporting R3.1).
- **rate limiting** — ``{prefix}:ratelimit:{scope}:{identifier}`` (fixed-window
  counters; also feeds enumeration-attempt signals).
- **recovery** — ``{prefix}:recovery:{challenge_id}`` (single-use, time-limited
  recovery challenges).
- **re-auth** — ``{prefix}:reauth:{grant_id}`` (short-lived, single-operation
  re-authentication grants gating Sensitive_Operations).
"""

from __future__ import annotations

import redis

from app.config import Settings, get_settings


def get_redis_client(settings: Settings | None = None) -> "redis.Redis":
    """Return a Redis client built from application settings.

    ``decode_responses=True`` so callers work with ``str`` rather than bytes for
    the small metadata values stored here (session records, rate-limit counters,
    recovery challenges, and re-auth grants).

    Args:
        settings: optional :class:`~app.config.Settings`; defaults to the cached
            process settings. Tests can pass a settings instance pointing at a
            dedicated Redis database/namespace for isolation.
    """
    settings = settings or get_settings()
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


# ---------------------------------------------------------------------------
# Key namespacing helpers
# ---------------------------------------------------------------------------


def _join(*parts: str) -> str:
    return ":".join(part for part in parts if part)


def session_key(session_id: str, settings: Settings | None = None) -> str:
    """Redis key for a server-side session record."""
    settings = settings or get_settings()
    return _join(settings.redis_key_prefix, settings.session_key_prefix, session_id)


def rate_limit_key(
    scope: str, identifier: str, settings: Settings | None = None
) -> str:
    """Redis key for a rate-limit counter.

    ``scope`` distinguishes the limited action (e.g. ``login``, ``recovery``,
    ``resource-read``); ``identifier`` is the actor/IP the window applies to.
    """
    settings = settings or get_settings()
    return _join(
        settings.redis_key_prefix,
        settings.rate_limit_key_prefix,
        scope,
        identifier,
    )


def recovery_key(challenge_id: str, settings: Settings | None = None) -> str:
    """Redis key for a single-use, time-limited account-recovery challenge."""
    settings = settings or get_settings()
    return _join(settings.redis_key_prefix, settings.recovery_key_prefix, challenge_id)


def reauth_key(grant_id: str, settings: Settings | None = None) -> str:
    """Redis key for a short-lived, single-operation re-authentication grant."""
    settings = settings or get_settings()
    return _join(settings.redis_key_prefix, settings.reauth_key_prefix, grant_id)


# A module-level client for simple reuse. Callers that need isolation
# (e.g. tests using a dedicated namespace/database) can build their own via the
# factory with an explicit ``Settings``.
redis_client = get_redis_client()


__all__ = [
    "get_redis_client",
    "redis_client",
    "session_key",
    "rate_limit_key",
    "recovery_key",
    "reauth_key",
]
