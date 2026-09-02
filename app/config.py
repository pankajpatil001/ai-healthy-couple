"""Application configuration and managed-secrets abstraction.

This module centralizes all runtime configuration for the Foundation slice and
provides the boundary through which secrets are obtained. Two concerns are kept
distinct:

1. **Non-secret settings** (URLs, TTLs, feature flags) are loaded from the
   process environment via :class:`Settings` (pydantic-settings). These are safe
   to read directly and have sensible local defaults so the app imports cleanly
   in development.

2. **Secrets and key material** (identity-provider client secrets, signing keys,
   database passwords embedded in a DSN, etc.) are obtained exclusively through a
   :class:`SecretsProvider`. Per the technology stack, secrets/keys live in a
   **managed secrets / KMS** service and are *never* committed to code
   (08-technology-stack.md §9, §11). No secret literal is present in this file.

The `SecretsProvider` protocol lets the application depend on an abstraction
rather than a concrete vault. In production this is backed by the managed
secrets manager / KMS; in local development the :class:`EnvSecretsProvider`
resolves the same logical secret names from environment variables so nothing
secret is hard-coded.

Design references:
- 08-technology-stack.md §5 (Redis for sessions/rate-limiting/short-lived state),
  §9 (delegated auth / identity provider), §11 (managed secrets/KMS).
- Requirements 2.4 (no sensitive account data in tokens) and 3.1 (session expiry)
  are supported here by exposing session/recovery/re-auth TTL configuration and
  the Redis wiring those services rely on.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Protocol, runtime_checkable

from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Non-secret settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Environment-driven, non-secret application settings.

    Values are read from environment variables (optionally an ``.env`` file in
    development). Secrets are intentionally excluded — they flow through a
    :class:`SecretsProvider` instead. Fields here are safe operational knobs.

    TTL fields are expressed in seconds and back the Redis-stored state used by
    the auth services (sessions, rate limiting, and short-lived recovery /
    re-auth grants).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Environment ------------------------------------------------------
    environment: str = "development"
    debug: bool = False

    # --- Datastores -------------------------------------------------------
    # DSNs may contain credentials in managed environments; there they should be
    # injected via the secrets provider. The local defaults are credential-free
    # so nothing secret is hard-coded here.
    database_url: str = "postgresql+psycopg://localhost:5432/healthy_couple"
    redis_url: str = "redis://localhost:6379/0"

    # --- Redis key namespacing -------------------------------------------
    # Prefixes keep sessions, rate limits, recovery, and re-auth state cleanly
    # separated within a single Redis instance/database.
    redis_key_prefix: str = "hc"
    session_key_prefix: str = "session"
    rate_limit_key_prefix: str = "ratelimit"
    recovery_key_prefix: str = "recovery"
    reauth_key_prefix: str = "reauth"

    # --- Session / auth TTLs (seconds) -----------------------------------
    session_ttl_seconds: int = 60 * 60 * 24 * 14  # 14 days — R3.1 session expiry
    recovery_challenge_ttl_seconds: int = 60 * 15  # 15 min — single-use challenge
    reauth_grant_ttl_seconds: int = 60 * 5  # 5 min — single-operation re-auth grant
    # Short-lived couple invitation: PENDING with a future expires_at (R10.2).
    # A couple invitation is single-purpose and time-limited; 7 days gives the
    # invitee ample time to accept while keeping stale tokens from lingering.
    invitation_ttl_seconds: int = 60 * 60 * 24 * 7  # 7 days — R10.2 invitation expiry

    # --- Rate limiting ----------------------------------------------------
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 120

    # --- Identity provider (managed auth) --------------------------------
    # Only the non-secret coordinates of the IdP live here; the client secret is
    # resolved via the SecretsProvider under `identity_provider_client_secret`.
    identity_provider_issuer: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance.

    Cached so configuration is parsed once per process. Tests that need to vary
    the environment can call ``get_settings.cache_clear()``.
    """
    return Settings()


# ---------------------------------------------------------------------------
# Managed secrets / KMS abstraction
# ---------------------------------------------------------------------------


class SecretNotFoundError(KeyError):
    """Raised when a requested secret is not available from the provider."""


@runtime_checkable
class SecretsProvider(Protocol):
    """Abstraction over a managed secrets / KMS service.

    The application depends on this protocol rather than a concrete vault so the
    backing implementation (a cloud secrets manager, KMS, or a local
    environment-based shim for development) can be swapped without touching call
    sites. Implementations MUST NOT log or otherwise expose secret values.
    """

    def get_secret(self, name: str) -> str:
        """Return the secret value for ``name``.

        Raises:
            SecretNotFoundError: if no secret is registered under ``name``.
        """
        ...

    def try_get_secret(self, name: str) -> str | None:
        """Return the secret value for ``name`` or ``None`` if absent."""
        ...


class EnvSecretsProvider:
    """Development / self-hosted :class:`SecretsProvider` backed by the environment.

    Resolves logical secret names to environment variables. A logical name such
    as ``identity_provider_client_secret`` maps to the environment variable
    ``HC_SECRET_IDENTITY_PROVIDER_CLIENT_SECRET`` (configurable prefix). This
    keeps secrets out of source while presenting the same interface a managed
    KMS-backed provider would.

    In production this is replaced by a provider that reads from the managed
    secrets manager / KMS; call sites remain unchanged because both satisfy
    :class:`SecretsProvider`.
    """

    def __init__(self, env_prefix: str = "HC_SECRET_") -> None:
        self._env_prefix = env_prefix

    def _env_key(self, name: str) -> str:
        return f"{self._env_prefix}{name.upper()}"

    def get_secret(self, name: str) -> str:
        value = self.try_get_secret(name)
        if value is None:
            raise SecretNotFoundError(
                f"Secret '{name}' is not configured. Provide it via the managed "
                f"secrets provider (env var '{self._env_key(name)}' for the "
                "environment-backed provider)."
            )
        return value

    def try_get_secret(self, name: str) -> str | None:
        return os.environ.get(self._env_key(name))


@lru_cache(maxsize=1)
def get_secrets_provider() -> SecretsProvider:
    """Return the process-wide :class:`SecretsProvider`.

    Defaults to the environment-backed provider. Production wiring can override
    this by clearing the cache and swapping in a managed KMS-backed provider;
    because callers depend only on the :class:`SecretsProvider` protocol, no call
    site changes are required.
    """
    return EnvSecretsProvider()


__all__ = [
    "Settings",
    "get_settings",
    "SecretsProvider",
    "EnvSecretsProvider",
    "SecretNotFoundError",
    "get_secrets_provider",
]
