"""AES-256-GCM application-level encryption for sensitive field content.

This is the single encryption boundary for Phase 2 (Private Reflection content).
It provides authenticated encryption with a fresh random nonce per operation, a
versioned self-describing envelope, and key resolution through the existing
:class:`~app.config.SecretsProvider`.

Design decisions (approved Phase 2):

* **Algorithm** — AES-256-GCM (via :mod:`cryptography`). GCM is *authenticated*
  encryption: any tampering with the ciphertext (or its embedded nonce/tag) is
  detected on decrypt and fails closed with :class:`DecryptionError`.
* **Nonce** — a fresh 96-bit (12-byte) nonce from a CSPRNG per encryption. 96
  bits is the size AES-GCM is specified for; a random nonce per operation means
  encrypting the same plaintext twice yields different ciphertext.
* **Key material** — 32 bytes (256-bit) resolved through the
  :class:`~app.config.SecretsProvider`. Keys are **never** hard-coded, logged,
  or stored in the database (05-privacy/04-encryption-strategy.md §4, §8).
* **Envelope** — ``v1:<key_id>:<nonce_b64>:<ciphertext_and_tag_b64>``. The
  ``key_id`` is embedded so a record encrypted under one key stays decryptable
  after the active key advances (future rotation without a schema change; not
  implemented in Phase 2). ``<ciphertext_and_tag_b64>`` is exactly what
  :class:`AESGCM.encrypt` returns (ciphertext with the 16-byte tag appended).

Failure model (fail closed):

* Missing/short key material or an unknown ``key_id`` → :class:`EncryptionConfigError`.
* Any decrypt failure — wrong key, tampered ciphertext, malformed envelope,
  bad base64 — → :class:`DecryptionError`.

No plaintext, key material, or raw ciphertext bytes are ever included in
exception messages or logs.
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import (
    SecretNotFoundError,
    SecretsProvider,
    Settings,
    get_secrets_provider,
    get_settings,
)

#: Envelope format version. Only ``v1`` is understood today; the prefix lets a
#: future format change be detected and rejected rather than silently mis-parsed.
_ENVELOPE_VERSION = "v1"

#: Envelope field separator. ``:`` is safe because every variable field is
#: base64 (which never contains ``:``) and the key id is a constrained label.
_SEP = ":"

#: AES-GCM nonce length in bytes (96 bits — the size AES-GCM is specified for).
_NONCE_BYTES = 12

#: Required symmetric key length in bytes (AES-256 → 32 bytes).
_KEY_BYTES = 32

#: Logical secret-name prefix under which per-key material is registered with the
#: SecretsProvider. The concrete secret name is this prefix + a normalised key id
#: (e.g. key id ``reflection-v1`` -> ``reflection_encryption_key_reflection_v1``,
#: env var ``HC_SECRET_REFLECTION_ENCRYPTION_KEY_REFLECTION_V1``).
_SECRET_NAME_PREFIX = "reflection_encryption_key_"


class EncryptionError(Exception):
    """Base class for encryption-boundary failures.

    Messages are deliberately generic — they never contain plaintext, key
    material, or raw ciphertext.
    """


class EncryptionConfigError(EncryptionError):
    """Key material is missing, malformed, or of the wrong length.

    Raised on encrypt (active key unavailable) or decrypt (the key id embedded
    in the envelope is not configured). Treated as fail-closed by callers.
    """


class DecryptionError(EncryptionError):
    """Ciphertext could not be authenticated/decrypted.

    Covers a wrong key, tampered ciphertext/nonce/tag, a malformed envelope, and
    invalid base64. All of these collapse to one error so a caller cannot use the
    failure mode to distinguish, for example, "wrong key" from "tampered".
    """


def _secret_name_for_key_id(key_id: str) -> str:
    """Return the SecretsProvider logical name holding ``key_id``'s material.

    Normalises the key id to the lower-snake shape the env-backed provider maps
    to an environment variable (``-`` and ``.`` -> ``_``).
    """
    normalised = key_id.strip().lower().replace("-", "_").replace(".", "_")
    return f"{_SECRET_NAME_PREFIX}{normalised}"


def _decode_key_material(raw: str) -> bytes:
    """Decode a provider-supplied key string to exactly 32 raw bytes.

    Accepts either base64 (standard or url-safe) or raw UTF-8 bytes of the right
    length. Raises :class:`EncryptionConfigError` if the result is not exactly
    :data:`_KEY_BYTES` bytes. The key value itself is never included in the error.
    """
    if not isinstance(raw, str) or not raw:
        raise EncryptionConfigError("Encryption key material is not configured.")

    candidate: bytes | None = None
    # Try base64 first (the recommended way to carry 32 random bytes in an env
    # var); fall back to raw UTF-8 bytes for operator convenience.
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(raw)
        except (ValueError, TypeError):
            continue
        if len(decoded) == _KEY_BYTES:
            candidate = decoded
            break

    if candidate is None:
        raw_bytes = raw.encode("utf-8")
        if len(raw_bytes) == _KEY_BYTES:
            candidate = raw_bytes

    if candidate is None or len(candidate) != _KEY_BYTES:
        raise EncryptionConfigError(
            "Encryption key material must decode to 32 bytes (AES-256)."
        )
    return candidate


class ContentCipher:
    """Encrypt/decrypt field content with AES-256-GCM and a versioned envelope.

    Constructed with the *active* ``key_id`` (used for new writes) and a
    :class:`~app.config.SecretsProvider` used to resolve key material on demand.
    Resolved keys are cached in-process per key id so repeated operations do not
    re-hit the provider; the cache holds raw key bytes and is never logged.
    """

    def __init__(
        self,
        *,
        active_key_id: str,
        secrets_provider: SecretsProvider,
    ) -> None:
        if not active_key_id:
            raise EncryptionConfigError("No active encryption key id is configured.")
        self._active_key_id = active_key_id
        self._secrets = secrets_provider
        self._key_cache: dict[str, bytes] = {}

    @property
    def active_key_id(self) -> str:
        """The key id stamped into newly-encrypted envelopes."""
        return self._active_key_id

    # -- key resolution ---------------------------------------------------

    def _key_for(self, key_id: str) -> AESGCM:
        """Resolve (and cache) the AES-GCM primitive for ``key_id``.

        Raises :class:`EncryptionConfigError` if the key is not configured or is
        the wrong length. The AESGCM object wraps the raw key; we cache the raw
        bytes so a fresh AESGCM can be rebuilt cheaply without another provider
        round-trip.
        """
        material = self._key_cache.get(key_id)
        if material is None:
            secret_name = _secret_name_for_key_id(key_id)
            try:
                raw = self._secrets.get_secret(secret_name)
            except SecretNotFoundError as exc:
                # Do not echo the secret name's value; the name itself is a
                # non-secret label and is safe to reference for operability.
                raise EncryptionConfigError(
                    f"Encryption key '{key_id}' is not configured."
                ) from exc
            material = _decode_key_material(raw)
            self._key_cache[key_id] = material
        return AESGCM(material)

    # -- encrypt / decrypt ------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Encrypt ``plaintext`` under the active key and return the envelope.

        A fresh 96-bit nonce is generated per call, so identical plaintext yields
        distinct ciphertext. Returns ``v1:<key_id>:<nonce_b64>:<ct+tag_b64>``.

        Raises:
            EncryptionConfigError: if the active key material is unavailable/invalid.
        """
        if not isinstance(plaintext, str):
            raise EncryptionError("Plaintext to encrypt must be a string.")
        aesgcm = self._key_for(self._active_key_id)
        nonce = os.urandom(_NONCE_BYTES)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return _SEP.join(
            (
                _ENVELOPE_VERSION,
                self._active_key_id,
                base64.urlsafe_b64encode(nonce).decode("ascii"),
                base64.urlsafe_b64encode(ct_and_tag).decode("ascii"),
            )
        )

    def decrypt(self, envelope: str) -> str:
        """Decrypt a ``v1`` envelope and return the plaintext.

        Parses the envelope, resolves the key id it names, and authenticates +
        decrypts. Any problem — malformed envelope, unknown version, bad base64,
        wrong key, or tampered ciphertext — fails closed. A missing/invalid key
        for the named id surfaces as :class:`EncryptionConfigError`; every other
        failure surfaces as :class:`DecryptionError`.
        """
        if not isinstance(envelope, str) or not envelope:
            raise DecryptionError("Ciphertext envelope is missing or malformed.")

        parts = envelope.split(_SEP)
        if len(parts) != 4:
            raise DecryptionError("Ciphertext envelope is malformed.")
        version, key_id, nonce_b64, ct_b64 = parts
        if version != _ENVELOPE_VERSION:
            raise DecryptionError("Unsupported ciphertext envelope version.")
        if not key_id:
            raise DecryptionError("Ciphertext envelope is missing a key id.")

        try:
            nonce = base64.urlsafe_b64decode(nonce_b64)
            ct_and_tag = base64.urlsafe_b64decode(ct_b64)
        except (ValueError, TypeError) as exc:
            raise DecryptionError("Ciphertext envelope is malformed.") from exc

        if len(nonce) != _NONCE_BYTES:
            raise DecryptionError("Ciphertext envelope is malformed.")

        # Resolve the key named by the envelope (EncryptionConfigError if absent).
        aesgcm = self._key_for(key_id)
        try:
            plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
        except InvalidTag as exc:
            # Wrong key or tampered ciphertext/tag — indistinguishable by design.
            raise DecryptionError("Ciphertext could not be authenticated.") from exc
        return plaintext.decode("utf-8")


@lru_cache(maxsize=1)
def get_content_cipher() -> ContentCipher:
    """Return the process-wide :class:`ContentCipher` for reflection content.

    Built from the active key id in :class:`~app.config.Settings` and the
    process :class:`~app.config.SecretsProvider`. Cached so configuration is read
    once; tests can clear the cache via ``get_content_cipher.cache_clear()`` (and
    should also clear ``get_settings``/``get_secrets_provider`` caches when they
    vary the environment).
    """
    settings: Settings = get_settings()
    return ContentCipher(
        active_key_id=settings.reflection_encryption_key_id,
        secrets_provider=get_secrets_provider(),
    )


__all__ = [
    "ContentCipher",
    "EncryptionError",
    "DecryptionError",
    "EncryptionConfigError",
    "get_content_cipher",
]
