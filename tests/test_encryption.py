"""Tests for the AES-256-GCM content-encryption boundary (app/crypto).

These are pure unit tests: no PostgreSQL or Redis required. They prove the
Phase 2 encryption invariants — round trip, fresh-nonce non-determinism, tamper
detection, malformed-envelope handling, unknown/missing key handling, and that
no plaintext/key material leaks through error messages.
"""

from __future__ import annotations

import base64
import os

import pytest

from app.crypto.encryption import (
    ContentCipher,
    DecryptionError,
    EncryptionConfigError,
    EncryptionError,
    _secret_name_for_key_id,
)


class _DictSecrets:
    """Minimal in-memory SecretsProvider for tests (name -> value)."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def get_secret(self, name: str) -> str:
        from app.config import SecretNotFoundError

        try:
            return self._secrets[name]
        except KeyError as exc:
            raise SecretNotFoundError(name) from exc

    def try_get_secret(self, name: str) -> str | None:
        return self._secrets.get(name)


def _key_b64() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _cipher(key_id: str = "reflection-v1", *, key: str | None = None) -> ContentCipher:
    key = key or _key_b64()
    secrets = _DictSecrets({_secret_name_for_key_id(key_id): key})
    return ContentCipher(active_key_id=key_id, secrets_provider=secrets)


def test_round_trip_recovers_plaintext():
    cipher = _cipher()
    plaintext = "I felt unheard during our conversation last night."
    envelope = cipher.encrypt(plaintext)
    assert cipher.decrypt(envelope) == plaintext


def test_envelope_format_is_versioned_with_key_id():
    cipher = _cipher(key_id="reflection-v1")
    envelope = cipher.encrypt("hello")
    parts = envelope.split(":")
    assert len(parts) == 4
    assert parts[0] == "v1"
    assert parts[1] == "reflection-v1"


def test_ciphertext_does_not_contain_plaintext():
    cipher = _cipher()
    plaintext = "SECRET-REFLECTION-CONTENT-MARKER"
    envelope = cipher.encrypt(plaintext)
    assert plaintext not in envelope


def test_fresh_nonce_makes_repeated_encryption_nondeterministic():
    cipher = _cipher()
    plaintext = "same content twice"
    a = cipher.encrypt(plaintext)
    b = cipher.encrypt(plaintext)
    assert a != b  # different nonce -> different envelope
    # ...but both decrypt back to the same plaintext.
    assert cipher.decrypt(a) == plaintext
    assert cipher.decrypt(b) == plaintext


def test_unicode_and_large_content_round_trip():
    cipher = _cipher()
    plaintext = "emoji 😊 and नमस्ते and 日本語 " + ("x" * 20000)
    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext


def test_tampered_ciphertext_fails_closed():
    cipher = _cipher()
    envelope = cipher.encrypt("original content")
    version, key_id, nonce_b64, ct_b64 = envelope.split(":")
    # Flip a byte in the ciphertext+tag.
    ct = bytearray(base64.urlsafe_b64decode(ct_b64))
    ct[0] ^= 0x01
    tampered = ":".join(
        (version, key_id, nonce_b64, base64.urlsafe_b64encode(bytes(ct)).decode())
    )
    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered)


def test_wrong_key_fails_closed():
    key_id = "reflection-v1"
    enc = _cipher(key_id=key_id)
    envelope = enc.encrypt("content")
    # A different cipher with the SAME key id but DIFFERENT key material.
    wrong = _cipher(key_id=key_id, key=_key_b64())
    with pytest.raises(DecryptionError):
        wrong.decrypt(envelope)


def test_unknown_key_id_in_envelope_is_config_error():
    cipher = _cipher(key_id="reflection-v1")
    envelope = cipher.encrypt("content")
    # Rewrite the envelope to name a key id the provider does not know.
    _, _, nonce_b64, ct_b64 = envelope.split(":")
    unknown = ":".join(("v1", "reflection-v99", nonce_b64, ct_b64))
    with pytest.raises(EncryptionConfigError):
        cipher.decrypt(unknown)


def test_missing_key_material_on_encrypt_is_config_error():
    # Provider has no secret for the active key id.
    secrets = _DictSecrets({})
    cipher = ContentCipher(active_key_id="reflection-v1", secrets_provider=secrets)
    with pytest.raises(EncryptionConfigError):
        cipher.encrypt("content")


def test_wrong_length_key_is_config_error():
    key_id = "reflection-v1"
    short_key = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")  # 128-bit
    secrets = _DictSecrets({_secret_name_for_key_id(key_id): short_key})
    cipher = ContentCipher(active_key_id=key_id, secrets_provider=secrets)
    with pytest.raises(EncryptionConfigError):
        cipher.encrypt("content")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-an-envelope",
        "v1:reflection-v1:only-three",
        "v2:reflection-v1:AAAA:BBBB",  # unsupported version
        "v1::AAAA:BBBB",  # empty key id
        "v1:reflection-v1:!!notb64!!:BBBB",  # bad base64 nonce
    ],
)
def test_malformed_envelope_fails_closed(bad):
    cipher = _cipher()
    with pytest.raises(DecryptionError):
        cipher.decrypt(bad)


def test_errors_do_not_leak_plaintext_or_key(caplog):
    key_id = "reflection-v1"
    key = _key_b64()
    enc = _cipher(key_id=key_id, key=key)
    plaintext = "TOP-SECRET-REFLECTION"
    envelope = enc.encrypt(plaintext)
    wrong = _cipher(key_id=key_id, key=_key_b64())
    with pytest.raises(EncryptionError) as exc_info:
        wrong.decrypt(envelope)
    message = str(exc_info.value)
    assert plaintext not in message
    assert key not in message
    # No plaintext/key emitted to logs either.
    assert plaintext not in caplog.text
    assert key not in caplog.text
