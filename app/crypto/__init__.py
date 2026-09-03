"""Application-level cryptography (Phase 2).

A single, narrow encryption boundary used to protect particularly sensitive
field content at rest — currently Private Reflection content
(05-privacy/04-encryption-strategy.md §3). The module owns AES-256-GCM
encryption, nonce generation, key resolution through the
:class:`~app.config.SecretsProvider`, and the versioned self-describing envelope
so future key rotation is possible without a schema change.

Nothing here performs authorization: whether a caller may access a resource is
decided by the authorization layer *before* any decryption is attempted
(app/authorization). This module only answers "given access is authorized, can
the stored ciphertext be read?".
"""

from __future__ import annotations

from app.crypto.encryption import (
    ContentCipher,
    DecryptionError,
    EncryptionConfigError,
    EncryptionError,
    get_content_cipher,
)

__all__ = [
    "ContentCipher",
    "EncryptionError",
    "DecryptionError",
    "EncryptionConfigError",
    "get_content_cipher",
]
