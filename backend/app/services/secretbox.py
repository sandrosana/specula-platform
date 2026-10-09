"""Encryption of small secrets stored in the database (TOTP secrets).

AES-256-GCM with a key derived from SECRET_KEY by HKDF-SHA256. Values are stored
as "v1:" + base64(nonce + ciphertext). Rotating SECRET_KEY makes existing values
unreadable: the Admins enrol the second factor again (docs/architettura.md §10.4).
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = "v1:"
NONCE_BYTES = 12
INFO = b"specula totp secret v1"


class SecretBoxError(Exception):
    """The value cannot be decrypted (wrong key or corrupted data)."""


def _cipher(secret_key: str) -> AESGCM:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(
        secret_key.encode("utf-8")
    )
    return AESGCM(key)


def encrypt(secret_key: str, plaintext: str) -> str:
    nonce = os.urandom(NONCE_BYTES)
    sealed = _cipher(secret_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt(secret_key: str, value: str) -> str:
    if not value.startswith(PREFIX):
        raise SecretBoxError("unknown format")
    try:
        raw = base64.b64decode(value[len(PREFIX) :], validate=True)
        opened = _cipher(secret_key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], None)
    except (InvalidTag, ValueError) as exc:
        raise SecretBoxError("cannot decrypt") from exc
    return opened.decode("utf-8")
