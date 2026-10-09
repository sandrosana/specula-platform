"""TOTP second factor for Admins (RFC 6238, docs/architettura.md §10.4).

SHA-1, 6 digits, 30-second step, one step of tolerance on each side: the
parameters every authenticator app supports. A code is accepted only for a step
later than the last one used, so the same code never works twice.
"""

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
TOLERANCE = 1
SECRET_BYTES = 20
ISSUER = "Specula"
RECOVERY_CODES = 10
# 10 base32 characters: 50 random bits per recovery code.
RECOVERY_LENGTH = 10


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def step_at(at: datetime) -> int:
    return int(at.timestamp()) // STEP_SECONDS


def code_at(secret: str, step: int) -> str:
    """HOTP value of `step` (RFC 4226)."""
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, at: datetime, last_step: int | None) -> int | None:
    """The step matched by `code`, or None. Steps up to `last_step` are refused (replay)."""
    candidate = "".join(code.split())
    if len(candidate) != DIGITS or not candidate.isdigit():
        return None
    current = step_at(at)
    for step in range(current - TOLERANCE, current + TOLERANCE + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), candidate):
            return step
    return None


def provisioning_uri(secret: str, account: str) -> str:
    """otpauth:// URI for the QR code shown by the UI."""
    label = quote(f"{ISSUER}:{account}", safe="@:")
    query = urlencode(
        {
            "secret": secret,
            "issuer": ISSUER,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def normalize_recovery_code(code: str) -> str:
    return "".join(code.split()).replace("-", "").lower()


def new_recovery_codes() -> list[str]:
    """Shown once to the user, formatted as xxxxx-xxxxx."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = base64.b32encode(secrets.token_bytes(8)).decode("ascii").lower()[:RECOVERY_LENGTH]
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(code: str) -> str:
    # High-entropy random codes: a fast hash is enough, unlike passwords.
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii")).hexdigest()
