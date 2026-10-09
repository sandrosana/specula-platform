"""Password hashing and rules (docs/architettura.md §10.4, NIST SP 800-63B).

- argon2id with the library's default parameters;
- 14 to 128 characters, any character, no composition rules, no expiry;
- rejected when listed in the local list of common or breached passwords
  (`data/common-passwords.txt`, see its header for source and licence) or when
  it contains the local part of the user's email. No external service is called.
"""

import unicodedata
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 14
MAX_LENGTH = 128
# The local part must be at least this long to be checked: "a@x.it" would reject too much.
MIN_EMAIL_PART = 3
COMMON_PASSWORDS = Path(__file__).with_name("data") / "common-passwords.txt"

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# Verified against when the email is unknown, so both cases take the same time.
DUMMY_HASH = hash_password("specula-dummy-password-for-timing")


def _normalize(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def read_password_list(lines: Iterable[str]) -> frozenset[str]:
    """Normalized entries; lines starting with '#' are comments."""
    return frozenset(
        _normalize(line.strip()) for line in lines if line.strip() and not line.startswith("#")
    )


@lru_cache
def common_passwords() -> frozenset[str]:
    with COMMON_PASSWORDS.open(encoding="utf-8") as lines:
        return read_password_list(lines)


def password_problems(
    password: str, email: str, blocked: frozenset[str] | None = None
) -> list[str]:
    """Rule codes the password breaks; empty when it is acceptable.

    Codes (translated by the UI): too_short, too_long, common, contains_email.
    """
    problems: list[str] = []
    length = len(password)
    if length < MIN_LENGTH:
        problems.append("too_short")
    if length > MAX_LENGTH:
        problems.append("too_long")
    normalized = _normalize(password)
    if normalized in (common_passwords() if blocked is None else blocked):
        problems.append("common")
    local_part = _normalize(email.split("@", 1)[0])
    if len(local_part) >= MIN_EMAIL_PART and local_part in normalized:
        problems.append("contains_email")
    return problems
