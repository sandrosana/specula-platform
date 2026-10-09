from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.main import create_app
from app.services import totp
from app.services.secretbox import SecretBoxError, decrypt, encrypt

# RFC 6238 appendix B: ASCII "12345678901234567890", SHA-1; the 8-digit values cut to 6.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
KEY = "unit-test-secret-key-unit-test-secret-key"


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [(59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")],
)
def test_rfc6238_vectors(timestamp: int, expected: str) -> None:
    step = totp.step_at(datetime.fromtimestamp(timestamp, UTC))

    assert totp.code_at(RFC_SECRET, step) == expected


def test_verify_accepts_one_step_of_tolerance() -> None:
    at = datetime.fromtimestamp(1234567890, UTC)
    step = totp.step_at(at)

    for offset in (-1, 0, 1):
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + offset), at, None) == (
            step + offset
        )
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 2), at, None) is None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 2), at, None) is None


def test_verify_refuses_replay_and_malformed_codes() -> None:
    at = datetime.fromtimestamp(1234567890, UTC)
    step = totp.step_at(at)
    code = totp.code_at(RFC_SECRET, step)

    assert totp.verify(RFC_SECRET, code, at, last_step=step) is None
    assert totp.verify(RFC_SECRET, code, at, last_step=step - 1) == step
    assert totp.verify(RFC_SECRET, f"{code[:3]} {code[3:]}", at, None) == step
    for bad in ("", "12345", "1234567", "abcdef"):
        assert totp.verify(RFC_SECRET, bad, at, None) is None


def test_new_secret_and_uri() -> None:
    secret = totp.new_secret()
    uri = urlparse(totp.provisioning_uri(secret, "admin@example.it"))
    query = parse_qs(uri.query)

    assert len(secret) == 32 and secret.isalnum()
    assert uri.scheme == "otpauth" and uri.netloc == "totp"
    assert uri.path == "/Specula:admin@example.it"
    assert query["secret"] == [secret] and query["issuer"] == ["Specula"]
    assert query["digits"] == ["6"] and query["period"] == ["30"]


def test_recovery_codes() -> None:
    codes = totp.new_recovery_codes()

    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(len(code) == 11 and code[5] == "-" for code in codes)
    first = codes[0]
    assert totp.hash_recovery_code(first) == totp.hash_recovery_code(
        first.upper().replace("-", " ")
    )


def test_secretbox_roundtrip_and_tampering() -> None:
    sealed = encrypt(KEY, "JBSWY3DPEHPK3PXP")

    assert sealed.startswith("v1:") and "JBSWY3DPEHPK3PXP" not in sealed
    assert decrypt(KEY, sealed) == "JBSWY3DPEHPK3PXP"
    # A new nonce every time.
    assert encrypt(KEY, "JBSWY3DPEHPK3PXP") != sealed
    with pytest.raises(SecretBoxError):
        decrypt(KEY + "x", sealed)
    with pytest.raises(SecretBoxError):
        decrypt(KEY, sealed[:-4] + "AAAA")
    with pytest.raises(SecretBoxError):
        decrypt(KEY, "plain-value")


def test_secret_key_must_be_long(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="test", secret_key=SecretStr("short"))
    # `SECRET_KEY=` as in .env.example means "not set".
    monkeypatch.setenv("SECRET_KEY", "")
    assert Settings(environment="test").secret_key is None


def test_api_needs_the_secret_key_in_production() -> None:
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(Settings(environment="production"))
    create_app(Settings(environment="production", secret_key=SecretStr(KEY)))
