"""Second factor of the Admins against PostgreSQL (docs/architettura.md §10.4)."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import get_settings
from app.services import totp
from app.services.auth import SESSION_COOKIE
from app.users.__main__ import main as users_cli
from tests.db.auth import PASSWORD, add_user, api_client, csrf_headers, login
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

ADMIN = "admin@example.it"


async def _sql(database_url: str, sql: str) -> list[Any]:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(text(sql))
            return list(result) if result.returns_rows else []
    finally:
        await engine.dispose()


def sql(database_url: str, statement: str) -> list[Any]:
    return asyncio.run(_sql(database_url, statement))


def fresh_code(secret: str, database_url: str) -> str:
    """A valid code for a step after the last one used (codes are never accepted twice)."""
    [(last,)] = sql(database_url, "SELECT totp_last_step FROM users WHERE role = 'admin'")
    step = totp.step_at(datetime.now(UTC))
    if last is not None and step <= last:
        step = last + 1  # within the tolerance of one step
    return totp.code_at(secret, step)


def enrol(client: TestClient, database_url: str) -> tuple[str, list[str], str]:
    """Log in as the Admin and enrol. Returns secret, recovery codes and the full CSRF token."""
    csrf = login(client, ADMIN)
    setup = client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf))
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    activated = client.post(
        "/api/v1/auth/totp/activate",
        json={"code": fresh_code(secret, database_url)},
        headers=csrf_headers(csrf),
    )
    assert activated.status_code == 200, activated.text
    body = activated.json()
    return secret, body["recovery_codes"], body["user"]["csrf_token"]


def second_factor(client: TestClient, csrf: str, **payload: str) -> Any:
    return client.post("/api/v1/auth/totp", json=payload, headers=csrf_headers(csrf))


def test_admin_login_waits_for_the_second_factor(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        response = client.post("/api/v1/auth/login", json={"email": ADMIN, "password": PASSWORD})

        assert response.status_code == 200
        assert response.json()["mfa_required"] == "enroll"
        assert "max-age=300" in response.headers["set-cookie"].lower()
        # The pending session opens nothing but the second-factor step.
        for path in ("/api/v1/kev", "/api/v1/cves", "/api/v1/sources"):
            denied = client.get(path)
            assert (
                denied.status_code == 401 and denied.json()["detail"] == "Second factor required."
            )
        assert client.get("/api/v1/auth/me").json()["mfa_required"] == "enroll"


def test_enrolment_completes_the_login(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        csrf = login(client, ADMIN)
        pending_cookie = client.cookies[SESSION_COOKIE]
        setup = client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf))
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        assert setup.json()["otpauth_uri"].startswith("otpauth://totp/Specula:admin@example.it?")
        # The secret is stored encrypted.
        [(stored,)] = sql(migrated_database_url, "SELECT totp_pending_secret FROM users")
        assert stored.startswith("v1:") and secret not in stored

        wrong = client.post(
            "/api/v1/auth/totp/activate", json={"code": "000000"}, headers=csrf_headers(csrf)
        )
        assert wrong.status_code == 401
        activated = client.post(
            "/api/v1/auth/totp/activate",
            json={"code": fresh_code(secret, migrated_database_url)},
            headers=csrf_headers(csrf),
        )
        assert activated.status_code == 200
        body = activated.json()
        assert len(body["recovery_codes"]) == 10
        assert body["user"]["mfa_required"] is None
        # A new session token replaces the pending one.
        assert client.cookies[SESSION_COOKIE] != pending_cookie
        assert client.get("/api/v1/kev").status_code == 200
    [(enabled, pending_secret)] = sql(
        migrated_database_url, "SELECT totp_enabled, totp_pending_secret FROM users"
    )
    assert enabled is True and pending_secret is None
    assert sql(migrated_database_url, "SELECT count(*) FROM sessions") == [(1,)]


def test_next_logins_need_a_new_code(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        secret, _codes, full_csrf = enrol(client, migrated_database_url)
        [(last,)] = sql(migrated_database_url, "SELECT totp_last_step FROM users")
        used_code = totp.code_at(secret, last)
        client.post("/api/v1/auth/logout", headers=csrf_headers(full_csrf))

        csrf = login(client, ADMIN)
        assert client.get("/api/v1/auth/me").json()["mfa_required"] == "verify"
        # The code used for the enrolment cannot be replayed.
        assert second_factor(client, csrf, code=used_code).status_code == 401
        ok = second_factor(client, csrf, code=fresh_code(secret, migrated_database_url))
        assert ok.status_code == 200 and ok.json()["mfa_required"] is None
        assert client.get("/api/v1/cves").status_code == 200


def test_recovery_code_works_once(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        _secret, codes, full_csrf = enrol(client, migrated_database_url)
        client.post("/api/v1/auth/logout", headers=csrf_headers(full_csrf))

        csrf = login(client, ADMIN)
        used = second_factor(client, csrf, recovery_code=codes[0].upper())
        assert used.status_code == 200
        client.post("/api/v1/auth/logout", headers=csrf_headers(used.json()["csrf_token"]))

        csrf = login(client, ADMIN)
        assert second_factor(client, csrf, recovery_code=codes[0]).status_code == 401
        assert second_factor(client, csrf, recovery_code=codes[1]).status_code == 200


def test_wrong_codes_lock_the_account(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        secret, _codes, full_csrf = enrol(client, migrated_database_url)
        client.post("/api/v1/auth/logout", headers=csrf_headers(full_csrf))

        csrf = login(client, ADMIN)
        for _ in range(5):
            assert second_factor(client, csrf, code="000000").status_code == 401
        locked = second_factor(client, csrf, code=fresh_code(secret, migrated_database_url))
        assert locked.status_code == 401
    [(locked_until,)] = sql(migrated_database_url, "SELECT locked_until FROM users")
    assert locked_until is not None


def test_pending_session_expires_after_5_minutes(migrated_database_url: str) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        csrf = login(client, ADMIN)
        [(lifetime,)] = sql(migrated_database_url, "SELECT expires_at - created_at FROM sessions")
        assert lifetime.total_seconds() == 300
        sql(migrated_database_url, "UPDATE sessions SET expires_at = now() - interval '1 second'")
        assert client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf)).status_code == 401


def test_second_factor_steps_need_the_right_state(migrated_database_url: str) -> None:
    add_user(migrated_database_url, "viewer@example.it", "viewer")
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        # Viewers get a complete session at once: no second-factor step to take.
        csrf = login(client, "viewer@example.it")
        assert client.get("/api/v1/auth/me").json()["mfa_required"] is None
        assert client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf)).status_code == 409
    with api_client(migrated_database_url) as client:
        csrf = login(client, ADMIN)
        # Not enrolled yet: verification is not possible.
        assert second_factor(client, csrf, code="123456").status_code == 409
        assert client.post("/api/v1/auth/totp/setup").status_code == 403  # no CSRF token
        invalid = client.post(
            "/api/v1/auth/totp",
            json={"code": "123456", "recovery_code": "abcde-fghij"},
            headers=csrf_headers(csrf),
        )
        assert invalid.status_code == 422


def test_cli_resets_the_second_factor(
    migrated_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_user(migrated_database_url, ADMIN, "admin")
    with api_client(migrated_database_url) as client:
        enrol(client, migrated_database_url)
        monkeypatch.setenv("DATABASE_URL", migrated_database_url)
        get_settings.cache_clear()

        assert users_cli(["reset-totp", "--email", "nobody@example.it"]) == 1
        assert users_cli(["reset-totp", "--email", ADMIN]) == 0
        # Every session is closed and the next login starts a new enrolment.
        assert client.get("/api/v1/kev").status_code == 401
        login(client, ADMIN)
        assert client.get("/api/v1/auth/me").json()["mfa_required"] == "enroll"
    assert sql(migrated_database_url, "SELECT count(*) FROM user_recovery_codes") == [(0,)]
