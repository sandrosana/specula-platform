"""Local login against PostgreSQL (docs/architettura.md §10.4)."""

import asyncio
import io
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import get_settings
from app.services.auth import SESSION_COOKIE
from app.users.__main__ import main as users_cli
from tests.db.auth import PASSWORD, add_user, api_client, csrf_headers, login
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS

EMAIL = "mario.rossi@example.it"
INVALID = "Invalid email or password."


async def _sql(database_url: str, sql: str, params: dict[str, Any] | None = None) -> list[Any]:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(text(sql), params or {})
            return list(result) if result.returns_rows else []
    finally:
        await engine.dispose()


def sql(database_url: str, statement: str, params: dict[str, Any] | None = None) -> list[Any]:
    return asyncio.run(_sql(database_url, statement, params))


def attempt(client: Any, password: str, email: str = EMAIL) -> Any:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_data_needs_a_login(migrated_database_url: str) -> None:
    with api_client(migrated_database_url) as client:
        for path in ("/api/v1/kev", "/api/v1/cves", "/api/v1/sources", "/api/v1/auth/me"):
            response = client.get(path)
            assert response.status_code == 401, path
            assert response.headers["content-type"].startswith("application/problem+json")
        assert client.get("/api/v1/health").status_code == 200


def test_login_sets_a_protected_session_cookie(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL, "analyst")
    with api_client(migrated_database_url) as client:
        response = attempt(client, PASSWORD, email="  Mario.Rossi@Example.IT ")

        assert response.status_code == 200
        body = response.json()
        assert body["email"] == EMAIL and body["role"] == "analyst"
        assert body["must_change_password"] is False and len(body["csrf_token"]) >= 32
        assert response.headers["cache-control"] == "no-store"
        cookie = response.headers["set-cookie"].lower()
        for attribute in ("httponly", "secure", "samesite=strict", "path=/", "max-age=36000"):
            assert attribute in cookie
        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200 and me.json()["csrf_token"] == body["csrf_token"]
        assert client.get("/api/v1/kev").status_code == 200
    # Only the hash of the token is stored.
    [(stored,)] = sql(migrated_database_url, "SELECT token_hash FROM sessions")
    assert len(stored) == 64 and stored not in cookie


def test_unknown_email_and_wrong_password_look_the_same(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        wrong = attempt(client, "not-the-password-at-all")
        unknown = attempt(client, PASSWORD, email="nobody@example.it")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"] == INVALID


def test_five_failures_lock_the_account_for_15_minutes(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        for _ in range(5):
            assert attempt(client, "not-the-password-at-all").status_code == 401
        # Locked: even the right password is refused, with the same message.
        locked = attempt(client, PASSWORD)
        assert locked.status_code == 401 and locked.json()["detail"] == INVALID
        [(locked_until,)] = sql(migrated_database_url, "SELECT locked_until FROM users")
        remaining = locked_until - datetime.now(UTC)
        assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)

        # 15 minutes later the account unlocks by itself.
        sql(migrated_database_url, "UPDATE users SET locked_until = now() - interval '1 second'")
        assert attempt(client, PASSWORD).status_code == 200
    [(failed, still_locked)] = sql(
        migrated_database_url, "SELECT failed_logins, locked_until FROM users"
    )
    assert failed == 0 and still_locked is None


def test_success_resets_the_failure_count(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        for _ in range(4):
            attempt(client, "not-the-password-at-all")
        assert attempt(client, PASSWORD).status_code == 200
        for _ in range(4):
            attempt(client, "not-the-password-at-all")
        assert attempt(client, PASSWORD).status_code == 200


def test_too_many_failures_from_one_address(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    sql(
        migrated_database_url,
        "INSERT INTO login_failures (ip, attempted_at) "
        "SELECT 'testclient', now() - interval '5 minutes' FROM generate_series(1, 20)",
    )
    with api_client(migrated_database_url) as client:
        assert attempt(client, PASSWORD).status_code == 429
    # Failures older than the 10-minute window do not count.
    sql(migrated_database_url, "UPDATE login_failures SET attempted_at = now() - interval '11 min'")
    with api_client(migrated_database_url) as client:
        assert attempt(client, PASSWORD).status_code == 200


def test_disabled_user_cannot_log_in(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    sql(migrated_database_url, "UPDATE users SET is_active = false")
    with api_client(migrated_database_url) as client:
        assert attempt(client, PASSWORD).status_code == 401


@pytest.mark.parametrize(
    "expire",
    [
        "UPDATE sessions SET last_seen_at = now() - interval '61 minutes'",
        "UPDATE sessions SET expires_at = now() - interval '1 second'",
    ],
    ids=["idle-60-minutes", "absolute-10-hours"],
)
def test_expired_sessions_are_refused_and_deleted(migrated_database_url: str, expire: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        login(client, EMAIL)
        sql(migrated_database_url, expire)
        assert client.get("/api/v1/auth/me").status_code == 401
    assert sql(migrated_database_url, "SELECT count(*) FROM sessions") == [(0,)]


def test_activity_keeps_the_session_alive(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        login(client, EMAIL)
        sql(migrated_database_url, "UPDATE sessions SET last_seen_at = now() - interval '59 min'")
        assert client.get("/api/v1/auth/me").status_code == 200
        [(idle,)] = sql(migrated_database_url, "SELECT now() - last_seen_at FROM sessions")
        assert idle < timedelta(minutes=1)


def test_writes_need_the_csrf_token(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        csrf = login(client, EMAIL)
        assert client.post("/api/v1/auth/logout").status_code == 403
        assert client.post("/api/v1/auth/logout", headers=csrf_headers("wrong")).status_code == 403
        cross_site = client.post(
            "/api/v1/auth/logout",
            headers={**csrf_headers(csrf), "Origin": "https://evil.example"},
        )
        assert cross_site.status_code == 403
        logout = client.post("/api/v1/auth/logout", headers=csrf_headers(csrf))
        assert logout.status_code == 204
        assert SESSION_COOKIE not in client.cookies
        assert client.get("/api/v1/auth/me").status_code == 401


def test_cross_site_login_is_refused(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 403
        same_site = client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"Origin": "https://testserver"},
        )
        assert same_site.status_code == 200


def test_temporary_password_must_be_changed(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL, must_change_password=True)
    new_password = "amber-quarry-falcon-38"
    with api_client(migrated_database_url) as client:
        csrf = login(client, EMAIL)
        assert client.get("/api/v1/auth/me").json()["must_change_password"] is True
        assert client.get("/api/v1/cves").status_code == 403

        def change(current: str, new: str) -> Any:
            return client.post(
                "/api/v1/auth/password",
                json={"current_password": current, "new_password": new},
                headers=csrf_headers(csrf),
            )

        assert change("not-the-password-at-all", new_password).status_code == 403
        rejected = change(PASSWORD, "short")
        assert rejected.status_code == 422 and "too_short" in rejected.json()["detail"]
        assert change(PASSWORD, PASSWORD).status_code == 422
        assert change(PASSWORD, "mario.rossi-amber-quarry").status_code == 422
        assert change(PASSWORD, new_password).status_code == 204
        # Every session of the user is closed: log in again with the new password.
        assert client.get("/api/v1/auth/me").status_code == 401
        login(client, EMAIL, new_password)
        assert client.get("/api/v1/cves").status_code == 200
    [(must_change,)] = sql(migrated_database_url, "SELECT must_change_password FROM users")
    assert must_change is False


def test_password_change_closes_the_other_sessions(migrated_database_url: str) -> None:
    add_user(migrated_database_url, EMAIL)
    with api_client(migrated_database_url) as first, api_client(migrated_database_url) as second:
        csrf = login(first, EMAIL)
        login(second, EMAIL)
        changed = first.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "amber-quarry-falcon-38"},
            headers=csrf_headers(csrf),
        )
        assert changed.status_code == 204
        assert second.get("/api/v1/auth/me").status_code == 401


def test_cli_creates_the_first_admin(
    migrated_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", migrated_database_url)
    get_settings.cache_clear()

    def run(email: str, password: str) -> int:
        monkeypatch.setattr("sys.stdin", io.StringIO(password + "\n"))
        return users_cli(["create-admin", "--email", email, "--password-stdin"])

    assert run("Admin@Example.it", "short") == 2
    assert run("admin@example.it", "amber-quarry-falcon-38") == 0
    assert run("ADMIN@example.it", "amber-quarry-falcon-38") == 1
    rows = sql(migrated_database_url, "SELECT email, role, must_change_password FROM users")
    assert rows == [("admin@example.it", "admin", False)]
    with api_client(migrated_database_url) as client:
        login(client, "admin@example.it", "amber-quarry-falcon-38")
