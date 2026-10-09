"""Role dependencies and the append-only audit log against PostgreSQL."""

import asyncio
import io
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.deps import AdminDep, AnalystDep
from app.core.config import get_settings
from app.main import create_app
from app.services import totp
from app.users.__main__ import main as users_cli
from tests.db.auth import (
    BASE_URL,
    PASSWORD,
    add_user,
    api_client,
    csrf_headers,
    login,
    login_admin,
    settings_for,
)
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS


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


def events(database_url: str) -> list[tuple[str, str, str, dict[str, Any]]]:
    rows = sql(database_url, "SELECT action, outcome, actor, details FROM audit_log ORDER BY id")
    return [(row[0], row[1], row[2], row[3]) for row in rows]


@pytest.fixture
def role_app(migrated_database_url: str) -> Iterator[TestClient]:
    """The real application plus two write routes guarded by the role dependencies."""
    app: FastAPI = create_app(settings_for(migrated_database_url))

    async def analyst_action(auth: AnalystDep) -> dict[str, str]:
        return {"role": auth.user.role}

    async def admin_action(auth: AdminDep) -> dict[str, str]:
        return {"role": auth.user.role}

    app.add_api_route("/api/v1/test/analyst", analyst_action, methods=["POST"])
    app.add_api_route("/api/v1/test/admin", admin_action, methods=["POST"])
    with TestClient(app, base_url=BASE_URL) as client:
        yield client


def call(client: TestClient, path: str, csrf: str) -> int:
    status: int = client.post(path, headers=csrf_headers(csrf)).status_code
    return status


@pytest.mark.parametrize(
    ("role", "analyst", "admin"),
    [("viewer", 403, 403), ("analyst", 200, 403), ("admin", 200, 200)],
)
def test_role_dependencies(
    migrated_database_url: str, role_app: TestClient, role: str, analyst: int, admin: int
) -> None:
    email = f"{role}@example.it"
    add_user(migrated_database_url, email, role)
    csrf = login_admin(role_app, email) if role == "admin" else login(role_app, email)

    assert call(role_app, "/api/v1/test/analyst", csrf) == analyst
    assert call(role_app, "/api/v1/test/admin", csrf) == admin
    denied = [e for e in events(migrated_database_url) if e[0] == "access.role"]
    assert len(denied) == [analyst, admin].count(403)
    assert all(e[1] == "denied" and e[2] == email for e in denied)


def test_without_login_role_routes_answer_401(role_app: TestClient) -> None:
    assert role_app.post("/api/v1/test/analyst").status_code == 401


def test_login_events(migrated_database_url: str) -> None:
    email = "mario.rossi@example.it"
    add_user(migrated_database_url, email)
    with api_client(migrated_database_url) as client:
        client.post("/api/v1/auth/login", json={"email": "typo@example.it", "password": PASSWORD})
        for _ in range(5):
            client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password!"})
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        sql(migrated_database_url, "UPDATE users SET locked_until = NULL")
        csrf = login(client, email)
        client.post("/api/v1/auth/logout", headers=csrf_headers(csrf))

    log = events(migrated_database_url)
    assert log[0] == ("auth.login", "failure", "anonymous", {"reason": "unknown_user"})
    assert [e[:2] for e in log[1:6]] == [("auth.login", "failure")] * 5
    assert ("auth.lock", "success", email, {"minutes": 15}) in log
    assert ("auth.login", "denied", email, {"reason": "locked"}) in log
    assert log[-2:] == [
        ("auth.login", "success", email, {}),
        ("auth.logout", "success", email, {}),
    ]
    # The mistyped email is never stored.
    assert sql(
        migrated_database_url, "SELECT count(*) FROM audit_log WHERE actor LIKE 'typo%'"
    ) == [(0,)]


def test_password_and_second_factor_events(migrated_database_url: str) -> None:
    admin = "admin@example.it"
    add_user(migrated_database_url, admin, "admin")
    new_password = "amber-quarry-falcon-38"
    with api_client(migrated_database_url) as client:
        csrf = login(client, admin)
        setup = client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf)).json()
        client.post(
            "/api/v1/auth/totp/activate", json={"code": "000000"}, headers=csrf_headers(csrf)
        )
        code = totp.code_at(setup["secret"], totp.step_at(datetime.now(UTC)))
        done = client.post(
            "/api/v1/auth/totp/activate", json={"code": code}, headers=csrf_headers(csrf)
        )
        full = done.json()["user"]["csrf_token"]
        recovery = done.json()["recovery_codes"]
        client.post(
            "/api/v1/auth/password",
            json={"current_password": "not-the-password", "new_password": new_password},
            headers=csrf_headers(full),
        )
        client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": new_password},
            headers=csrf_headers(full),
        )
        pending = login(client, admin, new_password)
        client.post(
            "/api/v1/auth/totp", json={"recovery_code": recovery[0]}, headers=csrf_headers(pending)
        )

    log = [(e[0], e[1], e[3]) for e in events(migrated_database_url)]
    assert log == [
        ("auth.login", "success", {"second_factor": "pending"}),
        ("auth.mfa", "failure", {"step": "enrolment"}),
        ("auth.mfa.enrolled", "success", {}),
        ("auth.password", "failure", {"reason": "current"}),
        ("auth.password", "success", {}),
        ("auth.login", "success", {"second_factor": "pending"}),
        ("auth.mfa", "success", {"method": "recovery_code"}),
    ]
    # No password, code, secret or recovery code ever reaches the log.
    dump = sql(migrated_database_url, "SELECT string_agg(audit_log::text, ' ') FROM audit_log")[0][
        0
    ]
    for secret in (PASSWORD, new_password, setup["secret"], code, *recovery):
        assert secret not in dump


def test_cli_events(migrated_database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", migrated_database_url)
    get_settings.cache_clear()
    monkeypatch.setattr("sys.stdin", io.StringIO("amber-quarry-falcon-38\n"))

    assert users_cli(["create-admin", "--email", "admin@example.it", "--password-stdin"]) == 0
    assert users_cli(["reset-totp", "--email", "admin@example.it"]) == 0
    [(user_id,)] = sql(migrated_database_url, "SELECT id FROM users")
    rows = sql(
        migrated_database_url,
        "SELECT action, actor, actor_user_id, target_type, target_id FROM audit_log ORDER BY id",
    )
    assert rows == [
        ("user.created", "cli", None, "user", str(user_id)),
        ("auth.mfa.reset", "cli", None, "user", str(user_id)),
    ]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET outcome = 'success'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ],
)
def test_audit_log_is_append_only(migrated_database_url: str, statement: str) -> None:
    sql(
        migrated_database_url,
        "INSERT INTO audit_log (action, outcome, actor) VALUES ('test', 'failure', 'cli')",
    )
    with pytest.raises(DBAPIError, match="append-only"):
        sql(migrated_database_url, statement)
    assert sql(migrated_database_url, "SELECT count(*), min(outcome) FROM audit_log") == [
        (1, "failure")
    ]


def test_role_check_needs_a_full_session(role_app: TestClient, migrated_database_url: str) -> None:
    """An Admin still waiting for the second factor is not an Admin yet."""
    add_user(migrated_database_url, "admin@example.it", "admin")
    csrf = login(role_app, "admin@example.it")
    response = role_app.post("/api/v1/test/admin", headers=csrf_headers(csrf))
    assert response.status_code == 401
    assert response.json()["detail"] == "Second factor required."
