"""Users and logged-in clients for database API tests."""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.deps import CSRF_HEADER
from app.core.config import Settings
from app.core.db import create_session_factory
from app.main import create_app
from app.services import totp
from app.services.auth import create_user

PASSWORD = "violet-harbour-lantern-92"
SECRET_KEY = "db-test-secret-key-db-test-secret-key"
# Secure cookies are only sent over https, as in production.
BASE_URL = "https://testserver"


def add_user(
    database_url: str,
    email: str,
    role: str = "viewer",
    password: str = PASSWORD,
    *,
    must_change_password: bool = False,
) -> int:
    async def main() -> int:
        engine = create_async_engine(database_url)
        try:
            async with create_session_factory(engine).begin() as session:
                user = await create_user(
                    session, email, password, role, must_change_password=must_change_password
                )
                return user.id
        finally:
            await engine.dispose()

    return asyncio.run(main())


def settings_for(database_url: str) -> Settings:
    return Settings(
        environment="test",
        log_level="WARNING",
        database_url=SecretStr(database_url),
        secret_key=SecretStr(SECRET_KEY),
        collector_env={},
    )


@contextmanager
def api_client(database_url: str, settings: Settings | None = None) -> Iterator[TestClient]:
    with TestClient(
        create_app(settings or settings_for(database_url)), base_url=BASE_URL
    ) as client:
        yield client


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    """Log in; the session cookie stays in the client. Returns the CSRF token."""
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    csrf: str = response.json()["csrf_token"]
    return csrf


def csrf_headers(token: str) -> dict[str, str]:
    return {CSRF_HEADER: token}


@contextmanager
def logged_in(
    database_url: str, role: str = "viewer", settings: Settings | None = None
) -> Iterator[TestClient]:
    """A client logged in as a new user with `role`."""
    email = f"{role}@example.it"
    add_user(database_url, email, role)
    with api_client(database_url, settings) as client:
        login(client, email)
        yield client


def login_admin(client: TestClient, email: str) -> str:
    """Password, second-factor enrolment and first code. Returns the full session CSRF token."""
    csrf = login(client, email)
    setup = client.post("/api/v1/auth/totp/setup", headers=csrf_headers(csrf))
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    code = totp.code_at(secret, totp.step_at(datetime.now(UTC)))
    activated = client.post(
        "/api/v1/auth/totp/activate", json={"code": code}, headers=csrf_headers(csrf)
    )
    assert activated.status_code == 200, activated.text
    token: str = activated.json()["user"]["csrf_token"]
    return token
