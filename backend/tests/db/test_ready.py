from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings
from app.main import create_app
from tests.db.helpers import DB_TEST_MARKS

pytestmark = DB_TEST_MARKS


def test_ready_reports_ok_with_database(database_url: str) -> None:
    settings = Settings(
        environment="test",
        log_level="WARNING",
        database_url=SecretStr(database_url),
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
