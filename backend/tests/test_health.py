from fastapi.testclient import TestClient

from app import SERVICE_NAME, __version__


def test_health_reports_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": SERVICE_NAME, "version": __version__}


def test_openapi_is_served_under_api_prefix(client: TestClient) -> None:
    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/v1/health" in paths
    assert "/api/v1/health/ready" in paths


def test_routes_outside_api_prefix_are_not_found(client: TestClient) -> None:
    assert client.get("/health").status_code == 404


def test_ready_reports_unavailable_without_database(client: TestClient) -> None:
    # Unit tests have sockets disabled, so the database can never be reached.
    response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "unavailable"}
