import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.errors import PROBLEM_JSON
from app.api.pagination import decode_cursor, encode_cursor


def test_unknown_route_is_problem_json(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json() == {
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
        "detail": "Not Found",
    }


def test_validation_error_is_problem_json_without_input(client: TestClient) -> None:
    response = client.get("/api/v1/kev", params={"limit": "0", "added_from": "secret-ish-value"})

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    body = response.json()
    assert body["title"] in {"Unprocessable Content", "Unprocessable Entity"}
    assert {tuple(error["loc"]) for error in body["errors"]} == {
        ("query", "limit"),
        ("query", "added_from"),
    }
    assert "secret-ish-value" not in response.text


def test_invalid_cursor_is_rejected(client: TestClient) -> None:
    response = client.get("/api/v1/kev", params={"cursor": "not-a-cursor"})

    assert response.status_code == 400
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["detail"] == "Invalid cursor."


def test_cursor_roundtrip() -> None:
    position = {"d": "2026-10-04", "c": "CVE-2026-88779"}

    assert decode_cursor(encode_cursor(position)) == position


@pytest.mark.parametrize("cursor", ["%%%", "bm90LWpzb24", encode_cursor({"d": 1})[:-2] + "!!"])
def test_tampered_cursor(cursor: str) -> None:
    with pytest.raises(HTTPException) as error:
        decode_cursor(cursor)

    assert error.value.status_code == 400
