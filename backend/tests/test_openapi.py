from typing import Any

import pytest

from app.core.config import Settings
from app.main import create_app


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/auth/logout",
        "/api/v1/auth/password",
        "/api/v1/auth/totp/setup",
        "/api/v1/auth/totp",
    ],
)
def test_write_endpoints_document_the_csrf_header(settings: Settings, path: str) -> None:
    """The interactive docs must offer a field for the token, or writes cannot be tried there."""
    schema: dict[str, Any] = create_app(settings).openapi()
    parameters = schema["paths"][path]["post"].get("parameters", [])

    assert {"name": "X-CSRF-Token", "in": "header"} in [
        {"name": p["name"], "in": p["in"]} for p in parameters
    ]
