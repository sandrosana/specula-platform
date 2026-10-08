"""Errors as application/problem+json (RFC 9457, docs/architettura.md §9)."""

from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_JSON = "application/problem+json"


def problem(
    status: int, detail: str | None = None, errors: list[dict[str, object]] | None = None
) -> JSONResponse:
    body: dict[str, object] = {"type": "about:blank", "title": HTTPStatus(status).phrase}
    body["status"] = status
    if detail:
        body["detail"] = detail
    if errors:
        body["errors"] = errors
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON)


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover - registered for this type
        raise exc
    detail = exc.detail if isinstance(exc.detail, str) else None
    response = problem(exc.status_code, detail)
    if exc.headers:
        response.headers.update(exc.headers)
    return response


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover - registered for this type
        raise exc
    # Location and message only: the rejected input is never echoed back.
    errors: list[dict[str, object]] = [
        {"loc": list(error.get("loc", ())), "msg": str(error.get("msg", ""))}
        for error in exc.errors()
    ]
    return problem(422, "The request parameters are not valid.", errors)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
