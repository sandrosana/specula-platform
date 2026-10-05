"""Liveness and readiness endpoints."""

import asyncio
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncEngine

from app import SERVICE_NAME, __version__
from app.api.deps import get_engine
from app.core.db import check_database

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

READINESS_TIMEOUT_SECONDS = 2.0


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    database: Literal["ok", "unavailable"]


@router.get("/health", summary="Liveness check")
async def health() -> HealthResponse:
    """The process is up and serving requests. Does not check dependencies."""
    return HealthResponse(status="ok", service=SERVICE_NAME, version=__version__)


@router.get(
    "/health/ready",
    summary="Readiness check",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
async def ready(
    response: Response,
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> ReadinessResponse:
    """The service can handle requests: the database is reachable."""
    try:
        async with asyncio.timeout(READINESS_TIMEOUT_SECONDS):
            await check_database(engine)
    except Exception as exc:
        # Only the exception type is logged: messages may contain connection details.
        logger.warning("readiness check failed: %s", type(exc).__name__)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(status="unavailable", database="unavailable")
    return ReadinessResponse(status="ok", database="ok")
