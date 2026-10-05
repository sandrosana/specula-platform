"""Liveness endpoint. Readiness (database check) arrives with the database layer."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from app import SERVICE_NAME, __version__

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


@router.get("/health", summary="Liveness check")
async def health() -> HealthResponse:
    """The process is up and serving requests. Does not check dependencies."""
    return HealthResponse(status="ok", service=SERVICE_NAME, version=__version__)
