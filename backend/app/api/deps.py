"""Shared FastAPI dependencies."""

from typing import cast

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine


def get_engine(request: Request) -> AsyncEngine:
    """The engine created by the application lifespan."""
    return cast(AsyncEngine, request.app.state.engine)
