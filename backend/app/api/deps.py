"""Shared FastAPI dependencies."""

from collections.abc import AsyncIterator
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.classification import Classification

# Until M4 adds authentication every caller is anonymous and sees public data only.
# Visibility is always applied in the repositories, never only in the UI.
ANONYMOUS_CLASSES = frozenset({Classification.PUBLIC})


def get_engine(request: Request) -> AsyncEngine:
    """The engine created by the application lifespan."""
    return cast(AsyncEngine, request.app.state.engine)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    sessions = cast(async_sessionmaker[AsyncSession], request.app.state.sessions)
    async with sessions() as session:
        yield session


def get_visible_classes() -> frozenset[Classification]:
    """Data classes the caller may see (docs/architettura.md §10.1)."""
    return ANONYMOUS_CLASSES


SessionDep = Annotated[AsyncSession, Depends(get_session)]
VisibleClassesDep = Annotated[frozenset[Classification], Depends(get_visible_classes)]
