"""Shared FastAPI dependencies."""

import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.classification import Classification
from app.models import SessionRow, UserRow
from app.services.auth import SESSION_COOKIE, resolve_session

# Until M4 adds grants (m4/classification-filters) every user sees public data only.
# Visibility is always applied in the repositories, never only in the UI.
DEFAULT_CLASSES = frozenset({Classification.PUBLIC})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "X-CSRF-Token"


def get_engine(request: Request) -> AsyncEngine:
    """The engine created by the application lifespan."""
    return cast(AsyncEngine, request.app.state.engine)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    sessions = cast(async_sessionmaker[AsyncSession], request.app.state.sessions)
    async with sessions() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def client_ip(request: Request) -> str:
    # Behind Caddy, uvicorn's proxy headers handling sets the real client address.
    return request.client.host if request.client else "unknown"


def check_origin(request: Request) -> None:
    """Reject cross-site writes: a browser sends Origin on every unsafe request."""
    origin = request.headers.get("origin")
    if origin is None:
        return
    expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if origin != expected:
        raise HTTPException(status_code=403, detail="Cross-site request refused.")


@dataclass(frozen=True)
class Auth:
    session: SessionRow
    user: UserRow


async def get_auth_any(request: Request, db: SessionDep) -> Auth:
    """The logged-in user, also while a password change is pending.

    Writes (non-GET requests) also need the CSRF token of the session and, when
    present, a same-site Origin header.
    """
    token = request.cookies.get(SESSION_COOKIE)
    found = await resolve_session(db, token) if token else None
    await db.commit()  # persists last_seen_at, or the deletion of an expired session
    if found is None:
        raise HTTPException(
            status_code=401, detail="Login required.", headers={"WWW-Authenticate": "Cookie"}
        )
    row, user = found
    if request.method not in SAFE_METHODS:
        check_origin(request)
        sent = request.headers.get(CSRF_HEADER, "")
        if not secrets.compare_digest(sent.encode(), row.csrf_token.encode()):
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token.")
    return Auth(session=row, user=user)


AuthAnyDep = Annotated[Auth, Depends(get_auth_any)]


async def get_auth(auth: AuthAnyDep) -> Auth:
    """The logged-in user, who has already replaced a temporary password."""
    if auth.user.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required.")
    return auth


AuthDep = Annotated[Auth, Depends(get_auth)]


def get_visible_classes(auth: AuthDep) -> frozenset[Classification]:
    """Data classes the user may see (docs/architettura.md §10.1)."""
    return DEFAULT_CLASSES


VisibleClassesDep = Annotated[frozenset[Classification], Depends(get_visible_classes)]
