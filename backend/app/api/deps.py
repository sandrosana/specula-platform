"""Shared FastAPI dependencies."""

import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.classification import Classification
from app.core.config import Settings
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


def get_app_settings(request: Request) -> Settings:
    """The settings the application was created with."""
    return cast(Settings, request.app.state.settings)


SettingsDep = Annotated[Settings, Depends(get_app_settings)]


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


CsrfHeader = Annotated[
    str | None,
    Header(
        alias=CSRF_HEADER,
        description=(
            "CSRF token of the session (from POST /auth/login or GET /auth/me). "
            "Required by every request that changes data."
        ),
    ),
]


async def _session_auth(request: Request, db: SessionDep, csrf: CsrfHeader = None) -> Auth:
    """The session of the request, complete or waiting for the second factor.

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
        # Declared as a header parameter so the interactive API docs offer a field for it.
        sent = csrf or ""
        if not secrets.compare_digest(sent.encode(), row.csrf_token.encode()):
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token.")
    return Auth(session=row, user=user)


SessionAuthDep = Annotated[Auth, Depends(_session_auth)]


async def get_mfa_pending_auth(auth: SessionAuthDep) -> Auth:
    """A session whose password is checked and whose second factor is still missing."""
    if not auth.session.mfa_pending:
        raise HTTPException(status_code=409, detail="The session is already complete.")
    return auth


MfaPendingDep = Annotated[Auth, Depends(get_mfa_pending_auth)]


async def get_auth_any(auth: SessionAuthDep) -> Auth:
    """The logged-in user, also while a password change is pending."""
    if auth.session.mfa_pending:
        raise HTTPException(
            status_code=401,
            detail="Second factor required.",
            headers={"WWW-Authenticate": "Cookie"},
        )
    return auth


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
