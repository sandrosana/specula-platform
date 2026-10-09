"""Local login (docs/architettura.md §9, §10.4)."""

from typing import Literal, cast

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import AuthAnyDep, SessionDep, check_origin, client_ip
from app.models import UserRow
from app.schemas.auth import LoginIn, MeOut, PasswordChangeIn
from app.services.auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    authenticate,
    change_password,
    create_session,
    revoke_session,
)
from app.services.passwords import password_problems, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_LOGIN = "Invalid email or password."


def _me(user: UserRow, csrf_token: str) -> MeOut:
    return MeOut(
        id=user.id,
        email=user.email,
        role=cast(Literal["viewer", "analyst", "admin"], user.role),
        must_change_password=user.must_change_password,
        csrf_token=csrf_token,
    )


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_MAX_AGE.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


@router.post("/login", summary="Log in with email and password")
async def login(body: LoginIn, request: Request, response: Response, db: SessionDep) -> MeOut:
    check_origin(request)
    ip = client_ip(request)
    result = await authenticate(db, body.email, body.password, ip)
    if result.outcome == "ip_limited":
        await db.commit()
        raise HTTPException(status_code=429, detail="Too many failed logins, try again later.")
    if result.user is None:
        await db.commit()  # keeps the failure counters
        raise HTTPException(status_code=401, detail=INVALID_LOGIN)
    new = await create_session(db, result.user, ip, request.headers.get("user-agent"))
    await db.commit()
    _set_cookie(response, new.token)
    response.headers["Cache-Control"] = "no-store"
    return _me(result.user, new.csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Close this session")
async def logout(request: Request, response: Response, db: SessionDep, auth: AuthAnyDep) -> None:
    token = request.cookies.get(SESSION_COOKIE, "")
    await revoke_session(db, token)
    await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


@router.get("/me", summary="Current user, role and CSRF token")
async def me(response: Response, auth: AuthAnyDep) -> MeOut:
    response.headers["Cache-Control"] = "no-store"
    return _me(auth.user, auth.session.csrf_token)


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change the password; every session of the user is closed",
)
async def password(
    body: PasswordChangeIn, response: Response, db: SessionDep, auth: AuthAnyDep
) -> None:
    user = auth.user
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status_code=403, detail="The current password is not correct.")
    problems = password_problems(body.new_password, user.email)
    if body.new_password == body.current_password:
        problems.append("same_as_current")
    if problems:
        raise HTTPException(
            status_code=422,
            detail="The new password does not meet the rules: " + ", ".join(problems) + ".",
        )
    await change_password(db, user, body.new_password)
    await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
