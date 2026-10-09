"""Local login and second factor (docs/architettura.md §9, §10.4)."""

from typing import Literal, cast

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import (
    AuthAnyDep,
    MfaPendingDep,
    SessionAuthDep,
    SessionDep,
    SettingsDep,
    check_origin,
    client_ip,
)
from app.core.config import Settings
from app.models import SessionRow, UserRow
from app.schemas.auth import (
    LoginIn,
    MeOut,
    MfaState,
    PasswordChangeIn,
    TotpActivatedOut,
    TotpActivateIn,
    TotpSetupOut,
    TotpVerifyIn,
)
from app.services import audit
from app.services.auth import (
    MFA_PENDING_MAX_AGE,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    authenticate,
    change_password,
    create_session,
    requires_second_factor,
    revoke_session,
)
from app.services.mfa import (
    MfaError,
    confirm_enrolment,
    start_enrolment,
    verify_second_factor,
)
from app.services.passwords import password_problems, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_LOGIN = "Invalid email or password."
INVALID_CODE = "Invalid code."


def _mfa_state(session: SessionRow, user: UserRow) -> MfaState | None:
    if not session.mfa_pending:
        return None
    return "verify" if user.totp_enabled else "enroll"


def _me(user: UserRow, session: SessionRow) -> MeOut:
    return MeOut(
        id=user.id,
        email=user.email,
        role=cast(Literal["viewer", "analyst", "admin"], user.role),
        must_change_password=user.must_change_password,
        mfa_required=_mfa_state(session, user),
        csrf_token=session.csrf_token,
    )


def _set_cookie(response: Response, token: str, *, pending: bool = False) -> None:
    max_age = MFA_PENDING_MAX_AGE if pending else SESSION_MAX_AGE
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(max_age.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


def _secret_key(settings: Settings) -> str:
    if settings.secret_key is None:
        raise HTTPException(status_code=503, detail="The second factor is not configured.")
    return settings.secret_key.get_secret_value()


async def _complete_login(
    db: SessionDep, request: Request, response: Response, pending: SessionRow, user: UserRow
) -> SessionRow:
    """Replace the pending session with a full one (new token: no session fixation)."""
    await db.delete(pending)
    new = await create_session(db, user, client_ip(request), request.headers.get("user-agent"))
    await db.commit()
    _set_cookie(response, new.token)
    row = await db.get(SessionRow, new.token_hash)
    if row is None:  # pragma: no cover - just committed
        raise HTTPException(status_code=500, detail="Session not created.")
    return row


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
    # Admins get a session that only allows the second-factor step (§10.4).
    pending = requires_second_factor(result.user)
    new = await create_session(
        db, result.user, ip, request.headers.get("user-agent"), mfa_pending=pending
    )
    await db.commit()
    _set_cookie(response, new.token, pending=pending)
    row = await db.get(SessionRow, new.token_hash)
    if row is None:  # pragma: no cover - just committed
        raise HTTPException(status_code=500, detail="Session not created.")
    return _me(result.user, row)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Close this session")
async def logout(
    request: Request, response: Response, db: SessionDep, auth: SessionAuthDep
) -> None:
    await revoke_session(db, request.cookies.get(SESSION_COOKIE, ""))
    audit.record(db, "auth.logout", "success", user=auth.user, ip=client_ip(request))
    await db.commit()
    _clear_cookie(response)


@router.get("/me", summary="Current user, role and CSRF token")
async def me(response: Response, auth: SessionAuthDep) -> MeOut:
    """Also answers during the second-factor step, with `mfa_required` set."""
    response.headers["Cache-Control"] = "no-store"
    return _me(auth.user, auth.session)


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change the password; every session of the user is closed",
)
async def password(
    body: PasswordChangeIn,
    request: Request,
    response: Response,
    db: SessionDep,
    auth: AuthAnyDep,
) -> None:
    user = auth.user
    ip = client_ip(request)
    if not verify_password(user.password_hash, body.current_password):
        audit.record(
            db, "auth.password", "failure", user=user, ip=ip, details={"reason": "current"}
        )
        await db.commit()
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
    audit.record(db, "auth.password", "success", user=user, ip=ip)
    await db.commit()
    _clear_cookie(response)


@router.post("/totp/setup", summary="Start the second-factor enrolment (Admins)")
async def totp_setup(
    response: Response, db: SessionDep, settings: SettingsDep, auth: MfaPendingDep
) -> TotpSetupOut:
    try:
        enrolment = await start_enrolment(_secret_key(settings), auth.user)
    except MfaError as exc:
        raise HTTPException(status_code=409, detail="The second factor is already active.") from exc
    await db.commit()
    response.headers["Cache-Control"] = "no-store"
    return TotpSetupOut(secret=enrolment.secret, otpauth_uri=enrolment.uri)


@router.post("/totp/activate", summary="Confirm the enrolment with a code; completes the login")
async def totp_activate(
    body: TotpActivateIn,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    auth: MfaPendingDep,
) -> TotpActivatedOut:
    try:
        codes = await confirm_enrolment(
            db, _secret_key(settings), auth.user, body.code, client_ip(request)
        )
    except MfaError as exc:
        raise HTTPException(status_code=409, detail="No enrolment in progress.") from exc
    if codes is None:
        await db.commit()  # keeps the failure counters
        raise HTTPException(status_code=401, detail=INVALID_CODE)
    session = await _complete_login(db, request, response, auth.session, auth.user)
    return TotpActivatedOut(user=_me(auth.user, session), recovery_codes=codes)


@router.post("/totp", summary="Second-factor code or recovery code; completes the login")
async def totp_verify(
    body: TotpVerifyIn,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    auth: MfaPendingDep,
) -> MeOut:
    try:
        ok = await verify_second_factor(
            db,
            _secret_key(settings),
            auth.user,
            client_ip(request),
            code=body.code,
            recovery_code=body.recovery_code,
        )
    except MfaError as exc:
        raise HTTPException(status_code=409, detail="Enrol the second factor first.") from exc
    if not ok:
        await db.commit()  # keeps the failure counters
        raise HTTPException(status_code=401, detail=INVALID_CODE)
    session = await _complete_login(db, request, response, auth.session, auth.user)
    return _me(auth.user, session)
