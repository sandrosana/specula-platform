"""Login, sessions and lockout (docs/architettura.md §10.4)."""

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LoginFailureRow, SessionRow, UserRow
from app.services import audit
from app.services.passwords import (
    DUMMY_HASH,
    hash_password,
    needs_rehash,
    verify_password,
)

SESSION_COOKIE = "specula_session"
SESSION_MAX_AGE = timedelta(hours=10)
SESSION_IDLE = timedelta(minutes=60)
# Time to type the second-factor code after the password.
MFA_PENDING_MAX_AGE = timedelta(minutes=5)
# last_seen_at is written at most this often, not on every request.
SESSION_TOUCH = timedelta(minutes=1)
LOCK_AFTER = 5
LOCK_FOR = timedelta(minutes=15)
IP_FAILURE_LIMIT = 20
IP_FAILURE_WINDOW = timedelta(minutes=10)
FAILURE_RETENTION = timedelta(days=1)

logger = logging.getLogger("app.auth")

LoginOutcome = Literal["ok", "invalid", "ip_limited"]


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class LoginResult:
    outcome: LoginOutcome
    user: UserRow | None = None


@dataclass(frozen=True)
class NewSession:
    token: str
    token_hash: str
    csrf_token: str
    expires_at: datetime


async def _record_failure(session: AsyncSession, ip: str, now: datetime) -> None:
    session.add(LoginFailureRow(ip=ip, attempted_at=now))
    await session.execute(
        delete(LoginFailureRow).where(LoginFailureRow.attempted_at < now - FAILURE_RETENTION)
    )


async def ip_failures(session: AsyncSession, ip: str, now: datetime) -> int:
    count = await session.scalar(
        select(func.count())
        .select_from(LoginFailureRow)
        .where(
            LoginFailureRow.ip == ip,
            LoginFailureRow.attempted_at >= now - IP_FAILURE_WINDOW,
        )
    )
    return int(count or 0)


def is_locked(user: UserRow, at: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > at


async def register_failure(session: AsyncSession, user: UserRow, ip: str, at: datetime) -> None:
    """A wrong password or second-factor code: 5 in a row lock the account."""
    user.failed_logins += 1
    if user.failed_logins >= LOCK_AFTER:
        user.locked_until = at + LOCK_FOR
        user.failed_logins = 0
        logger.warning("user %d locked for %s after failed logins", user.id, LOCK_FOR)
        audit.record(
            session,
            "auth.lock",
            "success",
            user=user,
            ip=ip,
            details={"minutes": int(LOCK_FOR.total_seconds() // 60)},
        )
    await _record_failure(session, ip, at)


async def authenticate(
    session: AsyncSession, email: str, password: str, ip: str, now: datetime | None = None
) -> LoginResult:
    """Check the credentials and apply the lockout rules. The caller commits.

    Unknown email, wrong password, locked or disabled account all give "invalid",
    after the same amount of hashing work.
    """
    at = now or utcnow()
    if await ip_failures(session, ip, at) >= IP_FAILURE_LIMIT:
        logger.warning("login refused: too many failures from one address")
        audit.record(session, "auth.login", "denied", ip=ip, details={"reason": "ip_limited"})
        return LoginResult("ip_limited")

    user = await session.scalar(select(UserRow).where(UserRow.email == normalize_email(email)))
    if user is None:
        verify_password(DUMMY_HASH, password)
        await _record_failure(session, ip, at)
        # The typed email is not logged: it may be a password typed in the wrong field.
        audit.record(session, "auth.login", "failure", ip=ip, details={"reason": "unknown_user"})
        return LoginResult("invalid")

    password_ok = verify_password(user.password_hash, password)
    if is_locked(user, at) or not user.is_active:
        await _record_failure(session, ip, at)
        logger.warning("login refused for user %d: locked or disabled", user.id)
        reason = "locked" if is_locked(user, at) else "disabled"
        audit.record(session, "auth.login", "denied", user=user, ip=ip, details={"reason": reason})
        return LoginResult("invalid")
    if not password_ok:
        audit.record(
            session, "auth.login", "failure", user=user, ip=ip, details={"reason": "password"}
        )
        await register_failure(session, user, ip, at)
        return LoginResult("invalid")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    if requires_second_factor(user):
        # Counters are reset only once the second factor is accepted too.
        audit.record(
            session,
            "auth.login",
            "success",
            user=user,
            ip=ip,
            details={"second_factor": "pending"},
        )
        return LoginResult("ok", user)
    login_succeeded(user, at)
    audit.record(session, "auth.login", "success", user=user, ip=ip)
    return LoginResult("ok", user)


def requires_second_factor(user: UserRow) -> bool:
    return user.role == "admin"


def login_succeeded(user: UserRow, at: datetime) -> None:
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = at


async def create_session(
    session: AsyncSession,
    user: UserRow,
    ip: str | None,
    user_agent: str | None,
    now: datetime | None = None,
    *,
    mfa_pending: bool = False,
) -> NewSession:
    at = now or utcnow()
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = at + (MFA_PENDING_MAX_AGE if mfa_pending else SESSION_MAX_AGE)
    session.add(
        SessionRow(
            token_hash=token_hash(token),
            user_id=user.id,
            csrf_token=csrf_token,
            mfa_pending=mfa_pending,
            created_at=at,
            last_seen_at=at,
            expires_at=expires_at,
            ip=ip,
            user_agent=(user_agent or "")[:255] or None,
        )
    )
    # Housekeeping: sessions past their absolute end are useless.
    await session.execute(delete(SessionRow).where(SessionRow.expires_at < at))
    return NewSession(
        token=token, token_hash=token_hash(token), csrf_token=csrf_token, expires_at=expires_at
    )


async def resolve_session(
    session: AsyncSession, token: str, now: datetime | None = None
) -> tuple[SessionRow, UserRow] | None:
    """The live session of `token` and its user, or None. Expired sessions are deleted."""
    at = now or utcnow()
    row = await session.get(SessionRow, token_hash(token))
    if row is None:
        return None
    user = await session.get(UserRow, row.user_id)
    expired = row.expires_at <= at or row.last_seen_at + SESSION_IDLE <= at
    if expired or user is None or not user.is_active:
        await session.delete(row)
        return None
    if at - row.last_seen_at >= SESSION_TOUCH:
        row.last_seen_at = at
    return row, user


async def revoke_session(session: AsyncSession, token: str) -> None:
    await session.execute(delete(SessionRow).where(SessionRow.token_hash == token_hash(token)))


async def revoke_user_sessions(session: AsyncSession, user_id: int) -> None:
    """Logout everywhere: after a password, role or grant change, or when disabled."""
    await session.execute(delete(SessionRow).where(SessionRow.user_id == user_id))


async def change_password(
    session: AsyncSession, user: UserRow, new_password: str, now: datetime | None = None
) -> None:
    at = now or utcnow()
    await session.execute(
        update(UserRow)
        .where(UserRow.id == user.id)
        .values(
            password_hash=hash_password(new_password),
            must_change_password=False,
            password_changed_at=at,
            updated_at=at,
        )
    )
    await revoke_user_sessions(session, user.id)


async def create_user(
    session: AsyncSession,
    email: str,
    password: str,
    role: str,
    *,
    must_change_password: bool,
) -> UserRow:
    user = UserRow(
        email=normalize_email(email),
        password_hash=hash_password(password),
        role=role,
        must_change_password=must_change_password,
    )
    session.add(user)
    await session.flush()
    return user
