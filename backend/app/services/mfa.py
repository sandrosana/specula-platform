"""Second factor of the Admins: enrolment, verification, reset (docs/architettura.md §10.4)."""

import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RecoveryCodeRow, UserRow
from app.services import audit, totp
from app.services.auth import (
    is_locked,
    login_succeeded,
    register_failure,
    revoke_user_sessions,
    utcnow,
)
from app.services.secretbox import SecretBoxError, decrypt, encrypt

logger = logging.getLogger("app.auth")


class MfaError(Exception):
    """The operation is not possible in the current state (e.g. already enrolled)."""


@dataclass(frozen=True)
class Enrolment:
    secret: str
    uri: str


async def start_enrolment(secret_key: str, user: UserRow) -> Enrolment:
    """A new secret, kept pending until a code confirms it. The caller commits."""
    if user.totp_enabled:
        raise MfaError("second factor already active")
    secret = totp.new_secret()
    user.totp_pending_secret = encrypt(secret_key, secret)
    return Enrolment(secret=secret, uri=totp.provisioning_uri(secret, user.email))


async def confirm_enrolment(
    session: AsyncSession,
    secret_key: str,
    user: UserRow,
    code: str,
    ip: str,
    now: datetime | None = None,
) -> list[str] | None:
    """Activate the pending secret if `code` matches; returns the recovery codes."""
    at = now or utcnow()
    if user.totp_enabled or user.totp_pending_secret is None:
        raise MfaError("no enrolment in progress")
    if is_locked(user, at):
        return None
    try:
        secret = decrypt(secret_key, user.totp_pending_secret)
    except SecretBoxError as exc:
        raise MfaError("the pending secret cannot be read") from exc
    step = totp.verify(secret, code, at, None)
    if step is None:
        audit.record(
            session, "auth.mfa", "failure", user=user, ip=ip, details={"step": "enrolment"}
        )
        await register_failure(session, user, ip, at)
        return None
    user.totp_secret = user.totp_pending_secret
    user.totp_pending_secret = None
    user.totp_enabled = True
    user.totp_last_step = step
    login_succeeded(user, at)
    codes = totp.new_recovery_codes()
    await session.execute(delete(RecoveryCodeRow).where(RecoveryCodeRow.user_id == user.id))
    session.add_all(
        RecoveryCodeRow(user_id=user.id, code_hash=totp.hash_recovery_code(recovery))
        for recovery in codes
    )
    logger.info("second factor activated for user %d", user.id)
    audit.record(session, "auth.mfa.enrolled", "success", user=user, ip=ip)
    return codes


async def verify_second_factor(
    session: AsyncSession,
    secret_key: str,
    user: UserRow,
    ip: str,
    *,
    code: str | None = None,
    recovery_code: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Check a TOTP code or a one-time recovery code. Failures count towards the lock."""
    at = now or utcnow()
    if not user.totp_enabled or user.totp_secret is None:
        raise MfaError("second factor not active")
    if is_locked(user, at) or not user.is_active:
        audit.record(session, "auth.mfa", "denied", user=user, ip=ip, details={"reason": "locked"})
        return False
    method = "totp" if code is not None else "recovery_code"
    if code is not None:
        try:
            secret = decrypt(secret_key, user.totp_secret)
        except SecretBoxError as exc:
            raise MfaError("the secret cannot be read: SECRET_KEY changed?") from exc
        step = totp.verify(secret, code, at, user.totp_last_step)
        if step is not None:
            user.totp_last_step = step
            login_succeeded(user, at)
            audit.record(
                session, "auth.mfa", "success", user=user, ip=ip, details={"method": method}
            )
            return True
    elif recovery_code is not None:
        used = await session.execute(
            update(RecoveryCodeRow)
            .where(
                RecoveryCodeRow.user_id == user.id,
                RecoveryCodeRow.code_hash == totp.hash_recovery_code(recovery_code),
                RecoveryCodeRow.used_at.is_(None),
            )
            .values(used_at=at)
            .returning(RecoveryCodeRow.id)
        )
        if used.first() is not None:
            logger.warning("recovery code used by user %d", user.id)
            login_succeeded(user, at)
            audit.record(
                session, "auth.mfa", "success", user=user, ip=ip, details={"method": method}
            )
            return True
    audit.record(session, "auth.mfa", "failure", user=user, ip=ip, details={"method": method})
    await register_failure(session, user, ip, at)
    return False


async def remaining_recovery_codes(session: AsyncSession, user_id: int) -> int:
    rows = await session.scalars(
        select(RecoveryCodeRow.id).where(
            RecoveryCodeRow.user_id == user_id, RecoveryCodeRow.used_at.is_(None)
        )
    )
    return len(rows.all())


async def reset_second_factor(session: AsyncSession, user: UserRow) -> None:
    """The Admin enrols again at the next login; every session is closed."""
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_pending_secret = None
    user.totp_last_step = None
    await session.execute(delete(RecoveryCodeRow).where(RecoveryCodeRow.user_id == user.id))
    await revoke_user_sessions(session, user.id)
    logger.warning("second factor reset for user %d", user.id)
