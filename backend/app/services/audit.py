"""Writes to the append-only audit log (docs/architettura.md §10.4).

Rows are added to the caller's transaction: an event is recorded together with
the change it describes. Failed logins are committed by the endpoint before it
answers, like the failure counters.
"""

from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditRow, UserRow

Outcome = Literal["success", "failure", "denied"]
CLI_ACTOR = "cli"
ANONYMOUS = "anonymous"


def record(
    session: AsyncSession,
    action: str,
    outcome: Outcome,
    *,
    user: UserRow | None = None,
    actor: str | None = None,
    ip: str | None = None,
    target: UserRow | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add one audit row. `user` is who acts; `actor` overrides the label (e.g. "cli")."""
    session.add(
        AuditRow(
            action=action,
            outcome=outcome,
            actor_user_id=user.id if user is not None else None,
            actor=actor or (user.email if user is not None else ANONYMOUS),
            ip=ip,
            target_type="user" if target is not None else None,
            target_id=str(target.id) if target is not None else None,
            details=details or {},
        )
    )
