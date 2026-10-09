"""Audit log (docs/architettura.md §10.1, §10.4).

Append-only: the migration installs a trigger that refuses UPDATE and DELETE.
There is no foreign key to `users`, so deleting a user never touches the log;
the actor's email is kept as it was at the time of the event.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # e.g. auth.login, auth.locked, auth.mfa, user.created
    action: Mapped[str] = mapped_column(String(64), index=True)
    # success | failure | denied
    outcome: Mapped[str] = mapped_column(String(16))
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    # Email of the actor, "cli" for the command line, "anonymous" for unknown emails.
    actor: Mapped[str] = mapped_column(String(254))
    ip: Mapped[str | None] = mapped_column(String(45))
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    # Context without secrets: never passwords, codes, tokens or keys.
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
