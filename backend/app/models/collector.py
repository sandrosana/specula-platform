"""Operational tables of the collector framework (docs/architettura.md §7.1, §8.1)."""

from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, ClassifiedMixin


class CollectorRun(Base):
    """One execution of a periodic collector (docs/architettura.md §5.4)."""

    __tablename__ = "collector_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    collector: Mapped[str] = mapped_column(String(64), index=True)
    trigger: Mapped[str] = mapped_column(String(16))
    full: Mapped[bool] = mapped_column(Boolean, server_default="false")
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_read: Mapped[int] = mapped_column(Integer, server_default="0")
    records_inserted: Mapped[int] = mapped_column(Integer, server_default="0")
    records_updated: Mapped[int] = mapped_column(Integer, server_default="0")
    errors: Mapped[int] = mapped_column(Integer, server_default="0")
    message: Mapped[str | None] = mapped_column(Text)


class CollectorState(Base):
    """Per-collector state: incremental cursor and last outcome."""

    __tablename__ = "collector_state"

    collector: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Listener heartbeat (roadmap, docs/architettura.md §5.3).
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Effective configuration published by the scheduler, which is the only
    # process holding the source keys: the API reads it from here.
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    disabled_reason: Mapped[str | None] = mapped_column(Text)
    configured: Mapped[bool | None] = mapped_column(Boolean)
    schedule: Mapped[str | None] = mapped_column(String(64))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class HttpCacheEntry(ClassifiedMixin, Base):
    """Cached source response. The body is stored zlib-compressed."""

    __tablename__ = "http_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    body: Mapped[bytes] = mapped_column(LargeBinary)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SourceUsage(Base):
    """Requests sent to a source per day, for quota enforcement and GET /sources."""

    __tablename__ = "source_usage"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    requests: Mapped[int] = mapped_column(Integer, server_default="0")
