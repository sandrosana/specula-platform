"""Operational tables of the collector framework (docs/architettura.md §7.1, §8.1)."""

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, ClassifiedMixin


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
