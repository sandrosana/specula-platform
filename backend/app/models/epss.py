"""EPSS scores (docs/architettura.md v1.4 §6.1, §8.1)."""

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, ClassifiedMixin


class EpssScoreRow(ClassifiedMixin, Base):
    """Current score of each CVE. Updated only when a value changes."""

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss: Mapped[float] = mapped_column(Float, index=True)
    percentile: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(32))
    # Publication date of the current values (date of the last change).
    score_date: Mapped[date] = mapped_column(Date)
    # Score at the last history entry: changes are measured against it, so slow
    # drifts are recorded too.
    history_epss: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EpssHistoryRow(ClassifiedMixin, Base):
    """Relevant changes only: first appearance, change of at least 0.01,
    threshold crossing or model version change."""

    __tablename__ = "epss_history"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score_date: Mapped[date] = mapped_column(Date, primary_key=True, index=True)
    epss: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(32))
    # first | change | threshold | model
    reason: Mapped[str] = mapped_column(String(16))
