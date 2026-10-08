"""CISA Known Exploited Vulnerabilities (docs/architettura.md §6.1, §8.1)."""

from datetime import date, datetime
from typing import Any

from sqlalchemy import Boolean, Date, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, ClassifiedMixin


class KevEntryRow(ClassifiedMixin, Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text)
    vulnerability_name: Mapped[str] = mapped_column(Text)
    date_added: Mapped[date] = mapped_column(Date, index=True)
    short_description: Mapped[str] = mapped_column(Text)
    required_action: Mapped[str] = mapped_column(Text)
    due_date: Mapped[date | None] = mapped_column(Date)
    # "Known" or "Unknown" as published by CISA.
    known_ransomware_campaign_use: Mapped[str | None] = mapped_column(String(16))
    forensic_triage: Mapped[bool | None] = mapped_column(Boolean)
    notes: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(ARRAY(String(32)), server_default="{}")
    catalog_version: Mapped[str] = mapped_column(String(32))
    # Source record as received, to re-normalize without downloading again.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
