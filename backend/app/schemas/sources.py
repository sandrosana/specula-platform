from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel

from app.collectors.status import SourceStatus
from app.core.classification import Classification


class SourceLicenseOut(BaseModel):
    kind: str
    commercial_use: Literal["yes", "no", "to_verify"]
    terms_url: str
    quota: str | None
    attribution: str | None
    notes: str | None
    verified_on: date | None


class LastRunOut(BaseModel):
    id: int
    trigger: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    read: int
    inserted: int
    updated: int
    errors: int


class SourceUsageOut(BaseModel):
    period: Literal["day", "month"]
    since: date
    requests: int
    limit: int | None


class SourceOut(BaseModel):
    name: str
    display_name: str
    kind: Literal["periodic", "listener"]
    classification: Classification
    status: SourceStatus
    enabled: bool | None
    disabled_reason: str | None
    # Whether the required settings (API keys) are present. Never their value.
    configured: bool | None
    schedule: str | None
    last_run_at: datetime | None
    last_success_at: datetime | None
    next_run_at: datetime | None
    last_run: LastRunOut | None
    license: SourceLicenseOut
    usage: SourceUsageOut


class SourcesOut(BaseModel):
    items: list[SourceOut]
    generated_at: datetime
