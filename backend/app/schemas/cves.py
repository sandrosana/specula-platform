from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel

from app.core.classification import Classification

PriorityLevel = Literal["P1", "P2", "P3", "P4"]


class CvssSummary(BaseModel):
    score: float
    version: str | None
    severity: str | None


class EpssSummary(BaseModel):
    score: float
    percentile: float
    score_date: date
    model_version: str


class KevSummary(BaseModel):
    date_added: date
    due_date: date | None
    known_ransomware_campaign_use: str | None
    ransomware_known: bool


class Priority(BaseModel):
    level: PriorityLevel | None
    # Structured facts (rule, kev, epss, epss_threshold, cvss): the UI builds the sentence.
    reason: dict[str, Any] | None


class AffectedProduct(BaseModel):
    vendor: str
    product: str
    source: str
    part: str | None


class CveItem(BaseModel):
    cve_id: str
    published: datetime
    last_modified: datetime
    vuln_status: str
    description: str | None
    cvss: CvssSummary | None
    epss: EpssSummary | None
    kev: KevSummary | None
    priority: Priority
    # First affected products (NVD CPE data first); the detail lists all of them.
    products: list[AffectedProduct]
    products_total: int
    classification: Classification


class CvePage(BaseModel):
    items: list[CveItem]
    total: int
    next_cursor: str | None
    # Last successful run of the nvd collector (freshness indicator).
    data_as_of: datetime | None


class KevDetail(KevSummary):
    vendor_project: str
    product: str
    vulnerability_name: str
    short_description: str
    required_action: str
    notes: str | None


class CvssMetric(BaseModel):
    version: str
    source: str | None
    type: str | None
    score: float
    severity: str | None
    vector: str | None


class Reference(BaseModel):
    url: str
    tags: list[str]


class EpssHistoryPoint(BaseModel):
    score_date: date
    score: float
    percentile: float
    model_version: str
    # first | change | threshold | model
    reason: str


class CveDetail(BaseModel):
    cve_id: str
    source_identifier: str | None
    published: datetime
    last_modified: datetime
    vuln_status: str
    description: str | None
    cvss: CvssSummary | None
    cvss_vector: str | None
    cvss_metrics: list[CvssMetric]
    cwes: list[str]
    references: list[Reference]
    products: list[AffectedProduct]
    epss: EpssSummary | None
    epss_history: list[EpssHistoryPoint]
    kev: KevDetail | None
    priority: Priority
    classification: Classification
    data_as_of: datetime | None
