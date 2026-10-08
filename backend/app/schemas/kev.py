from datetime import date, datetime

from pydantic import BaseModel, ConfigDict

from app.core.classification import Classification


class KevItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date | None
    short_description: str
    required_action: str
    known_ransomware_campaign_use: str | None
    ransomware_known: bool
    forensic_triage: bool | None
    notes: str | None
    cwes: list[str]
    classification: Classification


class KevPage(BaseModel):
    items: list[KevItem]
    total: int
    next_cursor: str | None
    # Last successful run of the cisa_kev collector (freshness indicator).
    data_as_of: datetime | None
