"""SQLAlchemy models. Import every model module here so Alembic sees all tables."""

from app.models.auth import LoginFailureRow, RecoveryCodeRow, SessionRow, UserRow
from app.models.base import Base, ClassifiedMixin, classification_type
from app.models.collector import CollectorRun, CollectorState, HttpCacheEntry, SourceUsage
from app.models.epss import EpssHistoryRow, EpssScoreRow
from app.models.kev import KevEntryRow
from app.models.vulnerability import VulnerabilityProductRow, VulnerabilityRow

__all__ = [
    "Base",
    "ClassifiedMixin",
    "CollectorRun",
    "CollectorState",
    "EpssHistoryRow",
    "EpssScoreRow",
    "HttpCacheEntry",
    "KevEntryRow",
    "LoginFailureRow",
    "RecoveryCodeRow",
    "SessionRow",
    "SourceUsage",
    "UserRow",
    "VulnerabilityProductRow",
    "VulnerabilityRow",
    "classification_type",
]
