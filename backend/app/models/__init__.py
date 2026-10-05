"""SQLAlchemy models. Import every model module here so Alembic sees all tables."""

from app.models.base import Base, ClassifiedMixin, classification_type

__all__ = ["Base", "ClassifiedMixin", "classification_type"]
