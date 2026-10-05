"""Data classification (docs/architettura.md §10).

Every entity, sighting and event row carries a classification assigned by the
collector at collection time. A row without an explicit classification is
treated as sensitive: this is also the database default.
"""

from enum import StrEnum


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"


DEFAULT_CLASSIFICATION = Classification.SENSITIVE
