"""Entity writers: idempotent upserts on natural keys (docs/architettura.md §5.4 point 5).

Each entity type (a Pydantic model returned by `normalize`) has one writer.
Writers receive the classification assigned by the collector and must upsert:
re-running a collector never creates duplicates.
"""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.classification import Classification


@dataclass(frozen=True)
class WriteStats:
    inserted: int = 0
    updated: int = 0

    def __add__(self, other: "WriteStats") -> "WriteStats":
        return WriteStats(self.inserted + other.inserted, self.updated + other.updated)


EntityWriter = Callable[[AsyncSession, Sequence[BaseModel], Classification], Awaitable[WriteStats]]

_writers: dict[type[BaseModel], EntityWriter] = {}


def register_writer(entity: type[BaseModel]) -> Callable[[EntityWriter], EntityWriter]:
    def decorator(writer: EntityWriter) -> EntityWriter:
        _writers[entity] = writer
        return writer

    return decorator


def writer_for(entity: type[BaseModel]) -> EntityWriter:
    try:
        return _writers[entity]
    except KeyError:
        raise LookupError(f"no writer registered for {entity.__name__}") from None


def unregister_writer(entity: type[BaseModel]) -> None:
    """For tests."""
    _writers.pop(entity, None)
