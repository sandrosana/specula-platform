"""Post-processor interface (docs/architettura.md §5.6).

Inline processors run inside the collector run, after the entities are written,
and update dedicated derived columns (never source fields). Async processors
(AI enrichment, roadmap §13.4) are not implemented in the MVP.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar, Literal

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession


class PostProcessor(ABC):
    name: ClassVar[str]
    version: ClassVar[str]
    applies_to: ClassVar[frozenset[type[BaseModel]]]
    mode: ClassVar[Literal["inline", "async"]] = "inline"

    @abstractmethod
    async def process(self, session: AsyncSession, entities: Sequence[BaseModel]) -> None:
        """Update derived data for `entities`, within the run's transaction."""


_processors: list[PostProcessor] = []


def register_processor(processor: PostProcessor) -> PostProcessor:
    if processor.mode != "inline":
        raise ValueError("only inline post-processors are supported in the MVP")
    _processors.append(processor)
    return processor


def inline_processors() -> list[PostProcessor]:
    return list(_processors)


def unregister_processor(processor: PostProcessor) -> None:
    """For tests."""
    if processor in _processors:
        _processors.remove(processor)
