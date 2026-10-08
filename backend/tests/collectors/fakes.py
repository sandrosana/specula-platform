"""In-memory stores and a controllable clock for collector tests."""

from datetime import UTC, date, datetime, timedelta

from app.collectors.http import CachedResponse


class FakeClock:
    def __init__(self, start: datetime = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)) -> None:
        self.current = start
        self.mono = 1000.0
        self.slept: list[float] = []

    def now(self) -> datetime:
        return self.current

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)
        self.mono += seconds

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.advance(seconds)


class MemoryCacheStore:
    def __init__(self) -> None:
        self.entries: dict[str, CachedResponse] = {}

    async def get(self, key: str) -> CachedResponse | None:
        return self.entries.get(key)

    async def put(self, entry: CachedResponse) -> None:
        self.entries[entry.key] = entry


class MemoryUsageStore:
    def __init__(self) -> None:
        self.counts: dict[tuple[str, date], int] = {}

    async def increment(self, source: str, day: date) -> None:
        self.counts[(source, day)] = self.counts.get((source, day), 0) + 1

    async def total(self, source: str, since: date) -> int:
        return sum(n for (name, day), n in self.counts.items() if name == source and day >= since)
