"""Async database engine and sessions."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Create the engine. No connection is opened until it is first used."""
    return create_async_engine(settings.database_url.get_secret_value(), pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def check_database(engine: AsyncEngine) -> None:
    """Raise if the database cannot be reached."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
