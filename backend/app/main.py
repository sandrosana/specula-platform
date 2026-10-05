"""FastAPI application factory.

Run with: uvicorn app.main:create_app --factory
"""

from fastapi import FastAPI

from app import __version__
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=None,
    )
    app.include_router(api_router, prefix=settings.api_prefix)
    return app
