"""Version 1 of the Specula Threat API."""

from fastapi import APIRouter

from app.api.v1 import auth, cves, health, kev, sources

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(cves.router)
api_router.include_router(kev.router)
api_router.include_router(sources.router)
