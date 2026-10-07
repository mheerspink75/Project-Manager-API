"""Health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check(
    db: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> dict[str, str]:
    """Liveness probe: verifies process configuration and DB connectivity."""
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "environment": settings.ENVIRONMENT,
        "service": settings.PROJECT_NAME,
    }
