"""Generic resource helpers shared by every router (no per-router 404 logic)."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import Base


def get_or_404(db: Session, model: type[Base], pk: int, *, message: str | None = None) -> Base:
    """Return the row with primary key ``pk`` or raise ``404``.

    Single reusable helper used by all resource routers instead of
    duplicating fetch-or-404 logic per endpoint.
    """
    instance = db.get(model, pk)
    if instance is None:
        detail = message or f"{model.__name__} not found"
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return instance


def conflict_if_exists(db: Session, stmt: Any, *, message: str) -> None:
    """Raise ``409`` if any row matches ``stmt`` (used for uniqueness checks)."""
    if db.execute(stmt).scalars().first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)
