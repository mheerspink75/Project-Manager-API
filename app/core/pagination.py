"""Shared limit/offset pagination helpers.

Every list endpoint uses this module so the default page size and the
server-enforced maximum page size stay consistent across routers.

Routers pass a clean ``Select`` (no limit/offset of their own); this helper
applies the validated ``limit``/``offset`` and computes the accurate total.
An out-of-range page (``offset`` past the end) yields an empty item list with
the correct ``total``; it is a 200, not an error.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fastapi import Query
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def pagination_params(
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> tuple[int, int]:
    """FastAPI dependency that validates and returns ``(limit, offset)``.

    * ``limit`` defaults to :data:`DEFAULT_PAGE_SIZE` and is capped at
      :data:`MAX_PAGE_SIZE` server-side (``le``);
    * ``offset`` defaults to 0.
    """
    return limit, offset


def paginate(
    db: Session, stmt: Select, *, limit: int, offset: int
) -> tuple[Sequence[Any], int]:
    """Apply limit/offset to ``stmt`` and return ``(items, total)``."""
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.execute(stmt.limit(limit).offset(offset)).scalars().all()
    return list(items), int(total)
