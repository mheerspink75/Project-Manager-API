"""The single shared declarative Base for all ORM models.

There is exactly one Base in the codebase; every model inherits from it so
``Base.metadata`` is the complete schema (used by Alembic and tests).
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base."""
