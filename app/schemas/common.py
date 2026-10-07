"""Generic pagination envelope for list endpoints."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """A page of items plus pagination metadata."""

    items: list[T]
    total: int
    limit: int
    offset: int
