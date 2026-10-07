"""Engine, session factory, and the ``get_db`` FastAPI dependency.

SQLite (local development and tests only) gets ``check_same_thread=False`` and
no pool-size arguments (those are invalid for the SQLite drivers). All other
backends (e.g. Postgres in the Docker stack) get explicit
``pool_size``/``max_overflow`` values read from settings.

``engine_kwargs`` is a pure function so the SQLite-vs-Postgres branch can be
unit-tested without a live Postgres server.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def engine_kwargs(url: str, *, pool_size: int, max_overflow: int) -> dict[str, object]:
    """Build ``create_engine`` kwargs for ``url``.

    SQLite: ``check_same_thread=False`` (shared in-memory/file DB across
    threads) and no pool sizing (invalid for SQLite drivers).
    Any other backend: explicit pool sizing from settings + ``pool_pre_ping``.
    """
    kwargs: dict[str, object] = {"echo": False, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update(
            {
                "pool_size": pool_size,
                "max_overflow": max_overflow,
                "pool_pre_ping": True,
                "pool_timeout": 30,
            }
        )
    return kwargs


_settings = get_settings()
engine = create_engine(
    _settings.DATABASE_URL,
    **engine_kwargs(
        _settings.DATABASE_URL,
        pool_size=_settings.ENGINE_POOL_SIZE,
        max_overflow=_settings.ENGINE_MAX_OVERFLOW,
    ),
)

SessionLocal = sessionmaker(
    bind=engine, autoflush=False, expire_on_commit=False, future=True
)


def get_db() -> Iterator[Session]:
    """Yield a database session per request and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
