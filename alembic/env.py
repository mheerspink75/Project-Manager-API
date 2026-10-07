"""Alembic migration environment.

Intentionally independent of the application's JWT settings: migrations only
need the database URL, so ``alembic upgrade head`` works without a configured
SECRET_KEY. The URL is resolved from (in order) the ``sqlalchemy.url`` ini
option, the ``DATABASE_URL`` environment variable, or a local SQLite fallback
(development/tests only).
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

import app.models  # noqa: F401  -- import all models so Base.metadata is complete
from app.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return (
        config.get_main_option("sqlalchemy.url")
        or os.environ.get("DATABASE_URL")
        or "sqlite:///./project_manager.db"
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a connection)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (with a live connection)."""
    url = get_url()
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url

    kwargs: dict[str, object] = {
        "prefix": "sqlalchemy.",
        "poolclass": pool.NullPool,
    }
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_pre_ping"] = True

    connectable = engine_from_config(section, **kwargs)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
