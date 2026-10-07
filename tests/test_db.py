"""Database layer tests: engine kwargs policy and the real get_db dependency."""

from __future__ import annotations

import os

from app.core.config import get_settings
from app.db.session import engine_kwargs, get_db


class TestEngineKwargs:
    def test_sqlite_url_gets_no_pool_sizing(self):
        kwargs = engine_kwargs("sqlite:///./x.db", pool_size=10, max_overflow=20)
        assert kwargs["connect_args"] == {"check_same_thread": False}
        assert "pool_size" not in kwargs
        assert "max_overflow" not in kwargs

    def test_sqlite_memory_url_too(self):
        kwargs = engine_kwargs("sqlite://", pool_size=10, max_overflow=20)
        assert "pool_size" not in kwargs

    def test_postgres_url_gets_pool_sizing_from_settings(self):
        kwargs = engine_kwargs(
            "postgresql+psycopg://u:p@db:5432/x", pool_size=7, max_overflow=3
        )
        assert kwargs["pool_size"] == 7
        assert kwargs["max_overflow"] == 3
        assert kwargs["pool_pre_ping"] is True
        assert "connect_args" not in kwargs

    def test_settings_defaults_are_sane(self):
        settings = get_settings()
        assert settings.ENGINE_POOL_SIZE >= 1
        assert settings.ENGINE_MAX_OVERFLOW >= 0


class TestGetDb:
    def test_get_db_yields_a_working_session_and_closes(self, tmp_path, monkeypatch):
        # Point the real session factory at a throwaway database file so this
        # test exercises the REAL get_db (not the test override) without
        # leaving artifacts.
        db_file = tmp_path / "real_getdb.db"
        from app.db import session as session_module
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine(
            f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
        )
        from app.db.base import Base

        Base.metadata.create_all(engine)

        old_session_local = session_module.SessionLocal
        session_module.SessionLocal = sessionmaker(
            bind=engine, autoflush=False, expire_on_commit=False, future=True
        )
        try:
            gen = get_db()
            db = next(gen)
            from app.models.user import User

            user = User(
                email="real@getdb.example",
                username="realgetdb",
                hashed_password="x",
                role="user",
                is_active=True,
            )
            db.add(user)
            db.commit()
            assert db.query(User).count() == 1
        finally:
            try:
                next(gen)
            except StopIteration:
                pass
            session_module.SessionLocal = old_session_local
            engine.dispose()
            if db_file.exists():
                os.remove(db_file)
