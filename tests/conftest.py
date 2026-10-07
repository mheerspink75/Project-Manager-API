"""Shared test fixtures.

Isolation strategy (requirement 18):
* every test gets a brand-new in-memory SQLite database (function-scoped
  engine + ``StaticPool`` so the app's worker thread and the test thread
  share one connection),
* ``app.db.session.get_db`` is dependency-overridden to that engine,
* the login lockout state is reset between tests,
* all primary keys and tokens are obtained from fixtures/API responses —
  never hardcoded.
"""

from __future__ import annotations

import os

# Environment MUST be configured before any ``app`` import happens.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-0123456789-0123456789")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.lockout import login_lockout
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.project import Project
from app.models.user import User

TEST_PASSWORD = "C0rrect-Horse-Battery"


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture()
def session(engine) -> Session:
    """A direct ORM session on the same engine (for setup/assertions)."""
    testing_local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    s = testing_local()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def client(engine):
    testing_local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        s = testing_local()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    login_lockout.reset()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        login_lockout.reset()


def make_user(
    session: Session,
    *,
    email: str,
    username: str,
    password: str = TEST_PASSWORD,
    role: str = "user",
    is_active: bool = True,
) -> User:
    """Create a user directly in the database (fixture-level helper)."""
    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(password),
        role=role,
        is_active=is_active,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture()
def admin(session) -> User:
    return make_user(session, email="admin@example.com", username="admin", role="admin")


@pytest.fixture()
def regular_user(session) -> User:
    return make_user(session, email="alice@example.com", username="alice")


@pytest.fixture()
def other_user(session) -> User:
    return make_user(session, email="bob@example.com", username="bob")


@pytest.fixture()
def inactive_user(session) -> User:
    return make_user(session, email="dormant@example.com", username="dormant", is_active=False)


def api_login(client: TestClient, identifier: str, password: str = TEST_PASSWORD):
    return client.post(
        "/auth/login", data={"username": identifier, "password": password}
    )


def auth_headers(client: TestClient, user: User, password: str = TEST_PASSWORD) -> dict[str, str]:
    """Log a user in and return ready-to-use Authorization headers."""
    response = api_login(client, user.username, password)
    assert response.status_code == 200, response.text
    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def make_project(session: Session, owner: User, name: str = "Project", **kwargs) -> Project:
    project = Project(name=name, description="fixture", owner_id=owner.id, **kwargs)
    session.add(project)
    session.commit()
    session.refresh(project)
    return project
