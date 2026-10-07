"""Shared FastAPI dependencies: authn, authz, and ownership guards.

Design notes
------------
* ``OAuth2PasswordBearer`` is declared here (before use in any router) and its
  ``tokenUrl`` matches the real login route (``/auth/login``).
* ``get_project_or_403`` enforces authorization BEFORE confirming existence:
  a non-owner/non-admin always receives 403 whether or not the project exists;
  only a true owner or an admin can ever receive 404.
"""

from __future__ import annotations

import jwt as pyjwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.lockout import login_lockout
from app.db.session import get_db
from app.models.project import Project
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _user_id_from_token(token: str) -> int:
    settings = get_settings()
    try:
        payload = pyjwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except pyjwt.PyJWTError as exc:
        raise _CREDENTIALS_ERROR from exc
    if payload.get("type") != "access":
        raise _CREDENTIALS_ERROR
    try:
        return int(payload["sub"])
    except (KeyError, ValueError, TypeError) as exc:
        raise _CREDENTIALS_ERROR from exc


def get_current_user(
    token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """Resolve the bearer token to an existing user (active or not)."""
    if not token:
        raise _CREDENTIALS_ERROR
    user = db.get(User, _user_id_from_token(token))
    if user is None:
        raise _CREDENTIALS_ERROR
    return user


def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Reject inactive (deactivated) accounts with 403."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return user


def get_current_admin(
    user: User = Depends(get_current_active_user),
) -> User:
    """Restrict to administrator accounts."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return user


def ensure_login_allowed(identifier: str) -> None:
    """Dependency that enforces the login lockout window.

    ``identifier`` is the username or email the client attempted. While the
    sliding window holds at least ``LOGIN_MAX_FAILED_ATTEMPTS`` failures, the
    endpoint responds ``429`` regardless of whether the credentials are now
    correct.
    """
    if login_lockout.is_locked(identifier):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(get_settings().LOGIN_LOCKOUT_WINDOW_SECONDS)},
        )


def get_project_or_403(
    db: Session, project_id: int, user: User
) -> Project:
    """Fetch a project enforcing ownership BEFORE confirming existence.

    * owner  -> the project (404 if the id does not belong to them),
    * admin  -> the project (404 if it does not exist),
    * anyone else -> 403 whether or not the project exists.
    """
    owned = (
        db.execute(
            select(Project).where(Project.id == project_id, Project.owner_id == user.id)
        )
        .scalars()
        .first()
    )
    if owned is not None:
        return owned

    if user.is_admin:
        project = db.get(Project, project_id)
        if project is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
            )
        return project

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Project not found"
    )
