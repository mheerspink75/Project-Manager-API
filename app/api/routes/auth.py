"""Authentication endpoints: register, login, refresh, logout.

* Login is protected by an in-app per-identifier lockout (429 after N failed
  attempts within a sliding window).
* Login returns a short-lived access token plus a refresh token whose ``jti``
  is tracked server-side; refresh rotates it and logout revokes it, so token
  invalidation does not rely on expiry alone.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import ensure_login_allowed, get_current_active_user
from app.core.lockout import login_lockout
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password,
    verify_password,
)
from app.db.session import get_db
from app.models.token_revocation import TokenRevocation
from app.models.user import User
from app.schemas.auth import LogoutRequest, RefreshRequest, TokenPair
from app.schemas.user import UserRead, UserRegister

router = APIRouter(prefix="/auth", tags=["auth"])


def _auth_error(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: UserRegister, db: Session = Depends(get_db)) -> User:
    """Self-service registration. New accounts are always regular users."""
    try:
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    username = payload.username.strip().lower()
    email = payload.email.lower()

    existing = (
        db.execute(select(User).where(User.email == email))
        .scalars()
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )
    existing = (
        db.execute(select(User).where(User.username == username))
        .scalars()
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this username already exists",
        )

    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(payload.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenPair:
    """Authenticate with username-or-email + password.

    The identifier is checked against the lockout BEFORE credential
    verification, so locked identifiers get 429 even with a correct password.
    """
    ensure_login_allowed(form.username)

    identifier = form.username.strip().lower()
    user = (
        db.execute(
            select(User).where(
                (User.email == identifier) | (User.username == identifier)
            )
        )
        .scalars()
        .first()
    )

    if user is None or not verify_password(form.password, user.hashed_password):
        login_lockout.record_failure(identifier)
        raise _auth_error("Incorrect username or password")

    if not user.is_active:
        login_lockout.record_failure(identifier)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )

    login_lockout.clear(identifier)
    return TokenPair(
        access_token=create_access_token(user.id, user.email, user.role),
        refresh_token=create_refresh_token(user.id, user.email),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh_tokens(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenPair:
    """Exchange a valid, unrevoked refresh token for a fresh token pair.

    The presented refresh token is rotated (revoked) on success.
    """
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except Exception as exc:  # jwt.InvalidTokenError and friends
        raise _auth_error("Invalid or expired refresh token") from exc

    user_id = int(claims["sub"])
    jti = str(claims.get("jti", ""))

    revoked = (
        db.execute(select(TokenRevocation).where(TokenRevocation.jti == jti))
        .scalars()
        .first()
    )
    if revoked is not None:
        raise _auth_error("Refresh token has been revoked")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _auth_error("Invalid account")

    db.add(TokenRevocation(jti=jti, user_id=user.id))
    db.commit()

    return TokenPair(
        access_token=create_access_token(user.id, user.email, user.role),
        refresh_token=create_refresh_token(user.id, user.email),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: LogoutRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> None:
    """Revoke a refresh token server-side (works even if already expired or
    already revoked; invalid tokens are rejected with 401)."""
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except Exception as exc:
        raise _auth_error("Invalid refresh token") from exc

    jti = str(claims.get("jti", ""))
    user_id = int(claims["sub"])

    existing = (
        db.execute(select(TokenRevocation).where(TokenRevocation.jti == jti))
        .scalars()
        .first()
    )
    if existing is None and user_id == user.id:
        db.add(TokenRevocation(jti=jti, user_id=user.id))
        db.commit()
