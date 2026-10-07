"""User management endpoints.

* ``/users/me`` is declared BEFORE ``/users/{user_id}`` so the literal path
  never falls through to the id parameter.
* Admin-only routes are guarded by :func:`get_current_admin`.
* Self-protection: an admin cannot deactivate or demote their own account,
  nor delete their own account, via the admin endpoints (mirrored guards).
* All admin mutations are written to the audit log (details sanitized).
* ``GET /users`` is paginated (limit/offset) with a server-enforced max size.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_current_admin
from app.api.helpers import conflict_if_exists, get_or_404
from app.core.audit import record_audit
from app.core.pagination import paginate, pagination_params
from app.core.security import hash_password, validate_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.common import Page
from app.schemas.user import UserCreate, UserRead, UserSelfUpdate, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


def _validate_password_or_422(plain: str | None) -> None:
    if plain is None:
        return
    try:
        validate_password(plain)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


@router.get("/me", response_model=UserRead)
def read_me(user: User = Depends(get_current_active_user)) -> User:
    return user


@router.patch("/me", response_model=UserRead)
def update_me(
    payload: UserSelfUpdate,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> User:
    """Self-service profile update. Privileged fields (role, is_active) are
    never writable through this endpoint."""
    _validate_password_or_422(payload.password)

    if payload.email is not None:
        email = payload.email.lower()
        if email != user.email:
            conflict_if_exists(
                db, select(User).where(User.email == email), message="Email already in use"
            )
            user.email = email

    if payload.username is not None:
        username = payload.username.strip().lower()
        if username != user.username:
            conflict_if_exists(
                db,
                select(User).where(User.username == username),
                message="Username already in use",
            )
            user.username = username

    if payload.password is not None:
        user.hashed_password = hash_password(payload.password)

    db.commit()
    db.refresh(user)
    return user


@router.get("", response_model=Page[UserRead])
def list_users(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> Page[UserRead]:
    limit, offset = pagination
    stmt = select(User).order_by(User.id.asc())
    items, total = paginate(db, stmt, limit=limit, offset=offset)
    return Page[UserRead](items=items, total=total, limit=limit, offset=offset)


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> User:
    _validate_password_or_422(payload.password)
    email = payload.email.lower()
    username = payload.username.strip().lower()

    conflict_if_exists(
        db, select(User).where(User.email == email), message="Email already in use"
    )
    conflict_if_exists(
        db, select(User).where(User.username == username), message="Username already in use"
    )

    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit(
        db,
        admin,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        detail={"email": email, "username": username, "role": user.role, "is_active": user.is_active},
    )
    db.commit()
    return user


@router.get("/{user_id}", response_model=UserRead)
def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> User:
    """Admin lookup. Non-admin callers are rejected (403) before the
    existence check (404), so user ids are not enumerable by regular users."""
    _ = admin  # authorization gate
    return get_or_404(db, User, user_id)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> User:
    """Admin update of another account, with self-protection guards."""
    _validate_password_or_422(payload.password)
    target = get_or_404(db, User, user_id)

    # Self-protection: an admin cannot deactivate or demote their own
    # account through the admin endpoints.
    if target.id == admin.id:
        deactivating = payload.is_active is False
        demoting = payload.role is not None and payload.role != "admin"
        if deactivating or demoting:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An administrator cannot deactivate or demote their own account",
            )

    if payload.email is not None:
        email = payload.email.lower()
        if email != target.email:
            conflict_if_exists(
                db,
                select(User).where(User.email == email, User.id != target.id),
                message="Email already in use",
            )
            target.email = email

    if payload.username is not None:
        username = payload.username.strip().lower()
        if username != target.username:
            conflict_if_exists(
                db,
                select(User).where(User.username == username, User.id != target.id),
                message="Username already in use",
            )
            target.username = username

    if payload.password is not None:
        target.hashed_password = hash_password(payload.password)

    if payload.role is not None:
        target.role = payload.role

    if payload.is_active is not None:
        target.is_active = payload.is_active

    changed = {
        "email": target.email,
        "username": target.username,
        "role": target.role,
        "is_active": target.is_active,
        "password_changed": payload.password is not None,
    }
    record_audit(
        db,
        admin,
        action="user.update",
        resource_type="user",
        resource_id=target.id,
        detail=changed,
    )
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> None:
    """Admin deletion of an account, with self-delete protection."""
    target = get_or_404(db, User, user_id)

    # Mirrored self-protection: an admin cannot delete their own account
    # through the admin endpoints.
    if target.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An administrator cannot delete their own account",
        )

    email = target.email
    username = target.username
    db.delete(target)
    record_audit(
        db,
        admin,
        action="user.delete",
        resource_type="user",
        resource_id=user_id,
        detail={"email": email, "username": username},
    )
    db.commit()
