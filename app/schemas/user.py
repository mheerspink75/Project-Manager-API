"""User-facing schemas (registration, admin CRUD, self-update, read)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRegister(BaseModel):
    """Public self-service registration (always creates a regular user)."""

    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserCreate(BaseModel):
    """Admin user creation. ``role`` is restricted to the two valid roles."""

    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user", pattern="^(user|admin)$")
    is_active: bool = True


class UserUpdate(BaseModel):
    """Partial admin update of a user account."""

    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=64)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    role: str | None = Field(default=None, pattern="^(user|admin)$")
    is_active: bool | None = None


class UserSelfUpdate(BaseModel):
    """User self-service profile update (no privileged fields)."""

    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=64)
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserRead(BaseModel):
    """Safe representation of a user (never exposes the password hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    username: str
    role: str
    is_active: bool
    created_at: datetime
