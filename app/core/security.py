"""Password hashing, password policy, and JWT access/refresh token handling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import bcrypt
import jwt

from app.core.config import get_settings

# A deliberately small, embedded blocklist of trivial/common passwords.
# Checked case-insensitively, in addition to the structural policy below.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "password1234",
        "pass123",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "000000",
        "111111",
        "121212",
        "123123",
        "qwerty",
        "qwerty1",
        "qwerty123",
        "qwertyuiop",
        "abc123",
        "abcd1234",
        "iloveyou",
        "iloveyou1",
        "letmein",
        "letmein1",
        "welcome",
        "welcome1",
        "welcome123",
        "admin",
        "admin123",
        "administrator",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "football",
        "trustno1",
        "passw0rd",
        "secret",
        "changeme",
        "secret123",
        "hunter2",
        "p@ssw0rd",
    }
)


def hash_password(plain: str) -> str:
    """Hash a password with bcrypt (cost 12)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt verification. Returns False on malformed input."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def validate_password(plain: str) -> None:
    """Enforce a password policy stronger than length-only.

    Rules: minimum 8 characters, at least one letter, at least one digit, and
    not present in the common/trivial password blocklist.
    Raises ``ValueError`` with a human-readable message on violation.
    """
    if not isinstance(plain, str) or not plain:
        raise ValueError("Password is required.")
    if len(plain) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if plain.lower() in COMMON_PASSWORDS:
        raise ValueError("Password is too common; choose a stronger password.")
    if not any(c.isalpha() for c in plain):
        raise ValueError("Password must contain at least one letter.")
    if not any(c.isdigit() for c in plain):
        raise ValueError("Password must contain at least one digit.")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: int, email: str, role: str) -> str:
    """Create a short-lived access token (HS256, sub + exp + jti)."""
    settings = get_settings()
    now = _utcnow()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": "access",
        "jti": uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: int, email: str) -> str:
    """Create a longer-lived refresh token carrying a unique ``jti``.

    The ``jti`` is tracked server-side (revocation list) so logout/rotation
    can invalidate it before natural expiry.
    """
    settings = get_settings()
    now = _utcnow()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "type": "refresh",
        "jti": uuid4().hex,
        "iat": now,
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str, expected_type: str) -> dict[str, Any]:
    """Decode and validate a JWT.

    Raises ``jwt.InvalidTokenError`` subclasses (caught by callers as 401) on
    missing/expired/malformed tokens, signature mismatch, or type mismatch.
    """
    settings = get_settings()
    payload: dict[str, Any] = jwt.decode(
        token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"Expected a {expected_type} token")
    return payload
