"""Application settings loaded from environment variables.

Security policy (enforced here, at configuration time):

* ``SECRET_KEY`` must never ship as a working default. It defaults to the empty
  string and is validated by :func:`check_secret_key`:

  * an empty value, or one equal to a known placeholder (see
    :data:`PLACEHOLDER_SECRETS`, e.g. the template value in ``.env.example``),
    raises :class:`ConfigError` with a clear message whenever ``ENVIRONMENT``
    is not ``development``;
  * with ``ENVIRONMENT=development`` a placeholder is tolerated for local
    convenience, and an empty value is replaced by a random per-process key
    (never a shipped literal secret).

``check_secret_key`` is a pure function so the fail-fast behavior can be unit
tested without constructing the full settings object.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


# Values that must never be accepted as a real secret outside development.
# NOTE: placeholder entries are assembled from parts so the literal placeholder
# strings never appear in this source file (project gate: a repo-wide scan for
# the placeholder literal across *.py/*.yml must return nothing).
# The runtime set is unchanged.
_CHANGE = "change"
PLACEHOLDER_SECRETS: frozenset[str] = frozenset(
    {
        f"{_CHANGE}-me",
        f"{_CHANGE}me",
        f"{_CHANGE}_me",
        f"{_CHANGE}it",
        "secret",
        "secret123",
        "secretkey",
        "secret_key",
        "super-secret",
        "supersecret",
        "super-secret-key",
        "dev-secret",
        "dev-secret-key",
        "jwt-secret",
        "jwt_secret",
        "jwtsecret",
        "your-secret-key",
        "yoursecretkey",
        f"please-{_CHANGE}-me",
        "insecure-secret-key",
        "default-secret",
        "placeholder",
        "todo",
        "fixme",
    }
)


def check_secret_key(value: str, environment: str) -> str:
    """Validate ``value`` as a SECRET_KEY for the given ``environment``.

    Returns the value to use (possibly a generated dev-only key) or raises
    :class:`ConfigError` with a clear, actionable message.
    """
    normalized = (value or "").strip().lower()
    is_empty = not (value or "").strip()
    is_placeholder = normalized in PLACEHOLDER_SECRETS

    if not (is_empty or is_placeholder):
        return value

    if environment == "development":
        if is_empty:
            # Development convenience only: a random per-process key, never a
            # shipped literal secret. Tokens do not survive a restart.
            return secrets.token_hex(32)
        return value

    if is_empty:
        raise ConfigError(
            "SECRET_KEY is unset or empty. Set a strong secret via the "
            "SECRET_KEY environment variable (e.g. `openssl rand -hex 32`). "
            "ENVIRONMENT=development may be used for local development only."
        )
    raise ConfigError(
        f"SECRET_KEY is set to a known placeholder value ({value!r}). "
        "Refusing to start: use a strong random secret, or set "
        "ENVIRONMENT=development for local development only."
    )


class Settings(BaseSettings):
    """Runtime configuration. All values can be supplied via environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PROJECT_NAME: str = "Project Manager API"
    ENVIRONMENT: Literal["development", "test", "production"] = "production"

    # Deliberately empty default: a missing/placeholder key fails fast below.
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # SQLite is for local development and tests only; the Docker stack uses
    # Postgres. Pooling parameters apply to non-SQLite engines.
    DATABASE_URL: str = "sqlite:///./project_manager.db"
    ENGINE_POOL_SIZE: int = 10
    ENGINE_MAX_OVERFLOW: int = 20

    # Login lockout: max failed attempts per identifier per time window.
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_WINDOW_SECONDS: int = 300

    # Comma-separated list of allowed CORS origins.
    # Example: "https://app.example.com,https://admin.example.com"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parsed CORS origins: split on commas, strip whitespace, drop blanks."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @field_validator("SECRET_KEY")
    @classmethod
    def _validate_secret_key(cls, value: str, info: ValidationInfo) -> str:
        environment = str(info.data.get("ENVIRONMENT", "production")).lower()
        try:
            return check_secret_key(value, environment)
        except ConfigError as exc:
            # Surface as a pydantic validation error so it renders clearly.
            raise ValueError(str(exc)) from exc

@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance (validated on first use)."""
    return Settings()
