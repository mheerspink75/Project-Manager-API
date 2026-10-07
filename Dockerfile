# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Project Manager API - production image
#
# * Postgres is the intended database (see docker-compose.yml); the driver
#   (psycopg) ships with the pinned requirements.
# * The app FAILS FAST at startup if SECRET_KEY is missing/placeholder and
#   ENVIRONMENT is not "development" (enforced by app.core.config) - no
#   fallback secret exists anywhere in this stack.
# * Migrations run automatically on startup (alembic upgrade head).
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Run as an unprivileged user.
RUN groupadd --system app && useradd --system --gid app --home-dir /app app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)" || exit 1

# Apply migrations, then start the API.
# If SECRET_KEY is invalid/missing the import of app.main raises a clear
# ConfigError and the container exits non-zero (fail-fast by design).
ENTRYPOINT ["/bin/sh", "-c", "python -m alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
