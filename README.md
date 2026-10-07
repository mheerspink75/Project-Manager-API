# Project Manager API

A production-grade FastAPI backend for managing users and projects, built with
Python 3.11+, Pydantic v2, SQLAlchemy 2.x and Alembic.

## Features

- **Authentication**: JWT access + refresh token pairs (PyJWT/HS256), bcrypt
  password hashing (cost 12), login with per-identifier lockout (rate limiting),
  server-side token revocation (logout + refresh rotation).
- **Authorization**: role-based access control (regular `user` / `admin`),
  ownership-gated projects with **authorization checked before existence**
  (non-owners always get `403`; only owners/admins ever see `404`), admin
  self-protection (an admin cannot deactivate, demote, or delete their own
  account).
- **Audit log**: every administrative mutation (user create/update/delete,
  project mutations performed by admins) records who did what, to which
  resource, and when. Passwords and secrets are never logged.
- **Pagination**: `limit`/`offset` on every list endpoint (default 20,
  server-enforced max 100).
- **Hardened configuration**: the app refuses to start with an unset, empty,
  or placeholder `SECRET_KEY` unless `ENVIRONMENT=development` is explicitly
  set. No working secret ships anywhere in the repository.
- **Migrations**: Alembic-managed schema; the initial migration is verified
  against `Base.metadata` with `alembic check`.

## Repository layout

```
app/
  main.py               # FastAPI app assembly (validates settings on import)
  core/
    config.py           # pydantic-settings + SECRET_KEY fail-fast policy
    security.py         # bcrypt, password policy, JWT access/refresh
    lockout.py          # in-app per-identifier login lockout (documented choice)
    audit.py            # audit-log writer (sanitizes secrets) + lister
    pagination.py       # shared limit/offset helpers (default 20, max 100)
  db/
    base.py             # the single shared declarative Base
    session.py          # engine (pooling for non-SQLite), get_db dependency
  models/               # User, Project, AuditLog, TokenRevocation
  schemas/              # Pydantic v2 request/response models
  api/
    deps.py             # OAuth2 scheme, current-user/admin deps, ownership guard
    helpers.py          # generic get-or-404 helpers (shared by all routers)
    routes/             # health, auth, users, projects
alembic/                # migration env + versions
scripts/verify_migration.py
tests/                  # pytest suite (isolated in-memory DB per test)
```

## Quickstart (local development)

Python 3.11+ is required (developed against 3.14).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
python -m pip install -r requirements.txt

cp .env.example .env            # optional; or export the variables directly
export ENVIRONMENT=development
export SECRET_KEY="$(openssl rand -hex 32)"   # any non-empty value in development
export DATABASE_URL="sqlite:///./project_manager.db"   # SQLite = local dev only

python -m alembic upgrade head
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/docs> for the interactive API docs.

### First admin

Public registration always creates a regular user. To bootstrap the first
admin (one-time), register a user, then promote it directly in the database:

```bash
export ENVIRONMENT=development SECRET_KEY="$(openssl rand -hex 32)" \
       DATABASE_URL="sqlite:///./project_manager.db"
python - <<'PY'
from app.db.session import SessionLocal
from app.models.user import User

db = SessionLocal()
u = db.query(User).filter_by(username="alice").first()
assert u, "register the user first (POST /auth/register)"
u.role = "admin"
db.commit()
print(f"promoted {u.username} to admin")
PY
```

## Quickstart (Docker, Postgres by default)

```bash
cp .env.example .env
# In .env set at minimum:
#   SECRET_KEY=<output of: openssl rand -hex 32>
#   POSTGRES_PASSWORD=<strong password>
docker compose up --build -d
```

The `api` service depends on a healthy `db` (Postgres 16) service, applies
migrations (`alembic upgrade head`) on startup, and serves the API on port
8000. **Compose fails fast with a clear message if `SECRET_KEY` or
`POSTGRES_PASSWORD` are missing** — there is no embedded fallback secret.

## API overview

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | – | Liveness + DB connectivity probe |
| POST | `/auth/register` | – | Create a regular user (201) |
| POST | `/auth/login` | – | Username-or-email + password → access+refresh tokens (lockout: 429) |
| POST | `/auth/refresh` | – | Rotate refresh token for a new pair (revoked on use) |
| POST | `/auth/logout` | Bearer | Revoke a refresh token server-side (204) |
| GET | `/users/me` | Bearer | Current user |
| PATCH | `/users/me` | Bearer | Update own email/username/password |
| GET | `/users` | Admin | List users (paginated) |
| POST | `/users` | Admin | Create user (201, audited) |
| GET | `/users/{id}` | Admin | Read user (403 for non-admins before existence is checked) |
| PATCH | `/users/{id}` | Admin | Update user (self-protection guards, audited) |
| DELETE | `/users/{id}` | Admin | Delete user (self-protection guard, audited) |
| POST | `/projects` | Bearer | Create project owned by caller (201) |
| GET | `/projects` | Bearer | List own projects (admin: all) — paginated |
| GET | `/projects/{id}` | Bearer | Read (owner/admin; others 403 whether or not it exists) |
| PATCH | `/projects/{id}` | Bearer | Update (owner/admin; admin mutations audited) |
| DELETE | `/projects/{id}` | Bearer | Delete (owner/admin; admin mutations audited) |
| GET | `/audit` | Admin | List audit entries, newest first (paginated) |

### Pagination

List endpoints accept `limit` (default `20`, max `100`) and `offset`
(default `0`) and return:

```json
{ "items": [ ... ], "total": 42, "limit": 20, "offset": 0 }
```

Out-of-range offsets return `200` with an empty `items` array and the correct
`total`.

## Security model

- **Secrets**: `SECRET_KEY` defaults to empty and is validated at
  configuration time. Empty values and known placeholders (e.g. `change-me`)
  raise a clear `ConfigError` unless `ENVIRONMENT=development`. In development
  an empty value is replaced by a random per-process key (never a shipped
  literal). Docker Compose requires `SECRET_KEY` and `POSTGRES_PASSWORD` from
  the environment — it aborts with a clear message otherwise.
- **Passwords**: bcrypt (cost 12); policy = min 8 chars, at least one letter,
  at least one digit, and rejection of a common/trivial password blocklist.
- **Tokens**: short-lived access token (15 min) + refresh token (7 days) with
  a `jti`. Refresh **rotates** (old jti revoked); logout **revokes** the jti
  in a server-side revocation list, so invalidation does not depend on expiry.
- **Login lockout**: 5 failed attempts per identifier per 300 s window →
  `429 Too Many Requests` (even with a subsequently correct password), with a
  `Retry-After` header. Implemented in-app and keyed by *credential
  identifier* (the requirement's semantics); deliberately chosen over an
  IP-keyed limiter such as slowapi.
- **Authorization ordering**: for ownership-gated resources the code checks
  ownership before existence, so non-owners always receive `403` (no
  existence leakage); only true owners or admins can receive `404`.
- **Admin self-protection**: an admin cannot deactivate or demote their own
  account, nor delete their own account, via the admin endpoints.
- **Audit log**: admin user mutations and admin project mutations are recorded
  (actor, action, resource, timestamp, sanitized detail). Passwords, tokens,
  and other secrets are stripped from audit detail before storage.

## Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `production` | `development` / `test` / `production` |
| `SECRET_KEY` | *(empty → fail-fast)* | required outside development |
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | |
| `DATABASE_URL` | `sqlite:///./project_manager.db` | use Postgres in the Docker stack |
| `ENGINE_POOL_SIZE` | `10` | non-SQLite engines only |
| `ENGINE_MAX_OVERFLOW` | `20` | non-SQLite engines only |
| `LOGIN_MAX_FAILED_ATTEMPTS` | `5` | lockout threshold |
| `LOGIN_LOCKOUT_WINDOW_SECONDS` | `300` | lockout window |

## Testing

```bash
python -m pytest -v                                   # full suite
python -m pytest --cov=app --cov-report=term-missing  # with coverage
```

Every test runs against an isolated in-memory SQLite database (per-test
engine), the login lockout is reset between tests, and all IDs/tokens are
obtained from fixtures or API responses — never hardcoded.

## Migration verification

```bash
python scripts/verify_migration.py    # or: make verify-migration
```

This runs `alembic upgrade head` against a throwaway database and then
`alembic check` to confirm the resulting schema matches `Base.metadata`
(expected output: `No new upgrade operations detected.`).

## Production notes / limitations

- The in-memory login lockout and refresh-token revocation list are
  process-local. For multi-replica deployments, move both to shared storage
  (e.g. Redis) or the database (revocation list is already in the DB; only
  the lockout counter is in-process).
- CORS is locked to `http://localhost:3000` as a safe default; extend
  `app/main.py` for your frontend origin(s).
- Run `uvicorn` behind TLS in production (e.g. a reverse proxy) and consider
  `--workers` for concurrency.
- Alembic `env.py` reads `DATABASE_URL` from the environment, so migrations
  run independently of the JWT secret.
