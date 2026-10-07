"""FastAPI application assembly.

Importing this module validates settings (SECRET_KEY fail-fast happens here,
not at process exit) and builds the app with routers and CORS.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import audit, auth, health, projects, users
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Project Manager backend: users, projects, JWT auth, RBAC, audit log.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    # Configurable via the CORS_ORIGINS env var (see Settings.cors_origins_list).
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(projects.router)
app.include_router(audit.router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"service": settings.PROJECT_NAME, "docs": "/docs", "health": "/health"}
