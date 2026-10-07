"""Admin read access to the audit log (paginated, newest first)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.core.audit import list_audit_entries
from app.core.pagination import pagination_params
from app.db.session import get_db
from app.models.user import User
from app.schemas.audit import AuditEntryRead
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEntryRead])
def list_audit_entries_endpoint(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> Page[AuditEntryRead]:
    """List administrative audit entries (newest first). Admin only."""
    limit, offset = pagination
    items, total = list_audit_entries(db, limit=limit, offset=offset)
    return Page[AuditEntryRead](items=items, total=total, limit=limit, offset=offset)
