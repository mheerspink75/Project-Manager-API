"""Audit logging for administrative mutating actions.

Records *who* did *what* to *which resource* and *when*. Values written to
``detail`` are sanitized: raw passwords, hashed passwords, tokens, and other
secrets must never reach the audit trail.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.pagination import paginate
from app.models.audit_log import AuditLog
from app.models.token_revocation import TokenRevocation
from app.models.user import User

# Keys (lower-cased) that must never be serialized into the audit detail.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "plain_password",
        "hashed_password",
        "secret",
        "secret_key",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
    }
)


def sanitize_detail(detail: dict[str, Any] | None) -> str:
    """Serialize ``detail`` to a JSON string, dropping sensitive keys."""
    if not detail:
        return ""

    def _clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(k): _clean(v)
                for k, v in value.items()
                if str(k).lower() not in _SENSITIVE_KEYS
            }
        if isinstance(value, (list, tuple)):
            return [_clean(v) for v in value]
        return value

    cleaned = _clean(detail)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=True, default=str)


def record_audit(
    db: Session,
    actor: User,
    action: str,
    resource_type: str,
    resource_id: Any,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Persist an audit entry for an administrative mutating action.

    The caller is responsible for committing the surrounding transaction; this
    helper only stages the row.
    """
    entry = AuditLog(
        actor_id=actor.id,
        actor_email=actor.email,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        detail=sanitize_detail(detail),
    )
    db.add(entry)
    return entry


def list_audit_entries(
    db: Session, *, limit: int, offset: int
) -> tuple[list[AuditLog], int]:
    """Return a page of audit entries (newest first) plus the total count."""
    # Delegate limit/offset + total-count to the shared pagination helper so
    # the page-size rules stay consistent with every other list endpoint.
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    )
    items, total = paginate(db, stmt, limit=limit, offset=offset)
    return list(items), total


def purge_expired_revocations(db: Session) -> int:
    """Delete token revocation rows whose refresh token has already expired.

    A revocation row is only needed while the underlying refresh token could
    still be presented; once ``expires_at`` has passed the row is dead weight.
    Intended to be called by a cron job or a startup hook (NOT from a request
    path). Returns the number of rows deleted.
    """
    result = db.execute(
        delete(TokenRevocation).where(TokenRevocation.expires_at < func.now())
    )
    db.commit()
    return result.rowcount or 0
