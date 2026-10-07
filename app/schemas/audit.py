"""Audit log read model."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int | None
    actor_email: str
    action: str
    resource_type: str
    resource_id: str
    detail: str
    created_at: datetime
