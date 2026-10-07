"""Project endpoints with ownership authorization.

* ``GET /projects`` is paginated: regular users see their own projects,
  administrators see all of them.
* Read/update/delete enforce authorization BEFORE confirming existence:
  non-owner, non-admin callers always get 403 (whether or not the project
  exists); only true owners or admins can get 404.
* Administrator mutations are audited (owner or override).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_project_or_403
from app.core.audit import record_audit
from app.core.pagination import paginate, pagination_params
from app.db.session import get_db
from app.models.project import Project
from app.models.user import User
from app.schemas.common import Page
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post(
    "",
    response_model=ProjectRead,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Project:
    project = Project(
        name=payload.name,
        description=payload.description,
        owner_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    if user.is_admin:
        record_audit(
            db,
            user,
            action="project.create",
            resource_type="project",
            resource_id=project.id,
            detail={"name": project.name, "description": project.description},
        )
        db.commit()
    return project


@router.get("", response_model=Page[ProjectRead])
def list_projects(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Page[ProjectRead]:
    """Paginated project list.

    Regular users only ever see projects they own; administrators see all
    projects. ``limit`` is server-capped at 100 and defaults to 20;
    out-of-range offsets return an empty page (200).
    """
    limit, offset = pagination
    stmt = select(Project).order_by(Project.id.asc())
    if not user.is_admin:
        stmt = stmt.where(Project.owner_id == user.id)
    items, total = paginate(db, stmt, limit=limit, offset=offset)
    return Page[ProjectRead](items=items, total=total, limit=limit, offset=offset)


@router.get("/{project_id}", response_model=ProjectRead)
def read_project(
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Project:
    return get_project_or_403(db, project_id, user)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: int,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Project:
    project = get_project_or_403(db, project_id, user)

    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description

    if user.is_admin:
        record_audit(
            db,
            user,
            action="project.update",
            resource_type="project",
            resource_id=project.id,
            detail={
                "name": project.name,
                "description": project.description,
                "owner_id": project.owner_id,
                "admin_override": project.owner_id != user.id,
            },
        )

    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> None:
    project = get_project_or_403(db, project_id, user)

    if user.is_admin:
        record_audit(
            db,
            user,
            action="project.delete",
            resource_type="project",
            resource_id=project.id,
            detail={
                "name": project.name,
                "owner_id": project.owner_id,
                "admin_override": project.owner_id != user.id,
            },
        )

    db.delete(project)
    db.commit()
