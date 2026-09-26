"""Automatic device discovery: registry, background jobs, per-switch discovery and acceptance.

Discovery only ever runs the registry's read-only discovery command through the Command
Safety Firewall. Administrators start it (and it starts automatically after a switch is
created, imported or its host key is trusted); nobody types a model or an AOS version.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.models import ACTIVE_DISCOVERY_STATUSES, DiscoveryJob, Switch, User
from app.schemas.common import DiscoveryJobCreate
from app.services.audit.service import record
from app.services.discovery import service as discovery
from app.services.discovery.registry import DISCOVERY_PROFILES

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.get("/registry")
async def discovery_registry(_: User = Depends(require(Permission.VIEW_SAFETY))) -> dict:
    """The Discovery Profile Registry: the only commands used to identify a device."""
    return {"profiles": [p.to_dict() for p in DISCOVERY_PROFILES]}


@router.post("/jobs", status_code=202)
async def start_job(body: DiscoveryJobCreate, request: Request,
                    admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                    db: AsyncSession = Depends(get_db)) -> dict:
    limiter.hit(f"discovery-job:{admin.id}", limit=10, window_seconds=60)
    if body.all_enabled == bool(body.switch_ids):
        raise ValidationFailedError("Give either switch_ids or all_enabled=true.")
    query = select(Switch.id)
    query = query.where(Switch.enabled.is_(True)) if body.all_enabled else \
        query.where(Switch.id.in_(body.switch_ids))
    ids = list((await db.execute(query)).scalars())
    if not ids:
        raise NotFoundError("No matching switches.")
    running = (await db.execute(select(DiscoveryJob.id).where(
        DiscoveryJob.status.in_(ACTIVE_DISCOVERY_STATUSES)).limit(1))).scalar_one_or_none()
    if running:
        raise ConflictError("A discovery job is already running. Wait for it to finish or "
                            "cancel it.", code="DISCOVERY_RUNNING")
    job = await discovery.create_job(db, admin, ids, source="manual")
    return discovery.job_view(job)


@router.get("/jobs")
async def list_jobs(_: User = Depends(require(Permission.VIEW_INVENTORY)),
                    db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (await db.execute(select(DiscoveryJob).order_by(
        DiscoveryJob.created_at.desc()).limit(20))).scalars().all()
    return [discovery.job_view(j) for j in rows]


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, _: User = Depends(require(Permission.VIEW_INVENTORY)),
                  db: AsyncSession = Depends(get_db)) -> dict:
    job = await db.get(DiscoveryJob, job_id)
    if job is None:
        raise NotFoundError("Discovery job not found.")
    return discovery.job_view(job)


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, request: Request,
                     admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                     db: AsyncSession = Depends(get_db)) -> dict:
    job = await db.get(DiscoveryJob, job_id)
    if job is None:
        raise NotFoundError("Discovery job not found.")
    if job.status not in ACTIVE_DISCOVERY_STATUSES:
        raise ConflictError(f"The job is {job.status}; nothing to cancel.")
    job.cancel_requested = True
    await db.commit()
    await record(db, action="DISCOVERY_JOB_CANCEL", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="discovery_job", target_id=job.id,
                 message="Cancellation requested (switches already running finish first)")
    return discovery.job_view(job)
