"""Bulk switch import / export (administrators only; see services/inventory/bulk.py).

Registered before the ``/api/switches/{switch_id}`` routes so that ``/api/switches/import`` and
``/api/switches/export`` are never parsed as a switch id.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require
from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.models import ImportJob, ImportStatus, User
from app.schemas.common import ImportConfirm, ImportUpload
from app.services.audit.service import record
from app.services.inventory import bulk
from app.workers.tasks import spawn

router = APIRouter(prefix="/api/switches", tags=["switch import/export"])

_MEDIA = {"csv": "text/csv; charset=utf-8", "json": "application/json"}


def _download(content: str, fmt: str, stem: str) -> Response:
    # Server-generated file name only: nothing from the request ends up in a path or header.
    name = f"{stem}-{utcnow().strftime('%Y%m%d-%H%M%S')}.{fmt}"
    return Response(content=content, media_type=_MEDIA[fmt],
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/export")
async def export_switches(request: Request,
                          format: str = Query(default="csv", pattern=r"^(csv|json)$"),
                          user: User = Depends(require(Permission.EXPORT_SWITCHES)),
                          db: AsyncSession = Depends(get_db)) -> Response:
    limiter.hit(f"switch-export:{user.id}", limit=10, window_seconds=60)
    content, count = await bulk.export_switches(db, format)
    await record(db, action="SWITCH_EXPORT", result="SUCCESS", user=user,
                 ip=client_ip(request), target_type="inventory",
                 message=f"Switch inventory exported ({format.upper()}, {count} switches; no "
                         "credentials or keys)", details={"format": format, "count": count})
    return _download(content, format, "switches")


@router.get("/import/template")
async def import_template(format: str = Query(default="csv", pattern=r"^(csv|json)$"),
                          _: User = Depends(require(Permission.IMPORT_SWITCHES))) -> Response:
    return _download(bulk.TEMPLATE_CSV if format == "csv" else bulk.TEMPLATE_JSON, format,
                     "switch-import-template")


@router.post("/import/validate")
async def validate_import(body: ImportUpload, request: Request,
                          user: User = Depends(require(Permission.IMPORT_SWITCHES)),
                          db: AsyncSession = Depends(get_db)) -> dict:
    limiter.hit(f"switch-import:{user.id}", limit=10, window_seconds=60)
    job = await bulk.validate_upload(db, user, content=body.content, file_format=body.format,
                                     filename=body.filename, ip=client_ip(request))
    return bulk.job_view(job)


@router.get("/import")
async def list_imports(_: User = Depends(require(Permission.IMPORT_SWITCHES)),
                       db: AsyncSession = Depends(get_db)) -> list[dict]:
    jobs = (await db.execute(select(ImportJob).order_by(ImportJob.created_at.desc())
                             .limit(20))).scalars().all()
    return [bulk.job_view(j, include_rows=False) for j in jobs]


@router.get("/import/{job_id}")
async def get_import(job_id: str, rows: bool = Query(default=True),
                     _: User = Depends(require(Permission.IMPORT_SWITCHES)),
                     db: AsyncSession = Depends(get_db)) -> dict:
    """``rows=false`` while polling progress (the per-row details can be large)."""
    return bulk.job_view(await bulk.get_job(db, job_id), include_rows=rows)


@router.get("/import/{job_id}/report")
async def import_report(job_id: str, _: User = Depends(require(Permission.IMPORT_SWITCHES)),
                        db: AsyncSession = Depends(get_db)) -> Response:
    return _download(bulk.error_report_csv(await bulk.get_job(db, job_id)), "csv",
                     "switch-import-report")


@router.post("/import/{job_id}/confirm")
async def confirm_import(job_id: str, body: ImportConfirm, request: Request,
                         user: User = Depends(require(Permission.IMPORT_SWITCHES)),
                         db: AsyncSession = Depends(get_db)) -> dict:
    job = await bulk.confirm_import(db, user, job_id, on_existing=body.on_existing,
                                    skip_invalid=body.skip_invalid, ip=client_ip(request),
                                    mode=body.mode)
    if job.status == ImportStatus.QUEUED.value:
        spawn(bulk.run_import(job.id), name=f"switch-import-{job.id}")
    return bulk.job_view(job, include_rows=False)


@router.post("/import/{job_id}/cancel")
async def cancel_import(job_id: str, request: Request,
                        user: User = Depends(require(Permission.IMPORT_SWITCHES)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    job = await bulk.cancel_import(db, user, job_id, client_ip(request))
    return bulk.job_view(job, include_rows=False)
