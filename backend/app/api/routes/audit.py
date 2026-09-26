from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.csv_safe import csv_row
from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.api.deps import require
from app.db.session import get_db
from app.models import AuditLog, User
from app.schemas.common import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _query(action: str | None, user: str | None, result: str | None, since: datetime | None,
           until: datetime | None, q: str | None, severity: str | None = None):
    query = select(AuditLog)
    if severity:
        query = query.where(AuditLog.severity == severity.upper())
    if action:
        query = query.where(AuditLog.action == action)
    if user:
        query = query.where(AuditLog.username == user.lower())
    if result:
        query = query.where(AuditLog.result == result.upper())
    if since:
        query = query.where(AuditLog.ts >= since)
    if until:
        query = query.where(AuditLog.ts <= until)
    if q:
        like = f"%{q}%"
        query = query.where(AuditLog.message.ilike(like) | AuditLog.switch_name.ilike(like) |
                            AuditLog.port.ilike(like) | AuditLog.mac.ilike(like.replace(":", "")))
    return query


@router.get("")
async def list_audit(action: str | None = None, user: str | None = None,
                     result: str | None = None, since: datetime | None = None,
                     until: datetime | None = None, q: str | None = None,
                     severity: str | None = None,
                     limit: int = Query(default=100, ge=1, le=1000),
                     offset: int = Query(default=0, ge=0),
                     _: User = Depends(require(Permission.VIEW_AUDIT)), db: AsyncSession = Depends(get_db)) -> dict:
    query = _query(action, user, result, since, until, q, severity)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(AuditLog.ts.desc(), AuditLog.id.desc())
                             .limit(limit).offset(offset))).scalars().all()
    actions = (await db.execute(select(AuditLog.action).distinct())).scalars().all()
    return {"total": total, "actions": sorted(actions),
            "items": [AuditOut.model_validate(r).model_dump(mode="json") for r in rows]}


@router.get("/export")
async def export_audit(action: str | None = None, user: str | None = None,
                       result: str | None = None, since: datetime | None = None,
                       until: datetime | None = None, q: str | None = None,
                       severity: str | None = None,
                       viewer: User = Depends(require(Permission.VIEW_AUDIT)), db: AsyncSession = Depends(get_db)):
    limiter.hit(f"audit-export:{viewer.id}", limit=5, window_seconds=60)
    rows = (await db.execute(_query(action, user, result, since, until, q, severity)
                             .order_by(AuditLog.ts.desc()).limit(50000))).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["time", "user", "action", "result", "severity", "switch", "port", "mac",
                     "message", "ip", "details"])
    for r in rows:
        writer.writerow(csv_row([r.ts.isoformat(), r.username, r.action, r.result, r.severity,
                                 r.switch_name, r.port, r.mac, r.message, r.ip,
                                 json.dumps(r.details, default=str)]))
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=audit-log.csv"})
