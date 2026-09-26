"""Alerts (§40): multiple locations, MAC move, unexpected trunk, NetBox mismatch, SSH failures,
circuit breaker, blocked dangerous operations, failed restarts, MAC not returning, unexpected
CLI output. Alerts are informational: nothing acts on them automatically."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require
from app.core.errors import NotFoundError
from app.core.permissions import Permission
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.models import Alert, User
from app.services.audit.service import record

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _out(a: Alert) -> dict:
    return {"id": a.id, "kind": a.kind, "severity": a.severity, "title": a.title,
            "message": a.message, "switch_name": a.switch_name, "port": a.port, "mac": a.mac,
            "occurrences": a.occurrences, "details": a.details, "status": a.status,
            "created_at": a.created_at.isoformat(), "last_seen_at": a.last_seen_at.isoformat(),
            "acknowledged_by": a.acknowledged_by,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None}


@router.get("")
async def list_alerts(status: str | None = Query(default=None, pattern=r"^(open|acknowledged)$"),
                      severity: str | None = Query(default=None,
                                                   pattern=r"^(INFO|WARNING|HIGH|CRITICAL)$"),
                      kind: str | None = Query(default=None, max_length=40),
                      limit: int = Query(default=100, ge=1, le=500),
                      offset: int = Query(default=0, ge=0),
                      _: User = Depends(require(Permission.VIEW_ALERTS)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if kind:
        query = query.where(Alert.kind == kind)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(Alert.last_seen_at.desc()).limit(limit)
                             .offset(offset))).scalars().all()
    return {"total": total, "items": [_out(a) for a in rows]}


@router.get("/summary")
async def summary(_: User = Depends(require(Permission.VIEW_ALERTS)),
                  db: AsyncSession = Depends(get_db)) -> dict:
    rows = (await db.execute(select(Alert.severity, func.count()).where(Alert.status == "open")
                             .group_by(Alert.severity))).all()
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "WARNING", "INFO")}
    counts.update({sev: n for sev, n in rows})
    return {"open": sum(counts.values()), "by_severity": counts}


@router.post("/{alert_id}/ack")
async def acknowledge(alert_id: int, request: Request,
                      user: User = Depends(require(Permission.ACK_ALERTS)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise NotFoundError("Alert not found.")
    if alert.status != "acknowledged":
        alert.status = "acknowledged"
        alert.acknowledged_by = user.username
        alert.acknowledged_at = utcnow()
        await db.commit()
        await record(db, action="ALERT_ACK", result="SUCCESS", user=user, ip=client_ip(request),
                     target_type="alert", target_id=alert.id, message=alert.title)
    return _out(alert)
