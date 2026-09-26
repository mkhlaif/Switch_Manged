from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.errors import NotFoundError
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.models import PortAction, PortActionStatus, User
from app.schemas.common import ExecuteRestartRequest, PortActionOut, PrepareRestartRequest
from app.services.port_control.service import change_report, execute_restart, prepare_restart

router = APIRouter(prefix="/api/ports", tags=["ports"])


@router.post("/restart/prepare", response_model=PortActionOut)
async def prepare(body: PrepareRestartRequest, request: Request,
                  user: User = Depends(require(Permission.RESTART_PORT)), db: AsyncSession = Depends(get_db)):
    """Read-only re-check + safety evaluation. Returns a single-use plan; nothing is changed."""
    limiter.hit(f"restart-prepare:{user.id}", limit=10, window_seconds=60)
    return await prepare_restart(db, user, method=body.method,
                                 search_result_id=body.search_result_id,
                                 switch_id=body.switch_id, port=body.port, mac=body.mac,
                                 ip=client_ip(request))


@router.post("/restart", response_model=PortActionOut)
async def restart(body: ExecuteRestartRequest, request: Request,
                  user: User = Depends(require(Permission.RESTART_PORT)), db: AsyncSession = Depends(get_db)):
    """Execute a prepared plan after exact confirmation (dry run unless enabled and approved)."""
    limiter.hit(f"restart:{user.id}", limit=5, window_seconds=60)
    return await execute_restart(db, user, plan_token=body.plan_token,
                                 confirmations=body.confirmations, reason=body.reason,
                                 ip=client_ip(request))


@router.get("/actions")
async def list_actions(status: str | None = None, switch: str | None = None,
                       limit: int = Query(default=50, ge=1, le=500),
                       offset: int = Query(default=0, ge=0),
                       _: User = Depends(require(Permission.VIEW_PORT_ACTIONS)),
                       db: AsyncSession = Depends(get_db)) -> dict:
    query = select(PortAction)
    if status:
        query = query.where(PortAction.status == status)
    else:
        # Unconfirmed plans are noise in the history; show them only when asked for.
        query = query.where(PortAction.status != PortActionStatus.PLANNED.value)
    if switch:
        query = query.where(PortAction.switch_name == switch)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(PortAction.created_at.desc()).limit(limit)
                             .offset(offset))).scalars().all()
    return {"total": total,
            "items": [PortActionOut.model_validate(r).model_dump(mode="json") for r in rows]}


@router.get("/actions/{action_id}", response_model=PortActionOut)
async def get_action(action_id: int, _: User = Depends(require(Permission.VIEW_PORT_ACTIONS)),
                     db: AsyncSession = Depends(get_db)):
    action = await db.get(PortAction, action_id)
    if action is None:
        raise NotFoundError("Port action not found.")
    return action


@router.get("/actions/{action_id}/report")
async def get_change_report(action_id: int,
                            _: User = Depends(require(Permission.VIEW_PORT_ACTIONS)),
                            db: AsyncSession = Depends(get_db)) -> dict:
    """§54 change report: plan / before / after snapshots and their differences."""
    action = await db.get(PortAction, action_id)
    if action is None:
        raise NotFoundError("Port action not found.")
    return await change_report(db, action)
