"""Network safety: firewall status, operation modes, kill switch, circuit breaker, locks, SSH
session records and safety events.

Every change of the safety state is written twice: as a ``safety_events`` row (the safety
timeline) and as an append-only audit entry.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require
from app.core.config import get_settings
from app.core.errors import PermissionDeniedError
from app.core.permissions import Permission
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.models import OperationLock, SafetyEvent, SshSessionRecord, User
from app.schemas.common import BreakerReset, KillSwitchRequest, ModeChange
from app.security.circuit_breaker import get_breaker
from app.security.firewall import get_firewall
from app.security.policy import policy_snapshot
from app.security.recorder import AlertItem, get_recorder
from app.services import system_settings
from app.services.audit.service import record

router = APIRouter(prefix="/api", tags=["safety"])


async def _status() -> dict:
    firewall = get_firewall()
    state = await firewall.safety_state()
    return {
        "firewall": firewall.status(),
        "state": state.to_dict(),
        "indicator": state.indicator,
        "breaker": get_breaker().counters(),
        "env_read_only_mode": get_settings().read_only_mode,
    }


@router.get("/safety")
async def safety_status(_: User = Depends(require(Permission.VIEW_SAFETY))) -> dict:
    return {**await _status(), "policy": policy_snapshot()}


async def _event(db: AsyncSession, kind: str, user: User, old: str, new: str, reason: str,
                 details: dict | None = None) -> None:
    db.add(SafetyEvent(kind=kind, username=user.username, old_value=old[:64],
                       new_value=new[:64], reason=reason, details=details or {}))


@router.post("/safety/mode")
async def change_mode(body: ModeChange, request: Request,
                      admin: User = Depends(require(Permission.MANAGE_SAFETY)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    old = str(await system_settings.get_value(db, "operation_mode"))
    await system_settings.set_value(db, "operation_mode", body.mode, admin.username)
    await system_settings.set_value(db, "mode_reason", body.reason[:200], admin.username)
    await _event(db, "MODE_CHANGE", admin, old, body.mode, body.reason)
    await db.commit()
    severity = "HIGH" if body.mode == "EMERGENCY" else "WARNING"
    await record(db, action="MODE_CHANGE", result="SUCCESS", severity=severity, user=admin,
                 ip=client_ip(request), target_type="safety", operation="MODE_CHANGE",
                 message=f"Operation mode {old} → {body.mode}: {body.reason}",
                 details={"from": old, "to": body.mode, "reason": body.reason,
                          "env_read_only_mode": get_settings().read_only_mode})
    if body.mode == "EMERGENCY":
        get_recorder().submit(AlertItem(
            kind="EMERGENCY_MODE", severity="HIGH", title="EMERGENCY mode enabled",
            message=f"{admin.username}: {body.reason}", dedupe_key="emergency-mode"))
    return await _status()


@router.post("/safety/kill-switch")
async def kill_switch(body: KillSwitchRequest, request: Request,
                      user: User = Depends(require(Permission.STOP_OPERATIONS)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Engage (operators and admins) or release (admins only) STOP ALL NETWORK OPERATIONS."""
    if not body.active and not user.has_permission(Permission.MANAGE_SAFETY):
        raise PermissionDeniedError("Only an administrator can release the kill switch.")
    was_enabled = bool(await system_settings.get_value(db, "network_command_execution"))
    await system_settings.set_value(db, "network_command_execution", not body.active,
                                    user.username)
    await _event(db, "KILL_SWITCH", user, "STOPPED" if not was_enabled else "RUNNING",
                 "STOPPED" if body.active else "RUNNING", body.reason)
    await db.commit()
    await record(db, action="KILL_SWITCH_ON" if body.active else "KILL_SWITCH_OFF",
                 result="SUCCESS", severity="CRITICAL" if body.active else "HIGH", user=user,
                 ip=client_ip(request), target_type="safety", operation="KILL_SWITCH",
                 message=("STOP ALL NETWORK OPERATIONS engaged" if body.active
                          else "STOP ALL NETWORK OPERATIONS released") + f": {body.reason}")
    if body.active:
        get_recorder().submit(AlertItem(
            kind="KILL_SWITCH", severity="CRITICAL", title="STOP ALL NETWORK OPERATIONS",
            message=f"Engaged by {user.username}: {body.reason}", dedupe_key="kill-switch"))
    return await _status()


@router.post("/safety/breaker/reset")
async def reset_breaker(body: BreakerReset, request: Request,
                        admin: User = Depends(require(Permission.MANAGE_SAFETY)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    values = await system_settings.get_all(db)
    old_reason = str(values.get("safe_mode_reason") or "")
    await system_settings.set_internal(db, "safe_mode", False, admin.username)
    await system_settings.set_internal(db, "safe_mode_reason", "", admin.username)
    await _event(db, "BREAKER_RESET", admin, "SAFE_MODE" if values.get("safe_mode") else "normal",
                 "normal", body.reason, {"previous_reason": old_reason,
                                         "counters": get_breaker().counters()})
    await db.commit()
    get_breaker().reset()
    await record(db, action="CIRCUIT_BREAKER_RESET", result="SUCCESS", severity="HIGH",
                 user=admin, ip=client_ip(request), target_type="safety",
                 operation="BREAKER_RESET",
                 message=f"SAFE MODE reset: {body.reason}",
                 details={"previous_reason": old_reason})
    return await _status()


@router.get("/safety/events")
async def safety_events(limit: int = Query(default=100, ge=1, le=500),
                        _: User = Depends(require(Permission.VIEW_SAFETY)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    rows = (await db.execute(select(SafetyEvent).order_by(SafetyEvent.id.desc())
                             .limit(limit))).scalars().all()
    return {"items": [{"id": r.id, "ts": r.ts.isoformat(), "kind": r.kind,
                       "username": r.username, "old_value": r.old_value,
                       "new_value": r.new_value, "reason": r.reason, "details": r.details}
                      for r in rows]}


@router.get("/safety/locks")
async def locks(_: User = Depends(require(Permission.VIEW_SAFETY)),
                db: AsyncSession = Depends(get_db)) -> dict:
    rows = (await db.execute(select(OperationLock).where(OperationLock.expires_at >= utcnow())
                             .order_by(OperationLock.acquired_at))).scalars().all()
    return {"items": [{"scope": r.scope, "switch_name": r.switch_name, "port": r.port,
                       "operation": r.operation, "locked_by": r.holder, "action_id": r.action_id,
                       "acquired_at": r.acquired_at.isoformat(),
                       "expires_at": r.expires_at.isoformat()} for r in rows]}


@router.get("/ssh-sessions")
async def ssh_sessions(switch: str | None = None, user: str | None = None,
                       result: str | None = None, since: datetime | None = None,
                       limit: int = Query(default=100, ge=1, le=500),
                       offset: int = Query(default=0, ge=0),
                       _: User = Depends(require(Permission.VIEW_AUDIT)),
                       db: AsyncSession = Depends(get_db)) -> dict:
    query = select(SshSessionRecord)
    if switch:
        query = query.where(SshSessionRecord.switch_name == switch)
    if user:
        query = query.where(SshSessionRecord.username == user.lower())
    if result:
        query = query.where(SshSessionRecord.result == result)
    if since:
        query = query.where(SshSessionRecord.started_at >= since)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(SshSessionRecord.started_at.desc())
                             .limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [{
        "id": r.id, "switch_id": r.switch_id, "switch_name": r.switch_name,
        "profile_key": r.profile_key, "username": r.username, "purpose": r.purpose,
        "reference": r.reference, "operations": r.operations,
        "started_at": r.started_at.isoformat(),
        "ended_at": r.ended_at.isoformat() if r.ended_at else None,
        "commands_attempted": r.commands_attempted, "commands_executed": r.commands_executed,
        "commands_blocked": r.commands_blocked, "result": r.result, "error": r.error,
        "commands": r.commands,
    } for r in rows]}
