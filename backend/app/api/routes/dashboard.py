from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import require
from app.core.timeutil import start_of_utc_day
from app.db.session import get_db
from app.models import (
    MacSearch,
    MacSearchResult,
    PortAction,
    PortActionStatus,
    Switch,
    SwitchStatus,
    User,
)
from app.parsers.common import format_mac

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SSH_FAILURE_STATUSES = {"auth_failed", "hostkey_error", "connection_failed", "timeout"}


@router.get("")
async def dashboard(_: User = Depends(require(Permission.VIEW_DASHBOARD)), db: AsyncSession = Depends(get_db)) -> dict:
    today = start_of_utc_day()
    switches = (await db.execute(select(Switch).order_by(Switch.name))).scalars().all()
    online = sum(1 for s in switches if s.status == SwitchStatus.ONLINE.value)
    unknown = sum(1 for s in switches if s.status == SwitchStatus.UNKNOWN.value)
    versions: dict[str, int] = {}
    for s in switches:
        label = "Unknown" if not s.aos_version else ".".join(s.aos_version.split(".")[:2])
        versions[label] = versions.get(label, 0) + 1

    async def count(query) -> int:
        return (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()

    searches_today = await count(select(MacSearch).where(MacSearch.created_at >= today))
    found_today = await count(select(MacSearch).where(MacSearch.created_at >= today,
                                                      MacSearch.found_count > 0))
    # Connection-level failures only (a rejected command or missing profile is not an SSH failure).
    failed_ssh_today = await count(select(MacSearchResult).where(
        MacSearchResult.created_at >= today,
        MacSearchResult.status.in_(list(SSH_FAILURE_STATUSES)),
    ))
    actions_today = await count(select(PortAction).where(
        PortAction.created_at >= today, PortAction.status != PortActionStatus.PLANNED.value))

    recent_searches = (await db.execute(select(MacSearch).order_by(MacSearch.created_at.desc())
                                        .limit(8))).scalars().all()
    recent_actions = (await db.execute(
        select(PortAction).where(PortAction.status != PortActionStatus.PLANNED.value)
        .order_by(PortAction.created_at.desc()).limit(8))).scalars().all()

    return {
        "stats": {
            "total_switches": len(switches),
            "enabled_switches": sum(1 for s in switches if s.enabled),
            "online": online,
            "offline": len(switches) - online - unknown,
            "unknown": unknown,
            "aos_versions": dict(sorted(versions.items())),
            "searches_today": searches_today,
            "macs_found_today": found_today,
            "failed_ssh_today": failed_ssh_today,
            "port_actions_today": actions_today,
        },
        "recent_searches": [{
            "id": s.id, "mac": format_mac(s.mac), "user": s.requested_by, "status": s.status,
            "found": s.found_count, "created_at": s.created_at.isoformat(),
            "likely_edge": (s.summary or {}).get("likely_edge"),
        } for s in recent_searches],
        "recent_actions": [{
            "id": a.id, "switch_name": a.switch_name, "port": a.port, "mac": format_mac(a.mac),
            "status": a.status, "dry_run": a.dry_run, "user": a.requested_by,
            "created_at": a.created_at.isoformat(), "classification": a.classification,
        } for a in recent_actions],
        "connectivity": [{
            "id": s.id, "name": s.name, "host": s.host, "status": s.status,
            "enabled": s.enabled, "last_check_at": s.last_check_at.isoformat()
            if s.last_check_at else None, "last_error": s.last_error,
            "model": s.model, "aos_version": s.aos_version,
        } for s in switches],
    }
