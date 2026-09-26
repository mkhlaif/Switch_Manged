"""Read-only topology and role views.

The topology is assembled from data the platform already holds — inventory topology roles,
declared uplink ports and the LLDP neighbors recorded by earlier searches/port queries. Viewing
it never connects to a switch. Links carry the time they were observed, because LLDP data from
an old search may be stale.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.permissions import PERMISSION_DESCRIPTIONS, ROLE_PERMISSIONS, Permission
from app.db.session import get_db
from app.models import MacSearchResult, Role, Switch, User

router = APIRouter(prefix="/api", tags=["topology"])

ROLE_ORDER = {"core": 0, "distribution": 1, "access": 2, "unknown": 3}


@router.get("/topology")
async def topology(_: User = Depends(require(Permission.VIEW_INVENTORY)),
                   db: AsyncSession = Depends(get_db)) -> dict:
    switches = (await db.execute(select(Switch).order_by(Switch.name))).scalars().all()
    by_key: dict[str, Switch] = {}
    for sw in switches:
        by_key[sw.name.lower()] = sw
        if sw.host:
            by_key[sw.host.lower()] = sw

    # Most recent LLDP evidence per (switch, port).
    rows = (await db.execute(
        select(MacSearchResult).where(MacSearchResult.status == "found",
                                      MacSearchResult.port != "")
        .order_by(MacSearchResult.created_at.desc()).limit(5000)
    )).scalars().all()
    seen: set[tuple[str, str]] = set()
    links: dict[tuple[str, ...], dict] = {}
    for r in rows:
        key = (r.switch_name, r.port)
        if key in seen:
            continue
        seen.add(key)
        for n in r.lldp or []:
            peer = None
            for candidate in (n.get("system_name"), n.get("management_ip")):
                if candidate and str(candidate).lower() in by_key:
                    peer = by_key[str(candidate).lower()]
                    break
            if peer is None or peer.name == r.switch_name:
                continue
            ends = tuple(sorted([(r.switch_name, r.port), (peer.name, n.get("port_id") or "")]))
            pair = (ends[0][0], ends[1][0], r.port)
            links.setdefault(pair, {
                "a": r.switch_name, "a_port": r.port,
                "b": peer.name, "b_port": n.get("port_id") or n.get("port_description") or "",
                "observed_at": r.created_at.isoformat(), "source": "lldp",
            })
    nodes = [{
        "id": s.id, "name": s.name, "role": s.role or "unknown", "model": s.model,
        "aos_version": s.aos_version, "status": s.status, "enabled": s.enabled,
        "location": s.location, "uplink_ports": list(s.uplink_ports or []),
    } for s in sorted(switches, key=lambda s: (ROLE_ORDER.get(s.role or "unknown", 9), s.name))]
    return {"nodes": nodes, "links": sorted(links.values(), key=lambda l: (l["a"], l["a_port"])),
            "note": "Links come from LLDP data recorded by earlier searches and port queries; "
                    "no command is sent to build this view."}


@router.get("/roles")
async def roles(_: User = Depends(require(Permission.MANAGE_USERS))) -> dict:
    """The fixed role → permission matrix (read-only; defined in code, enforced per route)."""
    return {
        "roles": [{"role": r.value, "permissions": sorted(p.value for p in ROLE_PERMISSIONS[r])}
                  for r in (Role.MAC_OPERATOR, Role.READONLY, Role.OPERATOR, Role.ADMIN)],
        "permissions": [{"permission": p.value, "description": PERMISSION_DESCRIPTIONS[p]}
                        for p in Permission],
    }
