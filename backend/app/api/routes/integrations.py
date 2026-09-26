"""Read-only NetBox / Zabbix views and NetBox reconciliation (§18, §19).

Nothing here writes to NetBox or Zabbix. Mismatches are reported (and raised as alerts); a
human decides which side is wrong.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.errors import AppError, NotFoundError
from app.core.permissions import Permission
from app.db.session import get_db
from app.models import MacSearchResult, Switch, User
from app.security.recorder import AlertItem, get_recorder
from app.services.integrations.netbox import (
    IntegrationError,
    IntegrationNotConfigured,
    compare_device,
    compare_interface,
    get_netbox,
)
from app.services.integrations.zabbix import get_zabbix

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def _fail(exc: IntegrationError) -> AppError:
    if isinstance(exc, IntegrationNotConfigured):
        return AppError(exc.message, code="INTEGRATION_NOT_CONFIGURED", status_code=409,
                        title="Integration not configured")
    return AppError(exc.message, code="INTEGRATION_ERROR", status_code=502,
                    title="Integration unavailable")


@router.get("/status")
async def status(_: User = Depends(require(Permission.VIEW_INTEGRATIONS))) -> dict:
    out: dict = {}
    for name, factory, probe in (("netbox", get_netbox, lambda c: c.status()),
                                 ("zabbix", get_zabbix, lambda c: c.version())):
        try:
            client = factory()
        except IntegrationNotConfigured:
            out[name] = {"configured": False}
            continue
        try:
            out[name] = {"configured": True, "reachable": True, "info": await probe(client)}
        except IntegrationError as exc:
            out[name] = {"configured": True, "reachable": False, "error": exc.message}
    return out


async def _switch(db: AsyncSession, switch_id: int) -> Switch:
    sw = await db.get(Switch, switch_id)
    if sw is None:
        raise NotFoundError("Switch not found.")
    return sw


def _alert_mismatch(sw: Switch, mismatches: list[dict], port: str = "") -> None:
    if mismatches:
        get_recorder().submit(AlertItem(
            kind="NETBOX_MISMATCH", severity="INFO",
            title=f"NetBox mismatch: {sw.name}{' ' + port if port else ''}",
            message="; ".join(m["message"] for m in mismatches),
            switch_name=sw.name, port=port,
            dedupe_key=f"netbox:{sw.name}:{port}", details={"mismatches": mismatches}))


@router.get("/netbox/switches/{switch_id}")
async def netbox_switch(switch_id: int, _: User = Depends(require(Permission.VIEW_INTEGRATIONS)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    sw = await _switch(db, switch_id)
    try:
        device = await get_netbox().device(sw.name)
    except IntegrationError as exc:
        raise _fail(exc) from exc
    mismatches = compare_device(sw, device)
    _alert_mismatch(sw, mismatches)
    return {"switch": sw.name, "netbox": device, "mismatches": mismatches}


@router.get("/netbox/reconcile")
async def netbox_reconcile(_: User = Depends(require(Permission.VIEW_INTEGRATIONS)),
                           db: AsyncSession = Depends(get_db)) -> dict:
    try:
        client = get_netbox()
    except IntegrationError as exc:
        raise _fail(exc) from exc
    switches = (await db.execute(select(Switch).order_by(Switch.name))).scalars().all()
    sem = asyncio.Semaphore(5)

    async def one(sw: Switch) -> dict:
        async with sem:
            try:
                device = await client.device(sw.name)
            except IntegrationError as exc:
                return {"switch": sw.name, "error": exc.message, "mismatches": []}
        mismatches = compare_device(sw, device)
        _alert_mismatch(sw, mismatches)
        return {"switch": sw.name, "netbox_found": device is not None, "mismatches": mismatches}

    items = await asyncio.gather(*(one(sw) for sw in switches))
    return {"items": list(items),
            "total_mismatches": sum(len(i["mismatches"]) for i in items)}


@router.get("/netbox/results/{result_id}")
async def netbox_port(result_id: int, _: User = Depends(require(Permission.VIEW_INTEGRATIONS)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Compare the port of a MAC search result (live switch data) with NetBox."""
    row = await db.get(MacSearchResult, result_id)
    if row is None or not row.port:
        raise NotFoundError("Search result with a port not found.")
    sw = await _switch(db, row.switch_id) if row.switch_id else None
    try:
        nb = await get_netbox().interface(row.switch_name, row.port)
    except IntegrationError as exc:
        raise _fail(exc) from exc
    live = {"port": row.port, "untagged_vlan": row.untagged_vlan,
            "tagged_vlans": row.tagged_vlans or [],
            "admin_status": (row.port_details or {}).get("admin_status")}
    mismatches = compare_interface(live, nb)
    if sw is not None:
        _alert_mismatch(sw, mismatches, row.port)
    return {"switch": row.switch_name, "port": row.port, "live": live, "netbox": nb,
            "mismatches": mismatches}


@router.get("/zabbix/switches/{switch_id}")
async def zabbix_switch(switch_id: int, limit: int = Query(default=20, ge=1, le=100),
                        _: User = Depends(require(Permission.VIEW_INTEGRATIONS)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    sw = await _switch(db, switch_id)
    try:
        client = get_zabbix()
        host = await client.host(sw.name)
        problems = await client.problems(host["hostid"], limit) if host else []
    except IntegrationError as exc:
        raise _fail(exc) from exc
    return {"switch": sw.name, "host": host, "problems": problems}
