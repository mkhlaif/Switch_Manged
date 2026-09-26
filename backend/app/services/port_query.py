"""Live, read-only port queries (GET_PORT_VLAN / GET_PORT_STATUS / GET_LLDP / GET_PORT_MACS).

Parameters are validated strictly BEFORE any SSH connection is opened; rejected values are
recorded as security events. All commands go through the Command Safety Firewall.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFoundError, ValidationFailedError
from app.models import Switch, User
from app.parsers.alcatel.mac_table import MacEntry
from app.security.firewall import CommandBlocked, ExecutionContext
from app.security.policy import Operation
from app.security.validators import (
    MacAddressValidator,
    ParameterRejected,
    PortValidator,
    SwitchIdValidator,
)
from app.services.alcatel.adapter import AlcatelAdapter
from app.services.alcatel.investigation import investigate
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record
from app.services.inventory import service as inventory
from app.services.ssh.errors import SwitchError
from app.services.ssh.manager import get_connector

PORT_OPERATIONS = {Operation.GET_PORT_VLAN, Operation.GET_PORT_STATUS, Operation.GET_LLDP,
                   Operation.GET_PORT_MACS}


async def reject(db: AsyncSession, user: User, ip: str, operation: str, exc: ParameterRejected,
                 switch_name: str = "") -> None:
    high = exc.severity.value in {"HIGH", "CRITICAL"}
    await record(db, action="INJECTION_ATTEMPT" if high else "INVALID_PARAMETER",
                 result="BLOCKED", severity=exc.severity.value, user=user, ip=ip,
                 switch_name=switch_name, message=f"{operation} blocked: invalid {exc.parameter}",
                 details={"operation": operation, "parameter": exc.parameter,
                          "value": exc.value_preview, "commands_executed": 0})
    raise ValidationFailedError(f"COMMAND BLOCKED BY SAFETY POLICY. Invalid parameter "
                                f"'{exc.parameter}': {exc.reason}. No command was executed.",
                                code="COMMAND_BLOCKED")


async def query_port(db: AsyncSession, user: User, *, switch_id: object, port: object,
                     mac: object | None, ip: str, operations: set[Operation] | None = None,
                     ) -> dict:
    """Run the requested read-only port operations (all of them when ``operations`` is None,
    plus classification)."""
    label = ",".join(sorted(o.value for o in operations)) if operations else "PORT_QUERY"
    try:
        sid = SwitchIdValidator.validate(switch_id)
    except ParameterRejected as exc:
        await reject(db, user, ip, label, exc)
    sw = await db.get(Switch, sid)
    if sw is None:
        raise NotFoundError("Switch not found.")
    profile, reason = select_profile(await load_profiles(db), sw)
    if profile is None:
        raise AppError(f"{reason} Model: {sw.model or 'unknown'}, AOS: "
                       f"{sw.aos_version or 'unknown'}. No command was executed.",
                       title="COMMAND PROFILE UNAVAILABLE", code="NO_PROFILE")
    try:
        canonical_port = PortValidator.validate(port, profile.family)
        normalized = MacAddressValidator.validate(mac) if mac else None
    except ParameterRejected as exc:
        await reject(db, user, ip, label, exc, switch_name=sw.name)

    full = operations is None
    ops = PORT_OPERATIONS if full else operations
    known = await inventory.known_switches(db)
    target = await inventory.build_target(db, sw)
    ctx = ExecutionContext.for_user(user, "PORT_QUERY", ip, reference=f"{sw.name} {canonical_port}")
    out: dict = {
        "switch": {"id": sw.id, "name": sw.name, "model": sw.model, "aos_version": sw.aos_version,
                   "role": sw.role},
        "port": canonical_port,
        "profile": profile.key,
        "operations": sorted(o.value for o in ops),
        "mac": normalized,
        "mac_on_port": None,
    }
    try:
        async with get_connector().session(target, ctx) as fs:
            await fs.bind_profile(profile, model=sw.model, version=sw.aos_version)
            adapter = AlcatelAdapter(fs)
            if normalized:
                entries, _ = await adapter.find_mac(normalized)
                out["mac_on_port"] = any(e.port == canonical_port for e in entries)
            if full:
                entry = MacEntry(mac=normalized or "", vlan_id=None, domain="VLAN", service=None,
                                 mac_type="", operation=None, interface_raw=canonical_port,
                                 port=canonical_port, linkagg_id=None)
                inv = await investigate(adapter, entry, uplink_ports=sw.uplink_ports or [],
                                        switch_role=sw.role or "",
                                        known_switches=known - {sw.name.lower(),
                                                                sw.host.lower()})
                c = inv.classification
                out.update({
                    "details": inv.detail.to_dict() if inv.detail else None,
                    "vlans": inv.vlans_as_dicts(),
                    "tagged_vlans": inv.tagged_vlans,
                    "untagged_vlan": inv.untagged_vlan,
                    "lldp": inv.lldp_as_dicts(),
                    "mac_count": inv.mac_count,
                    "classification": c.to_dict() if c else None,
                    "warnings": inv.warnings,
                })
            else:
                if Operation.GET_PORT_VLAN in ops:
                    out["vlans"] = [v.to_dict() for v in await adapter.vlans_for_port(
                        canonical_port)]
                if Operation.GET_PORT_STATUS in ops:
                    out["details"] = (await adapter.port_detail(canonical_port)).to_dict()
                if Operation.GET_LLDP in ops:
                    out["lldp"] = [n.to_dict() for n in await adapter.lldp_neighbors(
                        canonical_port)]
                if Operation.GET_PORT_MACS in ops:
                    entries = await adapter.port_macs(canonical_port)
                    out["macs"] = [e.to_dict() for e in entries]
                    out["mac_count"] = len({(e.mac, e.vlan_id) for e in entries if e.valid})
            out["commands"] = fs.executed_commands()
    except CommandBlocked as exc:
        raise AppError(exc.reason, title=exc.title, code="COMMAND_BLOCKED",
                       status_code=403) from exc
    except SwitchError as exc:
        raise AppError(exc.reason, title=exc.title, code=exc.status.upper(),
                       action="Retry", status_code=502) from exc
    return out
