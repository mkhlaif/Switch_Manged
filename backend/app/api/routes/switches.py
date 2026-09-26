from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.config import get_settings
from app.core.errors import AppError, ConflictError, NotFoundError, ValidationFailedError
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.models import Credential, Switch, User
from app.schemas.common import (
    DiscoveryAccept,
    SwitchCreate,
    SwitchOut,
    SwitchUpdate,
    TrustHostKeyRequest,
)
from app.security.firewall import ExecutionContext
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record
from app.services.discovery import service as discovery
from app.services.inventory import service as inventory
from app.services.port_query import query_port

router = APIRouter(prefix="/api/switches", tags=["switches"])


async def _out(db: AsyncSession, sw: Switch, profiles: dict | None = None) -> SwitchOut:
    profiles = profiles if profiles is not None else await load_profiles(db)
    profile, reason = select_profile(profiles, sw)
    out = SwitchOut.model_validate(sw)
    out.effective_profile = profile.key if profile else None
    out.profile_reason = reason
    out.host_key_trusted = bool(sw.host_key)
    if sw.credential_id:
        cred = await db.get(Credential, sw.credential_id)
        out.credential_name = cred.name if cred else None
    return out


async def _get(db: AsyncSession, switch_id: int) -> Switch:
    sw = await db.get(Switch, switch_id)
    if sw is None:
        raise NotFoundError("Switch not found.")
    return sw


# Changing any of these can make the device a different one: its identity must be rediscovered.
IDENTITY_FIELDS = {"host", "ssh_port", "transport"}
REDISCOVER_FIELDS = IDENTITY_FIELDS | {"credential_id", "expected_model", "expected_aos_version",
                                       "expected_host_key_fingerprint", "enabled"}


def _check_transport(transport: str | None) -> None:
    if transport == "simulator" and not get_settings().enable_simulator:
        raise ValidationFailedError("The simulator transport is only available in lab mode "
                                    "(ENABLE_SIMULATOR=true).")


async def _check_unique(db: AsyncSession, *, name: str, host: str, ssh_port: int,
                        hostname: str, exclude_id: int | None = None) -> None:
    """Friendly duplicate errors; the database constraints are the final guarantee."""
    others = select(Switch).where(Switch.id != exclude_id) if exclude_id else select(Switch)
    if (await db.execute(others.where(func.lower(Switch.name) == name.lower()))).scalars().first():
        raise ConflictError(f"A switch named '{name}' already exists.")
    same_address = (await db.execute(others.where(
        func.lower(Switch.host) == host.lower(), Switch.ssh_port == ssh_port))).scalars().first()
    if same_address:
        raise ConflictError(f"The management address {host}:{ssh_port} is already used by "
                            f"switch '{same_address.name}'.")
    if hostname:
        owner = (await db.execute(others.where(Switch.hostname == hostname))).scalars().first()
        if owner:
            raise ConflictError(f"The hostname '{hostname}' is already used by switch "
                                f"'{owner.name}'.")


async def _commit(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictError("The switch conflicts with another inventory entry (name, "
                            "management address or hostname).") from exc


@router.get("", response_model=list[SwitchOut])
async def list_switches(_: User = Depends(require(Permission.VIEW_INVENTORY)), db: AsyncSession = Depends(get_db)):
    profiles = await load_profiles(db)
    rows = (await db.execute(select(Switch).order_by(Switch.name))).scalars().all()
    return [await _out(db, s, profiles) for s in rows]


@router.get("/{switch_id}", response_model=SwitchOut)
async def get_switch(switch_id: int, _: User = Depends(require(Permission.VIEW_INVENTORY)),
                     db: AsyncSession = Depends(get_db)):
    return await _out(db, await _get(db, switch_id))


@router.post("", response_model=SwitchOut, status_code=201)
async def create_switch(body: SwitchCreate, request: Request, admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                        db: AsyncSession = Depends(get_db)):
    _check_transport(body.transport)
    await _check_unique(db, name=body.name, host=body.host, ssh_port=body.ssh_port,
                        hostname=body.hostname)
    if body.credential_id and await db.get(Credential, body.credential_id) is None:
        raise ValidationFailedError("Credential not found.")
    sw = Switch(**body.model_dump())
    db.add(sw)
    await _commit(db)
    await record(db, action="SWITCH_CREATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="switch", target_id=sw.id, target_label=sw.name,
                 switch_name=sw.name, site=sw.site, details=body.model_dump())
    if discovery.can_discover(sw):
        await discovery.create_job(db, admin, [sw.id], source="create")
    return await _out(db, sw)


@router.patch("/{switch_id}", response_model=SwitchOut)
async def update_switch(switch_id: int, body: SwitchUpdate, request: Request,
                        admin: User = Depends(require(Permission.MANAGE_INVENTORY)), db: AsyncSession = Depends(get_db)):
    sw = await _get(db, switch_id)
    changes = body.model_dump(exclude_unset=True)
    _check_transport(changes.get("transport"))
    if "credential_id" in changes and changes["credential_id"] and \
            await db.get(Credential, changes["credential_id"]) is None:
        raise ValidationFailedError("Credential not found.")
    await _check_unique(db, name=changes.get("name", sw.name), host=changes.get("host", sw.host),
                        ssh_port=changes.get("ssh_port", sw.ssh_port),
                        hostname=changes.get("hostname", sw.hostname), exclude_id=sw.id)
    if ("host" in changes and changes["host"] != sw.host) or (
            "ssh_port" in changes and changes["ssh_port"] != sw.ssh_port):
        # A different endpoint means a different host key; require re-enrollment.
        sw.host_key, sw.host_key_fingerprint = "", ""
        changes["host_key_cleared"] = True
    changed = {k for k, v in changes.items() if hasattr(sw, k) and getattr(sw, k) != v}
    if changed & IDENTITY_FIELDS:
        # Possibly another device: nothing may be changed on it until it is rediscovered.
        sw.discovery_status = "not_discovered"
        sw.discovery_error = "Management address or transport changed: rediscovery required."
        sw.discovery_category = ""
        changes["discovery_reset"] = True
    for key, value in changes.items():
        if hasattr(sw, key) and key not in {"host_key_cleared", "discovery_reset"}:
            setattr(sw, key, value)
    await _commit(db)
    await record(db, action="SWITCH_UPDATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="switch", target_id=sw.id, target_label=sw.name,
                 switch_name=sw.name, site=sw.site, details=changes)
    if changed & REDISCOVER_FIELDS and discovery.can_discover(sw):
        await discovery.create_job(db, admin, [sw.id], source="update")
    return await _out(db, sw)


@router.delete("/{switch_id}", status_code=204)
async def delete_switch(switch_id: int, request: Request, admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                        db: AsyncSession = Depends(get_db)):
    sw = await _get(db, switch_id)
    name = sw.name
    await db.delete(sw)
    await db.commit()
    await record(db, action="SWITCH_DELETE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="switch", target_id=switch_id, target_label=name, switch_name=name)


@router.post("/{switch_id}/test")
async def test_switch(switch_id: int, request: Request, user: User = Depends(require(Permission.TEST_SWITCH)),
                      db: AsyncSession = Depends(get_db)) -> dict:
    limiter.hit(f"switch-test:{user.id}", limit=30, window_seconds=60)
    sw = await _get(db, switch_id)
    ctx = ExecutionContext.for_user(user, "SWITCH_TEST", client_ip(request), reference=sw.name)
    result = await inventory.test_connection(db, sw, ctx)
    await record(db, action="SWITCH_TEST", result="SUCCESS" if result["ok"] else "FAILED",
                 user=user, ip=client_ip(request), target_type="switch", target_id=sw.id,
                 switch_name=sw.name, message=result.get("reason", "show system OK"))
    return result


@router.post("/{switch_id}/discover")
@router.post("/{switch_id}/detect")  # former name, kept for compatibility
async def discover_switch(switch_id: int, request: Request,
                          admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                          db: AsyncSession = Depends(get_db)) -> dict:
    """Identify the device now (read-only discovery command only) and store the result."""
    limiter.hit(f"switch-detect:{admin.id}", limit=20, window_seconds=60)
    sw = await _get(db, switch_id)
    ctx = ExecutionContext.for_user(admin, "DISCOVERY", client_ip(request), reference=sw.name)
    outcome = await discovery.discover_switch(db, sw, ctx, user=admin, source="manual")
    return outcome.to_dict()


@router.post("/{switch_id}/discovery/accept", response_model=SwitchOut)
async def accept_discovered_identity(switch_id: int, body: DiscoveryAccept, request: Request,
                                     admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                                     db: AsyncSession = Depends(get_db)):
    """An administrator confirms that a changed device identity (MISMATCH) is expected, e.g.
    after an AOS upgrade. The next restart re-verifies the identity again."""
    sw = await _get(db, switch_id)
    await discovery.accept_identity(db, sw, admin, body.reason, client_ip(request))
    return await _out(db, sw)


@router.post("/{switch_id}/host-key/fetch")
async def fetch_host_key(switch_id: int, admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                         db: AsyncSession = Depends(get_db)) -> dict:
    limiter.hit(f"hostkey-fetch:{admin.id}", limit=20, window_seconds=60)
    sw = await _get(db, switch_id)
    data = await inventory.fetch_host_key(sw)
    data["currently_trusted"] = sw.host_key_fingerprint or None
    data["matches_trusted"] = bool(sw.host_key_fingerprint) and \
        sw.host_key_fingerprint == data["fingerprint"]
    return data


@router.post("/{switch_id}/host-key/trust", response_model=SwitchOut)
async def trust_host_key(switch_id: int, body: TrustHostKeyRequest, request: Request,
                         admin: User = Depends(require(Permission.MANAGE_INVENTORY)), db: AsyncSession = Depends(get_db)):
    """The admin confirms the fingerprint they verified out-of-band (e.g. on the switch console
    with ``show ssh``/key files). The key is fetched again and stored only if it still matches."""
    sw = await _get(db, switch_id)
    data = await inventory.fetch_host_key(sw)
    if data["fingerprint"] != body.fingerprint.strip():
        await record(db, action="HOSTKEY_TRUST", result="DENIED", user=admin,
                     ip=client_ip(request), target_type="switch", target_id=sw.id,
                     switch_name=sw.name, message="Fingerprint mismatch on re-fetch")
        raise AppError("The switch now presents a different host key than the one you confirmed. "
                       "Nothing was stored.", title="HOST KEY CHANGED", code="HOSTKEY_MISMATCH")
    previous = sw.host_key_fingerprint
    sw.host_key, sw.host_key_fingerprint = data["host_key"], data["fingerprint"]
    await db.commit()
    await record(db, action="HOSTKEY_TRUST", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="switch", target_id=sw.id, switch_name=sw.name,
                 details={"fingerprint": data["fingerprint"], "previous": previous})
    if discovery.can_discover(sw):
        await discovery.create_job(db, admin, [sw.id], source="host-key-trust")
    return await _out(db, sw)


@router.delete("/{switch_id}/host-key", response_model=SwitchOut)
async def clear_host_key(switch_id: int, request: Request, admin: User = Depends(require(Permission.MANAGE_INVENTORY)),
                         db: AsyncSession = Depends(get_db)):
    sw = await _get(db, switch_id)
    previous = sw.host_key_fingerprint
    sw.host_key, sw.host_key_fingerprint = "", ""
    await db.commit()
    await record(db, action="HOSTKEY_CLEAR", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="switch", target_id=sw.id, switch_name=sw.name,
                 details={"previous": previous})
    return await _out(db, sw)


@router.get("/{switch_id}/ports/{port:path}")
async def port_info(switch_id: int, port: str, request: Request,
                    mac: str | None = Query(default=None),
                    user: User = Depends(require(Permission.PORT_INSPECT)),
                    db: AsyncSession = Depends(get_db)) -> dict:
    """Live, read-only view of one port: status, VLANs, LLDP, MAC count and classification.
    Every command goes through the Command Safety Firewall."""
    limiter.hit(f"port-info:{user.id}", limit=30, window_seconds=60)
    return await query_port(db, user, switch_id=switch_id, port=port, mac=mac,
                            ip=client_ip(request))
