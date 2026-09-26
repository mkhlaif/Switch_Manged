from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.db.session import get_db
from app.models import User
from app.schemas.common import SettingsUpdate
from app.services import system_settings
from app.services.audit.service import record

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _environment() -> dict:
    s = get_settings()
    return {
        "max_concurrent_switch_connections": s.max_concurrent_switch_connections,
        "ssh_connect_timeout": s.ssh_connect_timeout,
        "ssh_command_timeout": s.ssh_command_timeout,
        "ssh_connect_retries": s.ssh_connect_retries,
        "ssh_allow_unknown_host_keys": s.ssh_allow_unknown_host_keys,
        "enable_simulator": s.enable_simulator,
        "environment": s.environment,
        "read_only_mode": s.read_only_mode,
        "network_command_execution": s.network_command_execution,
        "ssh_max_session_seconds": s.ssh_max_session_seconds,
        "circuit_breaker_threshold": s.circuit_breaker_threshold,
        "netbox_configured": bool(s.netbox_url and s.netbox_token),
        "zabbix_configured": bool(s.zabbix_url and s.zabbix_token),
    }


@router.get("")
async def get_settings_values(_: User = Depends(require(Permission.VIEW_SETTINGS)),
                              db: AsyncSession = Depends(get_db)) -> dict:
    values = await system_settings.get_all(db)
    return {
        "values": values,
        "definitions": {
            k: {"type": d.kind.__name__, "description": d.description, "min": d.minimum,
                "max": d.maximum, "choices": list(d.choices or [])}
            for k, d in system_settings.SETTING_DEFS.items()
        },
        "environment": _environment(),
    }


@router.put("")
async def update_settings(body: SettingsUpdate, request: Request,
                          admin: User = Depends(require(Permission.MANAGE_SAFETY)),
                          db: AsyncSession = Depends(get_db)) -> dict:
    before = await system_settings.get_all(db)
    dedicated = set(body.values) & system_settings.DEDICATED_KEYS
    if dedicated:
        raise ValidationFailedError(
            f"{', '.join(sorted(dedicated))} can only be changed through the safety controls "
            "(operation mode / kill switch), which record a reason and a safety event.")
    for key, value in body.values.items():
        system_settings.validate(key, value)
    for key, value in body.values.items():
        await system_settings.set_value(db, key, value, admin.username)
    await db.commit()
    changed = {k: {"from": before.get(k), "to": v} for k, v in body.values.items()
               if before.get(k) != v}
    safety_keys = {"dry_run_mode", "operator_restart_classes", "require_lab_verification",
                   "breaker_ssh_failures", "breaker_auth_failures",
                   "breaker_validation_failures", "breaker_unexpected_output",
                   "breaker_window_minutes"}
    await record(db, action="SETTINGS_UPDATE", result="SUCCESS", user=admin,
                 severity="WARNING" if safety_keys & set(changed) else "INFO",
                 ip=client_ip(request), target_type="settings", details=changed,
                 message=", ".join(f"{k}={v['to']}" for k, v in changed.items()))
    return await get_settings_values(admin, db)
