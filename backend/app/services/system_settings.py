"""Runtime system settings stored in the ``system_settings`` table."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.models import SystemSetting


@dataclass(frozen=True)
class SettingDef:
    key: str
    kind: type
    description: str
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] | None = None


SETTING_DEFS: dict[str, SettingDef] = {
    d.key: d
    for d in (
        SettingDef("dry_run_mode", bool, "When on, port restarts only show the commands that "
                   "would be sent. NO commands are executed."),
        SettingDef("operator_restart_classes", list, "Port classifications operators may "
                   "restart.", choices=("ACCESS", "LIKELY_ACCESS")),
        SettingDef("port_bounce_hold_seconds", int, "Seconds between the down and up command.",
                   1, 60),
        SettingDef("post_restart_verify_seconds", int, "How long to wait for the port and MAC "
                   "to come back after a restart.", 10, 600),
        SettingDef("restart_plan_ttl_seconds", int, "How long a prepared restart plan stays "
                   "valid before it must be re-checked.", 30, 1800),
        SettingDef("search_include_lldp", bool, "Query LLDP on the port where a MAC is found."),
        SettingDef("search_include_mac_count", bool, "Count MACs learned on the port where a "
                   "MAC is found."),
        # --- Command Safety Firewall -----------------------------------------------------------
        SettingDef("network_command_execution", bool, "EMERGENCY KILL SWITCH. When disabled, "
                   "ALL state-changing commands are blocked immediately. Read-only operations "
                   "continue."),
        SettingDef("operation_mode", str, "Operation mode: NORMAL (read-only operations), "
                   "MAINTENANCE (authorized state changes), READ_ONLY (no state changes), "
                   "EMERGENCY (admin-approved emergency operations only).",
                   choices=("NORMAL", "MAINTENANCE", "READ_ONLY", "EMERGENCY")),
        SettingDef("mode_reason", str, "Reason for the current operation mode.", 0, 200),
        SettingDef("breaker_ssh_failures", int, "Circuit breaker: SSH failures on previously "
                   "healthy switches within the window before SAFE MODE.", 1, 100),
        SettingDef("breaker_auth_failures", int, "Circuit breaker: authentication failures on "
                   "previously healthy switches within the window.", 1, 100),
        SettingDef("breaker_validation_failures", int, "Circuit breaker: HIGH/CRITICAL command "
                   "validation failures within the window.", 1, 100),
        SettingDef("breaker_unexpected_output", int, "Circuit breaker: unexpected CLI responses "
                   "within the window.", 1, 100),
        SettingDef("breaker_window_minutes", int, "Circuit breaker counting window.", 1, 1440),
        SettingDef("require_lab_verification", bool, "Require an admin lab-verification record "
                   "(model family + AOS version) before profile commands run on real switches."),
        SettingDef("max_mac_searches_per_minute", int, "Maximum MAC searches per user per "
                   "minute.", 1, 1000),
        SettingDef("max_restarts_per_10_minutes", int, "Maximum live port restarts per user per "
                   "10 minutes.", 1, 50),
        SettingDef("min_port_restart_interval_seconds", int, "Minimum time between two live "
                   "restarts of the same switch port.", 0, 3600),
    )
}


def default_values() -> dict[str, Any]:
    return {
        "dry_run_mode": get_settings().default_dry_run,
        "operator_restart_classes": ["ACCESS", "LIKELY_ACCESS"],
        "port_bounce_hold_seconds": 5,
        "post_restart_verify_seconds": 90,
        "restart_plan_ttl_seconds": 300,
        "search_include_lldp": True,
        "search_include_mac_count": True,
        "network_command_execution": True,
        "operation_mode": "NORMAL",
        "mode_reason": "",
        "safe_mode": False,
        "safe_mode_reason": "",
        "breaker_ssh_failures": get_settings().circuit_breaker_threshold,
        "breaker_auth_failures": 3,
        "breaker_validation_failures": 3,
        "breaker_unexpected_output": 3,
        "breaker_window_minutes": 10,
        "require_lab_verification": True,
        "max_mac_searches_per_minute": 100,
        "max_restarts_per_10_minutes": 3,
        "min_port_restart_interval_seconds": 60,
    }


async def get_all(db: AsyncSession) -> dict[str, Any]:
    values = default_values()
    rows = (await db.execute(select(SystemSetting))).scalars().all()
    for row in rows:
        if row.key in SETTING_DEFS or row.key in INTERNAL_KEYS:
            values[row.key] = row.value.get("v")
    return values


# Keys written only by dedicated code paths (circuit breaker / admin reset), never via the
# generic settings API.
INTERNAL_KEYS = frozenset({"safe_mode", "safe_mode_reason"})

# Settings changed only through the audited safety endpoints (/api/safety/mode, kill-switch).
DEDICATED_KEYS = frozenset({"operation_mode", "mode_reason", "network_command_execution"})


async def set_internal(db: AsyncSession, key: str, value: Any, username: str) -> None:
    assert key in INTERNAL_KEYS
    row = await db.get(SystemSetting, key)
    if row is None:
        db.add(SystemSetting(key=key, value={"v": value}, updated_by=username))
    else:
        row.value = {"v": value}
        row.updated_by = username


async def get_value(db: AsyncSession, key: str) -> Any:
    row = await db.get(SystemSetting, key)
    return row.value.get("v") if row else default_values()[key]


def validate(key: str, value: Any) -> Any:
    d = SETTING_DEFS.get(key)
    if d is None:
        raise ValidationFailedError(f"Unknown setting '{key}'.")
    if d.kind is bool:
        if not isinstance(value, bool):
            raise ValidationFailedError(f"'{key}' must be true or false.")
    elif d.kind is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationFailedError(f"'{key}' must be an integer.")
        if (d.minimum is not None and value < d.minimum) or (
            d.maximum is not None and value > d.maximum
        ):
            raise ValidationFailedError(f"'{key}' must be between {d.minimum} and {d.maximum}.")
    elif d.kind is str and d.choices:
        if value not in d.choices:
            raise ValidationFailedError(f"'{key}' must be one of {list(d.choices)}.")
    elif d.kind is str:
        if not isinstance(value, str) or len(value) > (d.maximum or 200):
            raise ValidationFailedError(f"'{key}' must be text of at most {d.maximum} characters.")
        if any(ord(c) < 32 for c in value):
            raise ValidationFailedError(f"'{key}' must be a single line of text.")
    elif d.kind is list:
        if not isinstance(value, list) or any(v not in (d.choices or ()) for v in value):
            raise ValidationFailedError(f"'{key}' must be a list drawn from {list(d.choices or ())}.")
    return value


async def set_value(db: AsyncSession, key: str, value: Any, username: str) -> None:
    value = validate(key, value)
    row = await db.get(SystemSetting, key)
    if row is None:
        db.add(SystemSetting(key=key, value={"v": value}, updated_by=username))
    else:
        row.value = {"v": value}
        row.updated_by = username
