"""Global network safety state: operation mode, kill switch and circuit-breaker SAFE MODE.

Operation modes (§26):

    NORMAL       read-only operations only (state-changing operations are not enabled)
    MAINTENANCE  authorized state-changing operations (safe ports, full safety checks)
    READ_ONLY    no state changes (forced by READ_ONLY_MODE=true; the initial deployment state)
    EMERGENCY    only administrator-approved emergency operations (e.g. trunk override)

Independent of the mode:

    Kill switch  "STOP ALL NETWORK OPERATIONS": every state-changing command blocked
                 (runtime setting; forced by NETWORK_COMMAND_EXECUTION=DISABLED)
    SAFE MODE    tripped by the circuit breaker; blocks state changes until an admin resets it

The state is loaded fresh before every state-changing step. If it cannot be read, the result is
fail-closed: everything state-changing is blocked.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass

from app.core.config import get_settings
from app.core.logging import get_logger, log_security
from app.models.user import Role

log = get_logger("security.state")


class OperationMode(str, enum.Enum):
    NORMAL = "NORMAL"
    MAINTENANCE = "MAINTENANCE"
    READ_ONLY = "READ_ONLY"
    EMERGENCY = "EMERGENCY"


@dataclass(frozen=True)
class SafetyState:
    available: bool
    mode: str                      # effective mode
    configured_mode: str
    mode_reason: str
    read_only_forced_by_env: bool
    command_execution_enabled: bool
    kill_switch_forced_by_env: bool
    safe_mode: bool
    safe_mode_reason: str
    dry_run_mode: bool
    unavailable_reason: str = ""

    def state_changing_block_reason(self, role: Role | str | None = None) -> str | None:
        """None when state-changing commands may be sent (for this role), else why not."""
        if not self.available:
            return (f"Safety state is unavailable ({self.unavailable_reason}); state-changing "
                    "commands are blocked (fail closed).")
        if not self.command_execution_enabled:
            src = " (forced by NETWORK_COMMAND_EXECUTION=DISABLED)" \
                if self.kill_switch_forced_by_env else ""
            return f"STOP ALL NETWORK OPERATIONS is active (kill switch){src}."
        if self.safe_mode:
            return (f"SAFE MODE is active (circuit breaker: {self.safe_mode_reason}). An "
                    "administrator must review and reset it.")
        if self.mode == OperationMode.READ_ONLY.value:
            src = "READ_ONLY_MODE environment setting" if self.read_only_forced_by_env \
                else "operation mode"
            return f"Operation mode is READ_ONLY ({src}): no state changes."
        if self.mode == OperationMode.NORMAL.value:
            return ("Operation mode is NORMAL (read-only operations). State-changing operations "
                    "require MAINTENANCE mode.")
        if self.mode == OperationMode.EMERGENCY.value and role is not None and \
                Role(role) is not Role.ADMIN:
            return "EMERGENCY mode: only administrator-approved operations are allowed."
        if self.mode not in {OperationMode.MAINTENANCE.value, OperationMode.EMERGENCY.value}:
            return f"Unknown operation mode {self.mode!r} (fail closed)."
        return None

    @property
    def indicator(self) -> str:
        if not self.available:
            return "SAFE MODE"
        if not self.command_execution_enabled:
            return "STOPPED"
        if self.safe_mode:
            return "SAFE MODE"
        if self.mode in {OperationMode.READ_ONLY.value, OperationMode.NORMAL.value}:
            return "READ ONLY"
        if self.mode == OperationMode.EMERGENCY.value:
            return "EMERGENCY"
        return "ACTIVE"

    @property
    def network_state(self) -> str:
        """Global network state (§19 vocabulary): EMERGENCY_STOP (kill switch), SAFE_MODE
        (circuit breaker, or safety state unavailable), READ_ONLY, NORMAL (read-only
        operations), MAINTENANCE (authorized state changes) — plus EMERGENCY_OVERRIDE for the
        administrator-only emergency mode."""
        if not self.available:
            return "SAFE_MODE"
        if not self.command_execution_enabled:
            return "EMERGENCY_STOP"
        if self.safe_mode:
            return "SAFE_MODE"
        return {OperationMode.READ_ONLY.value: "READ_ONLY",
                OperationMode.NORMAL.value: "NORMAL",
                OperationMode.MAINTENANCE.value: "MAINTENANCE",
                OperationMode.EMERGENCY.value: "EMERGENCY_OVERRIDE"}.get(self.mode, "SAFE_MODE")

    @property
    def state_changes_enabled(self) -> bool:
        return self.state_changing_block_reason() is None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state_changing_block_reason"] = self.state_changing_block_reason()
        data["network_state"] = self.network_state
        data["indicator"] = self.indicator
        data["state_changes_enabled"] = self.state_changes_enabled
        return data


def env_kill_switch() -> bool:
    """Fail closed: anything other than exactly ENABLED (typos, empty) engages the kill switch."""
    return get_settings().network_command_execution.strip().upper() != "ENABLED"


def locked_state(reason: str) -> SafetyState:
    return SafetyState(
        available=False, mode=OperationMode.READ_ONLY.value, configured_mode="",
        mode_reason="", read_only_forced_by_env=get_settings().read_only_mode,
        command_execution_enabled=False, kill_switch_forced_by_env=env_kill_switch(),
        safe_mode=True, safe_mode_reason=reason, dry_run_mode=True, unavailable_reason=reason,
    )


async def load_safety_state() -> SafetyState:
    from app.db.session import session_factory
    from app.services import system_settings

    settings = get_settings()
    try:
        async with session_factory()() as db:
            values = await system_settings.get_all(db)
        configured = str(values["operation_mode"])
        if configured not in OperationMode.__members__:
            configured = OperationMode.READ_ONLY.value  # corrupted value: fail closed
        effective = OperationMode.READ_ONLY.value if settings.read_only_mode else configured
        return SafetyState(
            available=True,
            mode=effective,
            configured_mode=configured,
            mode_reason=str(values.get("mode_reason") or "")[:200],
            read_only_forced_by_env=settings.read_only_mode,
            command_execution_enabled=(values["network_command_execution"] is True
                                       and not env_kill_switch()),
            kill_switch_forced_by_env=env_kill_switch(),
            safe_mode=values["safe_mode"] is not False,
            safe_mode_reason=str(values.get("safe_mode_reason") or "")[:300],
            dry_run_mode=values["dry_run_mode"] is not False,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on any problem
        log_security(log, "Safety state unavailable (%s): state-changing commands blocked",
                     exc.__class__.__name__)
        return locked_state(exc.__class__.__name__)
