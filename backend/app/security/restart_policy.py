"""Port-restart safety policy (part of the Command Safety Firewall; enforced server-side).

Whether state changes are enabled AT ALL is decided by the operation mode / kill switch /
SAFE MODE (security/state.py). This module decides, per port, whether a restart may be planned:

| Port / switch                                   | MAC_OPERATOR | OPERATOR       | ADMIN                        |
|-------------------------------------------------|--------------|----------------|------------------------------|
| ACCESS                                          | yes (button) | "RESTART PORT <port>" | "RESTART PORT <port>" |
| LIKELY_ACCESS                                   | NO           | phrase + warning | phrase + warning          |
| UNKNOWN (uncertain classification)              | NO           | NO             | NO (fail closed)             |
| TRUNK / LIKELY_TRUNK, core/distribution switch  | NO           | NO             | EMERGENCY mode only: HIGH RISK + 2 phrases |
| declared uplink / link aggregate                | NO           | NO             | NO (hard block)              |

Restart is never automatic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.user import Role
from app.services.classification.engine import PortClass

PHRASE_TRUNK = "I UNDERSTAND THIS IS A TRUNK"
INFRASTRUCTURE_ROLES = {"core", "distribution"}

BLOCKED_TRUNK = ("PORT RESTART BLOCKED. This port appears to be a trunk/uplink. "
                 "No command was executed.")


def restart_phrase(port: str) -> str:
    return f"RESTART PORT {port}"


@dataclass
class RestartPolicy:
    allowed: bool
    risk_level: str  # normal | elevated | high | blocked
    required_phrases: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    trunk_override: bool = False

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "risk_level": self.risk_level,
            "required_phrases": self.required_phrases,
            "warnings": self.warnings,
            "blocked_reason": self.blocked_reason,
            "trunk_override": self.trunk_override,
        }


def evaluate_restart_policy(
    *,
    category: PortClass,
    role: Role,
    port: str,
    declared_uplink: bool,
    is_linkagg: bool,
    mode: str,
    operator_classes: set[str],
    switch_role: str = "",
    confidence: str = "",
    mac_count: int | None = None,
) -> RestartPolicy:
    def blocked(reason: str) -> RestartPolicy:
        return RestartPolicy(False, "blocked", blocked_reason=reason)

    role = Role(role)
    if role is Role.READONLY:
        return blocked("Read-only users cannot restart ports. No command was executed.")
    if declared_uplink:
        return blocked("PORT RESTART BLOCKED. This port is declared as an uplink in the switch "
                       "inventory; uplinks can never be restarted. No command was executed.")
    if is_linkagg:
        return blocked("PORT RESTART BLOCKED. The MAC is learned on a link aggregate. No command "
                       "was executed.")
    if category is PortClass.UNKNOWN:
        return blocked("PORT RESTART BLOCKED. The port classification is uncertain (UNKNOWN); a "
                       "state-changing command is never sent to a port that cannot be "
                       "classified. No command was executed.")

    warnings: list[str] = ["This operation will temporarily disconnect the device."]
    if mac_count and mac_count > 1:
        warnings.append(f"{mac_count} MAC addresses are learned on this port; all of those "
                        "devices will be disconnected.")
    phrase = restart_phrase(port)
    infrastructure = (switch_role or "").lower() in INFRASTRUCTURE_ROLES
    trunkish = category in (PortClass.LIKELY_TRUNK, PortClass.TRUNK)

    if trunkish or infrastructure:
        what = "a TRUNK / UPLINK" if trunkish else f"on a {switch_role.upper()} switch"
        if role is not Role.ADMIN or mode != "EMERGENCY":
            if trunkish:
                return blocked(BLOCKED_TRUNK)
            return blocked(f"PORT RESTART BLOCKED. The port is on a {switch_role} switch "
                           "(infrastructure). No command was executed.")
        return RestartPolicy(
            True, "high", [PHRASE_TRUNK, phrase],
            [f"HIGH RISK: this port is {what}. Restarting it may disconnect multiple devices or "
             "an entire network segment. EMERGENCY mode administrator override."] + warnings,
            trunk_override=True,
        )

    if role is Role.MAC_OPERATOR:
        # Non-technical flow: only confidently classified access/endpoint ports.
        if category is not PortClass.ACCESS or confidence not in {"High", "Medium"}:
            return blocked("RESTART BLOCKED for the simplified flow: the port is not a "
                           "confidently classified access port.")
        return RestartPolicy(True, "normal", [], warnings)

    if role is Role.OPERATOR and category.value not in operator_classes:
        return blocked(f"Operators may not restart {category.value} ports (see settings). No "
                       "command was executed.")

    if category is PortClass.LIKELY_ACCESS:
        return RestartPolicy(
            True, "elevated", [phrase],
            ["The port is probably an access port, but not all evidence agrees. Review the "
             "classification reasons."] + warnings,
        )
    return RestartPolicy(True, "normal", [phrase], warnings)


def check_phrases(required: list[str], provided: list[str]) -> bool:
    """Exact (case-sensitive, whitespace-trimmed) match of every required phrase, in order."""
    cleaned = [p.strip() for p in provided]
    return cleaned == list(required)
