"""Port-restart safety policy (part of the Command Safety Firewall; enforced server-side).

Whether state changes are enabled AT ALL is decided by the operation mode / kill switch /
SAFE MODE (security/state.py). This module decides, per port, whether a restart may be planned:

| Port / switch                                   | MAC_OPERATOR | OPERATOR       | ADMIN                        |
|-------------------------------------------------|--------------|----------------|------------------------------|
| ACCESS (High confidence, access switch, every endpoint check passes) | yes (simple confirmation, no approval) | "RESTART PORT <port>" | "RESTART PORT <port>" |
| ACCESS (Medium confidence / switch role not "access") | NO     | phrase         | phrase                       |
| LIKELY_ACCESS                                   | NO           | phrase + warning | phrase + warning          |
| UNKNOWN (uncertain classification)              | NO           | NO             | NO (fail closed)             |
| TRUNK / LIKELY_TRUNK, core/distribution switch  | NO           | NO             | EMERGENCY mode only: HIGH RISK + 2 phrases |
| declared uplink / link aggregate                | NO           | NO             | NO (hard block)              |

The MAC_OPERATOR needs no human approval; instead every restart must pass
:func:`endpoint_evidence_problems` (independent evidence that the port is a single endpoint
port) in addition to the policy, the Command Safety Firewall, locks and the safety modes.

Restart is never automatic.
"""

from __future__ import annotations

import re
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
        # Non-technical flow without human approval: only High-confidence ACCESS ports of
        # switches explicitly declared as access switches (fail closed on anything less).
        if category is not PortClass.ACCESS or confidence != "High":
            return blocked("RESTART BLOCKED for the simplified flow: the port is not an ACCESS "
                           "port classified with High confidence.")
        if (switch_role or "").lower() != "access":
            return blocked("RESTART BLOCKED for the simplified flow: the switch is not declared "
                           "as an access switch in the inventory (role "
                           f"'{switch_role or 'unknown'}').")
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


_INFRA_WORDS = re.compile(
    r"(?i)\b(uplink|up-link|trunk|core|distribution|dist|backbone|isl|lag|linkagg|"
    r"inter-?switch|mgmt|management|oob|stack|stacking|vfl|mclag|to[-_ ]?(?:sw|switch|core|dist))\b"
)
MAX_ENDPOINT_MACS = 3


def endpoint_evidence_problems(snapshot: dict, switch_role: str) -> list[str]:
    """Independent checks that a port is a single endpoint (access) port, from a snapshot taken
    on the switch moments before (see port_control.snapshot_data). Any problem blocks the
    MAC_OPERATOR restart; missing evidence counts as a problem (never guessed)."""
    problems: list[str] = []
    if (switch_role or "").lower() != "access":
        problems.append(f"switch role is '{switch_role or 'unknown'}', not 'access'")
    if not snapshot.get("mac_on_port"):
        problems.append("the MAC is not learned on the port")
    if snapshot.get("classification") != "ACCESS" or snapshot.get("confidence") != "High":
        problems.append(f"classification {snapshot.get('classification') or 'UNKNOWN'} "
                        f"({snapshot.get('confidence') or 'no'} confidence), not ACCESS/High")
    if snapshot.get("declared_uplink"):
        problems.append("the port is declared as an uplink")
    if not snapshot.get("vlans_known"):
        problems.append("VLAN membership could not be read")
    else:
        vlans = snapshot.get("vlans") or []
        tagged = [v for v in vlans if v.get("tagged") is True]
        untagged = [v for v in vlans if v.get("tagged") is False]
        if tagged:
            problems.append(f"the port carries {len(tagged)} tagged VLAN(s)")
        if len(untagged) != 1:
            problems.append(f"the port has {len(untagged)} untagged VLANs (expected exactly 1)")
        elif snapshot.get("mac_vlan") != untagged[0].get("vlan_id"):
            problems.append(f"the MAC is in VLAN {snapshot.get('mac_vlan')}, not in the port's "
                            f"access VLAN {untagged[0].get('vlan_id')}")
    if not snapshot.get("lldp_known"):
        problems.append("LLDP neighbours could not be read")
    mac_count = snapshot.get("mac_count")
    if mac_count is None:
        problems.append("the number of MACs on the port could not be read")
    elif mac_count > MAX_ENDPOINT_MACS:
        problems.append(f"{mac_count} MACs are learned on the port")
    if (snapshot.get("admin_status") or "").lower() != "enabled":
        problems.append(f"admin state is {snapshot.get('admin_status') or 'unknown'}")
    if (snapshot.get("oper_status") or "").lower() != "up":
        problems.append(f"operational state is {snapshot.get('oper_status') or 'unknown'}")
    if (snapshot.get("speed") or 0) >= 10000:
        problems.append(f"{snapshot.get('speed')} Mbit/s link (uplink speed)")
    alias = snapshot.get("alias") or ""
    if alias and _INFRA_WORDS.search(alias):
        problems.append(f"port description '{alias}' indicates infrastructure")
    return problems


def check_phrases(required: list[str], provided: list[str]) -> bool:
    """Exact (case-sensitive, whitespace-trimmed) match of every required phrase, in order."""
    cleaned = [p.strip() for p in provided]
    return cleaned == list(required)
