"""THE authoritative command security policy.

Everything that decides *which* CLI text may ever reach an OmniSwitch lives in this one module:

* :data:`COMMAND_POLICIES` — the closed set of operations, their risk class, minimum role,
  permitted command keys and command-count budgets.
* :data:`COMMAND_ALLOWLIST` — for every command key, the exact template literals (verified AOS
  syntax, see docs/AOS_COMMAND_VERIFICATION.md) that a command profile may use.
* :data:`STRATEGY_TEMPLATES` — the only state-changing command pairs (port bounce) in existence.
* :data:`DISCOVERY_PROFILE` — the separately approved read-only discovery command.

Rule: NO COMMAND IN ALLOWLIST = COMMAND BLOCKED. Anything not expressible here cannot be sent.
All structures are immutable at runtime; changing them is a code change that must be reviewed.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from app.models.user import Role

POLICY_VERSION = "1.0.0"


class Risk(str, enum.Enum):
    READ_ONLY = "READ_ONLY"
    STATE_CHANGING = "STATE_CHANGING"
    DANGEROUS = "DANGEROUS"
    UNKNOWN = "UNKNOWN"


class Severity(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Operation(str, enum.Enum):
    DISCOVER_SYSTEM = "DISCOVER_SYSTEM"  # internal: separately approved discovery profile
    SEARCH_MAC = "SEARCH_MAC"
    GET_PORT_VLAN = "GET_PORT_VLAN"
    GET_PORT_STATUS = "GET_PORT_STATUS"
    GET_LLDP = "GET_LLDP"
    GET_PORT_MACS = "GET_PORT_MACS"
    RESTART_PORT = "RESTART_PORT"


@dataclass(frozen=True)
class CommandRule:
    key: str
    params: frozenset[str]
    max_per_invocation: int


@dataclass(frozen=True)
class OperationPolicy:
    operation: Operation
    risk: Risk
    allowed_roles: frozenset[Role]
    description: str
    commands: Mapping[str, CommandRule]
    max_commands: int
    uses_discovery_profile: bool = False
    api_requestable: bool = True
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "operation": self.operation.value,
            "risk": self.risk.value,
            "allowed_roles": sorted(r.value for r in self.allowed_roles),
            "description": self.description,
            "max_commands": self.max_commands,
            "uses_discovery_profile": self.uses_discovery_profile,
            "api_requestable": self.api_requestable,
            "notes": self.notes,
            "commands": {
                k: {"params": sorted(r.params), "max_per_invocation": r.max_per_invocation,
                    "allowed_templates": sorted(COMMAND_ALLOWLIST.get(k, ()))}
                for k, r in self.commands.items()
            },
        }


ALL_ROLES = frozenset(Role)
# RESTART_PORT: technical operators/admins, and MAC_OPERATOR through the simplified flow (which
# is further restricted by the restart policy: confident ACCESS ports only).
RESTART_ROLES = frozenset({Role.OPERATOR, Role.ADMIN, Role.MAC_OPERATOR})


def _rules(*rules: CommandRule) -> Mapping[str, CommandRule]:
    return MappingProxyType({r.key: r for r in rules})


def _rule(key: str, params: tuple[str, ...] = (), max_per_invocation: int = 1) -> CommandRule:
    return CommandRule(key, frozenset(params), max_per_invocation)


COMMAND_POLICIES: Mapping[Operation, OperationPolicy] = MappingProxyType({
    Operation.DISCOVER_SYSTEM: OperationPolicy(
        Operation.DISCOVER_SYSTEM, Risk.READ_ONLY, ALL_ROLES,
        "Identify model and AOS version (read-only discovery profile).",
        _rules(_rule("system_info")), max_commands=1, uses_discovery_profile=True,
        api_requestable=False,
    ),
    Operation.SEARCH_MAC: OperationPolicy(
        Operation.SEARCH_MAC, Risk.READ_ONLY, ALL_ROLES,
        "MAC-filtered lookup in the switch MAC table.",
        _rules(_rule("mac_lookup", ("mac",))), max_commands=1,
    ),
    Operation.GET_PORT_VLAN: OperationPolicy(
        Operation.GET_PORT_VLAN, Risk.READ_ONLY, ALL_ROLES,
        "VLAN membership of one port or link aggregate.",
        _rules(_rule("vlan_port", ("port",)), _rule("vlan_linkagg", ("agg",))), max_commands=1,
    ),
    Operation.GET_PORT_STATUS: OperationPolicy(
        Operation.GET_PORT_STATUS, Risk.READ_ONLY, ALL_ROLES,
        "Operational/admin status, speed, errors and description of one port.",
        _rules(_rule("port_detail", ("port",)), _rule("port_admin", ("port",))), max_commands=2,
        notes="Two commands: the verified AOS profiles report oper status/counters and "
              "admin status/alias in separate show commands.",
    ),
    Operation.GET_LLDP: OperationPolicy(
        Operation.GET_LLDP, Risk.READ_ONLY, ALL_ROLES,
        "LLDP remote system on one port.",
        _rules(_rule("lldp_port", ("port",))), max_commands=1,
    ),
    Operation.GET_PORT_MACS: OperationPolicy(
        Operation.GET_PORT_MACS, Risk.READ_ONLY, ALL_ROLES,
        "MAC addresses learned on one port.",
        _rules(_rule("mac_on_port", ("port",))), max_commands=1,
    ),
    Operation.RESTART_PORT: OperationPolicy(
        Operation.RESTART_PORT, Risk.STATE_CHANGING, RESTART_ROLES,
        "Bounce one access port (link or PoE) after confirmation and re-check.",
        _rules(_rule("bounce_down", ("port",), 1), _rule("bounce_up", ("port",), 2)),
        max_commands=3,
        notes="Per authorization: down at most once; up at most twice (one restore retry, "
              "possibly on a new session). The up command is the approved restore step, not a "
              "fallback to a different command.",
    ),
})

ALLOWED_OPERATIONS: frozenset[Operation] = frozenset(COMMAND_POLICIES)
API_OPERATIONS: frozenset[Operation] = frozenset(
    op for op, p in COMMAND_POLICIES.items() if p.api_requestable
)
STATE_CHANGING_OPERATIONS: frozenset[Operation] = frozenset(
    op for op, p in COMMAND_POLICIES.items() if p.risk is Risk.STATE_CHANGING
)

# Categories explicitly NOT supported. They are not merely unlisted: requesting them is recorded
# as a security event. Adding one requires a separately reviewed policy change.
DENIED_OPERATION_CATEGORIES: tuple[str, ...] = (
    "CONFIGURATION", "VLAN_CREATION", "VLAN_DELETION", "VLAN_MODIFICATION",
    "ROUTING_CONFIGURATION", "STP_CONFIGURATION", "IP_CONFIGURATION", "INTERFACE_CONFIGURATION",
    "USER_CONFIGURATION", "PASSWORD_CONFIGURATION", "SYSTEM_CONFIGURATION", "REBOOT_SWITCH",
    "WRITE_MEMORY", "COPY_CONFIGURATION", "DELETE_CONFIGURATION", "FIRMWARE_UPGRADE",
    "EXECUTE_COMMAND", "CLI", "SHELL", "TERMINAL",
)

# ---------------------------------------------------------------------------------------------
# Exact template allowlist. Sources: [A8] AOS 8.10R1 CLI guide, [A6] AOS 6.7.1 CLI guide.
# Placeholders: {mac} (xx:xx:xx:xx:xx:xx), {port} (slot/port or chassis/slot/port), {agg} (int).
# ---------------------------------------------------------------------------------------------
COMMAND_ALLOWLIST: Mapping[str, frozenset[str]] = MappingProxyType({
    "system_info": frozenset({"show system"}),                                   # A8 61-56, A6 2-31
    "mac_lookup": frozenset({"show mac-learning mac-address {mac}",              # A8 4-41
                             "show mac-address-table {mac}"}),                   # A6 20-10
    "mac_on_port": frozenset({"show mac-learning port {port}",                   # A8 4-41
                              "show mac-address-table {port}"}),                 # A6 20-10
    "vlan_port": frozenset({"show vlan members port {port}",                     # A8 5-13
                            "show vlan port {port}"}),                           # A6 25-15
    "vlan_linkagg": frozenset({"show vlan members linkagg {agg}",                 # A8 5-13
                               "show vlan port {agg}"}),                         # A6 25-15
    "port_detail": frozenset({"show interfaces port {port}",                     # A8 1-59
                              "show interfaces {port}"}),                        # A6 23-49
    "port_admin": frozenset({"show interfaces port {port} alias",                # A8 1-63
                             "show interfaces {port} port"}),                    # A6 23-79
    "lldp_port": frozenset({"show lldp port {port} remote-system",               # A8 18-63
                            "show lldp {port} remote-system"}),                  # A6 13-47
})

READ_COMMAND_KEYS: frozenset[str] = frozenset(COMMAND_ALLOWLIST) - {"system_info"}


class BounceStrategyId(str, enum.Enum):
    INTERFACE_ADMIN = "INTERFACE_ADMIN"              # AOS 6 link bounce       [A6 23-15]
    INTERFACE_ADMIN_STATE = "INTERFACE_ADMIN_STATE"  # AOS 8 link bounce       [A8 1-3]
    LANPOWER_STOP_START = "LANPOWER_STOP_START"      # AOS 6 PoE power cycle   [A6 4-2/4-4]
    LANPOWER_ADMIN_STATE = "LANPOWER_ADMIN_STATE"    # AOS 8 PoE power cycle   [A8 2-4]


# The ONLY state-changing commands that exist in this application: (down, up) template pairs.
STRATEGY_TEMPLATES: Mapping[BounceStrategyId, frozenset[tuple[str, str]]] = MappingProxyType({
    BounceStrategyId.INTERFACE_ADMIN: frozenset({
        ("interfaces {port} admin down", "interfaces {port} admin up"),
    }),
    BounceStrategyId.INTERFACE_ADMIN_STATE: frozenset({
        ("interfaces port {port} admin-state disable", "interfaces port {port} admin-state enable"),
        # Early AOS 8 form without the "port" keyword; only usable in a lab-verified profile.
        ("interfaces {port} admin-state disable", "interfaces {port} admin-state enable"),
    }),
    BounceStrategyId.LANPOWER_STOP_START: frozenset({
        ("lanpower stop {port}", "lanpower start {port}"),
    }),
    BounceStrategyId.LANPOWER_ADMIN_STATE: frozenset({
        ("lanpower port {port} admin-state disable", "lanpower port {port} admin-state enable"),
    }),
})

STATE_CHANGING_TEMPLATES: frozenset[str] = frozenset(
    t for pairs in STRATEGY_TEMPLATES.values() for pair in pairs for t in pair
)


@dataclass(frozen=True)
class DiscoveryCommand:
    key: str
    template: str
    sources: tuple[str, ...]
    expected_output: str = r"(?i)Description:"


# Separately approved discovery profile: one read-only command valid on AOS 6 and AOS 8.
DISCOVERY_PROFILE: Mapping[str, DiscoveryCommand] = MappingProxyType({
    "system_info": DiscoveryCommand(
        "system_info", "show system",
        ("[A8] AOS Release 8 CLI Reference Guide 8.10R1 p.61-56",
         "[A6] AOS Release 6250/6350/6450 CLI Reference Guide 6.7.1 p.2-31"),
    ),
})

# ---------------------------------------------------------------------------------------------
# Parameter shapes used when matching rendered commands (final validation).
# ---------------------------------------------------------------------------------------------
PARAM_PATTERNS: Mapping[str, str] = MappingProxyType({
    "mac": r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}",
    "port": r"\d{1,2}/\d{1,3}(?:/\d{1,3}[A-Z]?)?",
    "agg": r"\d{1,3}",
})

MAX_COMMAND_LENGTH = 120


def template_regex(template: str) -> re.Pattern[str]:
    parts = re.split(r"(\{[a-z]+\})", template)
    out = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            out.append(f"(?:{PARAM_PATTERNS[part[1:-1]]})")
        else:
            out.append(re.escape(part))
    return re.compile("^" + "".join(out) + "$")


_READ_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    template_regex(t) for ts in COMMAND_ALLOWLIST.values() for t in ts
)
_STATE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    template_regex(t) for t in STATE_CHANGING_TEMPLATES
)


def matches_read_allowlist(text: str) -> bool:
    return any(p.match(text) for p in _READ_PATTERNS)


def matches_state_allowlist(text: str) -> bool:
    return any(p.match(text) for p in _STATE_PATTERNS)


class PolicyViolation(ValueError):
    """A template or profile is not permitted by the security policy."""


def check_template(command_key: str, template: str) -> None:
    allowed = COMMAND_ALLOWLIST.get(command_key)
    if allowed is None:
        raise PolicyViolation(f"'{command_key}' is not a command key in the security policy.")
    if template not in allowed:
        raise PolicyViolation(
            f"Template {template!r} is not on the allowlist for '{command_key}'. Allowed: "
            + " | ".join(sorted(allowed))
        )


def check_strategy_templates(strategy: str, down: str, up: str) -> None:
    try:
        sid = BounceStrategyId(strategy)
    except ValueError as exc:
        raise PolicyViolation(f"Unknown bounce strategy {strategy!r}.") from exc
    if (down, up) not in STRATEGY_TEMPLATES[sid]:
        raise PolicyViolation(
            f"{sid.value}: ({down!r}, {up!r}) is not an allowlisted down/up template pair."
        )


def policy_snapshot() -> dict:
    return {
        "version": POLICY_VERSION,
        "operations": {op.value: p.to_dict() for op, p in sorted(COMMAND_POLICIES.items())},
        "allowlist": {k: sorted(v) for k, v in sorted(COMMAND_ALLOWLIST.items())},
        "strategies": {k.value: sorted(list(p) for p in v)
                       for k, v in sorted(STRATEGY_TEMPLATES.items())},
        "discovery": {k: {"template": v.template, "sources": list(v.sources),
                          "expected_output": v.expected_output}
                      for k, v in DISCOVERY_PROFILE.items()},
        "denied_categories": list(DENIED_OPERATION_CATEGORIES),
    }


def policy_digest() -> str:
    canonical = json.dumps(policy_snapshot(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class PolicyIntegrityError(RuntimeError):
    pass


@dataclass
class IntegrityReport:
    ok: bool
    problems: list[str] = field(default_factory=list)


def verify_policy_integrity() -> IntegrityReport:
    """Self-check run when the firewall starts. Any problem puts the firewall in FAILED state,
    which blocks every command (fail closed)."""
    problems: list[str] = []
    for op, pol in COMMAND_POLICIES.items():
        if pol.operation is not op:
            problems.append(f"{op}: operation mismatch")
        if pol.max_commands < 1:
            problems.append(f"{op}: max_commands must be >= 1")
        for key, rule in pol.commands.items():
            if pol.risk is Risk.READ_ONLY:
                if key not in COMMAND_ALLOWLIST:
                    problems.append(f"{op}: read command key {key} missing from allowlist")
                for t in COMMAND_ALLOWLIST.get(key, ()):
                    if not t.startswith("show ") or matches_state_allowlist(t):
                        problems.append(f"{op}: template {t!r} is not a read-only show command")
            elif pol.risk is Risk.STATE_CHANGING:
                if key not in {"bounce_down", "bounce_up"}:
                    problems.append(f"{op}: unexpected state-changing key {key}")
            else:
                problems.append(f"{op}: operations may only be READ_ONLY or STATE_CHANGING")
            if rule.max_per_invocation > pol.max_commands:
                problems.append(f"{op}: {key} per-invocation limit exceeds operation budget")
    if STATE_CHANGING_OPERATIONS != {Operation.RESTART_PORT}:
        problems.append("Only RESTART_PORT may be state-changing")
    for t in STATE_CHANGING_TEMPLATES:
        if t.startswith("show") or matches_read_allowlist(t):
            problems.append(f"state template {t!r} overlaps the read allowlist")
    for key, cmd in DISCOVERY_PROFILE.items():
        if cmd.template not in COMMAND_ALLOWLIST.get(key, ()):
            problems.append(f"discovery command {key} not in allowlist")
    return IntegrityReport(not problems, problems)
