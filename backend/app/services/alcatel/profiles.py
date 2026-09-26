"""Command profiles for Alcatel-Lucent Enterprise OmniSwitch (AOS).

This module is the executable form of ``docs/AOS_COMMAND_VERIFICATION.md``. Every command carries
the documentation it was verified against. Keep the two in sync.

Sources:
  [A8] OmniSwitch AOS Release 8 CLI Reference Guide, 8.10R1 (July 2024)
  [A6] OmniSwitch AOS Release 6250/6350/6450 CLI Reference Guide, 6.7.1 (Part 033071-00 Rev B, 2016)

Safety model
------------
* Profiles only *select* templates. Which templates exist at all is decided by the single
  authoritative security policy (:mod:`app.security.policy`): every read template must be on
  ``COMMAND_ALLOWLIST`` for its command key, and every bounce strategy must be one of the
  ``STRATEGY_TEMPLATES`` pairs. Nothing else can be expressed.
* Commands are generated and executed only by the Command Safety Firewall
  (:mod:`app.security.firewall`); this module never renders or sends anything.
* A write strategy is usable only when an administrator has lab-verified it for the switch's
  model family + AOS version (``command_verifications`` table). Read commands on real switches
  need the same kind of record (capability ``READ``) unless the requirement is switched off.
* Discovery (``show system``) is not part of these profiles: it lives in the separately approved
  ``DISCOVERY_PROFILE`` of the security policy.
"""

from __future__ import annotations

import enum
import re
from dataclasses import asdict, dataclass, field, replace

from app.parsers.common import PORT_AOS6, PORT_AOS8
from app.security.policy import (
    READ_COMMAND_KEYS,
    BounceStrategyId,
    PolicyViolation,
    check_strategy_templates,
    check_template,
)


class Verification(str, enum.Enum):
    DOC_EXAMPLE = "doc_example"      # exact form appears as an example in the ALE guide
    DOC_SYNTAX = "doc_syntax"        # built from the guide's syntax definition
    LAB_VERIFIED = "lab_verified"    # confirmed on a real switch by an administrator
    UNVERIFIED = "unverified"        # disabled until verified

    @property
    def usable(self) -> bool:
        return self is not Verification.UNVERIFIED


# The strategy identifiers are defined by the security policy (single source of truth).
PortBounceStrategy = BounceStrategyId


class BounceMethod(str, enum.Enum):
    LINK_BOUNCE = "link_bounce"  # administratively disable/enable the Ethernet link
    POE_CYCLE = "poe_cycle"      # switch PoE power off/on (reboots a powered device)


STRATEGY_METHOD = {
    PortBounceStrategy.INTERFACE_ADMIN: BounceMethod.LINK_BOUNCE,
    PortBounceStrategy.INTERFACE_ADMIN_STATE: BounceMethod.LINK_BOUNCE,
    PortBounceStrategy.LANPOWER_STOP_START: BounceMethod.POE_CYCLE,
    PortBounceStrategy.LANPOWER_ADMIN_STATE: BounceMethod.POE_CYCLE,
}

READ_COMMAND_NAMES = tuple(sorted(READ_COMMAND_KEYS))

_PORT_ANY = re.compile(f"{PORT_AOS8.pattern}|{PORT_AOS6.pattern}")


class ProfileLintError(ValueError):
    pass


def lint_read_command(command_key: str, template: str) -> None:
    """Raise ProfileLintError unless ``template`` is allowlisted for ``command_key``."""
    try:
        check_template(command_key, template)
    except PolicyViolation as exc:
        raise ProfileLintError(str(exc)) from exc


def lint_write_template(strategy: PortBounceStrategy, down: str, up: str) -> None:
    try:
        check_strategy_templates(strategy.value, down, up)
    except PolicyViolation as exc:
        raise ProfileLintError(str(exc)) from exc


@dataclass(frozen=True)
class CommandSpec:
    name: str
    template: str
    read_only: bool
    verification: Verification
    source: str
    supported_models: tuple[str, ...] = ()
    supported_versions: tuple[str, ...] = ()
    notes: str = ""
    parser: str = ""                 # parser that consumes the output
    expected_output: str = ""        # regex that valid output must match (output validation)
    allow_empty: bool = False        # e.g. LLDP prints nothing when there is no neighbor
    verified_by: str = ""
    verified_at: str = ""

    @property
    def usable(self) -> bool:
        return self.verification.usable

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verification"] = self.verification.value
        data["verified"] = self.usable
        data["supported_models"] = list(self.supported_models)
        data["supported_versions"] = list(self.supported_versions)
        data["risk_level"] = "READ_ONLY"
        return data


@dataclass(frozen=True)
class BounceStrategySpec:
    strategy: PortBounceStrategy
    down_template: str
    up_template: str
    verification: Verification
    source: str
    # Model-family prefixes (e.g. "OS6860"). Empty = every model of the profile's family.
    supported_models: tuple[str, ...] = ()
    unsupported_models: tuple[str, ...] = ()
    requires_poe_model: bool = False
    notes: str = ""
    verified_by: str = ""
    verified_at: str = ""

    @property
    def method(self) -> BounceMethod:
        return STRATEGY_METHOD[self.strategy]

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy.value,
            "method": self.method.value,
            "down_template": self.down_template,
            "up_template": self.up_template,
            "verification": self.verification.value,
            "verified": self.verification.usable,
            "source": self.source,
            "supported_models": list(self.supported_models),
            "unsupported_models": list(self.unsupported_models),
            "requires_poe_model": self.requires_poe_model,
            "notes": self.notes,
            "verified_by": self.verified_by,
            "verified_at": self.verified_at,
            "risk_level": "STATE_CHANGING",
        }


@dataclass(frozen=True)
class CommandProfile:
    key: str
    name: str
    family: str  # "AOS6" | "AOS7" | "AOS8" — selects port syntax
    version_prefixes: tuple[str, ...]
    description: str
    commands: dict[str, CommandSpec]
    strategies: tuple[BounceStrategySpec, ...] = ()
    builtin: bool = True
    enabled: bool = True
    prompt_pattern: str = r"->\s*$"
    sources: tuple[str, ...] = field(default_factory=tuple)
    # Model families the profile applies to (see model_family()). Empty = none (fail closed).
    supported_models: tuple[str, ...] = ()
    pager_patterns: tuple[str, ...] = ()

    @property
    def port_pattern(self) -> re.Pattern[str]:
        if self.family == "AOS6":
            return PORT_AOS6
        if self.family == "AOS8":
            return PORT_AOS8
        return _PORT_ANY

    def command(self, name: str) -> CommandSpec | None:
        return self.commands.get(name)

    def strategies_for(self, method: BounceMethod) -> list[BounceStrategySpec]:
        return [s for s in self.strategies if s.method is method]

    def validate(self) -> None:
        for name, spec in self.commands.items():
            if spec.expected_output:
                try:
                    re.compile(spec.expected_output)
                except re.error as exc:
                    raise ProfileLintError(f"{self.key}.{name}: invalid expected_output") from exc
        if "mac_lookup" not in self.commands:
            raise ProfileLintError(f"Profile {self.key} lacks the required 'mac_lookup' command.")
        for name, spec in self.commands.items():
            if name not in READ_COMMAND_KEYS:
                raise ProfileLintError(f"{self.key}: unknown command key {name!r}.")
            if not spec.read_only:
                raise ProfileLintError(
                    f"{self.key}.{spec.name}: profile commands must be read-only; "
                    "port changes are only possible through bounce strategies."
                )
            lint_read_command(name, spec.template)
        for strat in self.strategies:
            lint_write_template(strat.strategy, strat.down_template, strat.up_template)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "family": self.family,
            "version_prefixes": list(self.version_prefixes),
            "description": self.description,
            "builtin": self.builtin,
            "enabled": self.enabled,
            "prompt_pattern": self.prompt_pattern,
            "pager_patterns": list(self.pager_patterns),
            "supported_models": list(self.supported_models),
            "supported_versions": list(self.version_prefixes),
            "sources": list(self.sources),
            "commands": {k: v.to_dict() for k, v in self.commands.items()},
            "strategies": [s.to_dict() for s in self.strategies],
        }

    @classmethod
    def from_dict(cls, data: dict) -> CommandProfile:
        commands = {
            name: CommandSpec(
                name=name,
                template=c["template"],
                read_only=bool(c.get("read_only", True)),
                verification=Verification(c.get("verification", "unverified")),
                source=c.get("source", ""),
                supported_models=tuple(c.get("supported_models", ())),
                supported_versions=tuple(c.get("supported_versions", ())),
                notes=c.get("notes", ""),
                parser=c.get("parser", ""),
                expected_output=c.get("expected_output", ""),
                allow_empty=bool(c.get("allow_empty", False)),
                verified_by=c.get("verified_by", ""),
                verified_at=c.get("verified_at", ""),
            )
            for name, c in data.get("commands", {}).items()
        }
        strategies = tuple(
            BounceStrategySpec(
                strategy=PortBounceStrategy(s["strategy"]),
                down_template=s["down_template"],
                up_template=s["up_template"],
                verification=Verification(s.get("verification", "unverified")),
                source=s.get("source", ""),
                supported_models=tuple(s.get("supported_models", ())),
                unsupported_models=tuple(s.get("unsupported_models", ())),
                requires_poe_model=bool(s.get("requires_poe_model", False)),
                notes=s.get("notes", ""),
                verified_by=s.get("verified_by", ""),
                verified_at=s.get("verified_at", ""),
            )
            for s in data.get("strategies", ())
        )
        profile = cls(
            key=data["key"],
            name=data["name"],
            family=data["family"],
            version_prefixes=tuple(data.get("version_prefixes", ())),
            description=data.get("description", ""),
            commands=commands,
            strategies=strategies,
            builtin=bool(data.get("builtin", False)),
            enabled=bool(data.get("enabled", True)),
            prompt_pattern=data.get("prompt_pattern", r"->\s*$"),
            sources=tuple(data.get("sources", ())),
            supported_models=tuple(data.get("supported_models", ())),
            pager_patterns=tuple(data.get("pager_patterns", ())),
        )
        profile.validate()
        return profile


A8 = "[A8] AOS Release 8 CLI Reference Guide 8.10R1"
A6 = "[A6] AOS Release 6250/6350/6450 CLI Reference Guide 6.7.1"


# Output contracts: every command's output must match its pattern, else it is treated as
# UNEXPECTED CLI OUTPUT (logged, counted by the circuit breaker, fail closed).
OUTPUT_CONTRACTS: dict[str, tuple[str, str, bool]] = {
    # key: (parser, expected_output regex, allow_empty)
    "mac_lookup": ("mac_table_parser", r"(?i)Mac Address|Total number of Valid MAC", False),
    "mac_on_port": ("mac_table_parser", r"(?i)Mac Address|Total number of Valid MAC", False),
    "vlan_port": ("vlan_port_parser", r"(?im)^\s*vlan\s+type\s+status", False),
    "vlan_linkagg": ("vlan_port_parser", r"(?im)^\s*vlan\s+type\s+status", False),
    "port_detail": ("port_status_parser", r"(?i)Operational Status", False),
    "port_admin": ("port_admin_parser", r"(?i)Admin\s+Link", False),
    "lldp_port": ("lldp_parser", r"(?i)Remote LLDP", True),
}
A8_PLATFORMS = ("OS6360", "OS6465", "OS6560", "OS6570M", "OS6860", "OS6860N", "OS6865",
                "OS6900", "OS9900")
A6_PLATFORMS = ("OS6250", "OS6350", "OS6450")
DOC_REVIEW = "ALE CLI Reference Guide (documentation review)"
# Date of the documentation review in this project (NOT a lab test). The guide editions and page
# references are in each command's `source`; lab verification is recorded per model family / AOS
# version in the command_verifications table.
DOC_REVIEW_DATE = "2026-09-25"


def _cmd(name: str, template: str, verification: Verification, source: str, notes: str = "",
         **kw) -> CommandSpec:
    parser, expected, allow_empty = OUTPUT_CONTRACTS[name]
    base = dict(parser=parser, expected_output=expected, allow_empty=allow_empty,
                verified_by=DOC_REVIEW, verified_at=DOC_REVIEW_DATE)
    base.update(kw)
    return CommandSpec(name=name, template=template, read_only=True, verification=verification,
                       source=source, notes=notes, **base)


AOS8_PROFILE = CommandProfile(
    key="AOS8",
    name="AOS 8.x (OS6360/6465/6560/6570M/6860/6865/6900/9900)",
    family="AOS8",
    version_prefixes=("8.",),
    description=(
        "Verified against the ALE AOS Release 8 CLI Reference Guide (8.10R1). Ports are "
        "chassis/slot/port. Link bounce and PoE cycle strategies require admin approval per AOS "
        "version after lab validation."
    ),
    sources=(A8,),
    supported_models=A8_PLATFORMS,
    pager_patterns=("--More--",),
    commands={
        "mac_lookup": _cmd("mac_lookup", "show mac-learning mac-address {mac}",
                           Verification.DOC_SYNTAX, f"{A8} p.4-41",
                           "Filtered lookup; the switch returns only entries for this MAC."),
        "mac_on_port": _cmd("mac_on_port", "show mac-learning port {port}",
                            Verification.DOC_SYNTAX, f"{A8} p.4-41"),
        "vlan_port": _cmd("vlan_port", "show vlan members port {port}",
                          Verification.DOC_EXAMPLE, f"{A8} p.5-13"),
        "vlan_linkagg": _cmd("vlan_linkagg", "show vlan members linkagg {agg}",
                             Verification.DOC_SYNTAX, f"{A8} p.5-13"),
        "port_detail": _cmd("port_detail", "show interfaces port {port}",
                            Verification.DOC_EXAMPLE, f"{A8} p.1-59"),
        "port_admin": _cmd("port_admin", "show interfaces port {port} alias",
                           Verification.DOC_EXAMPLE, f"{A8} p.1-63"),
        "lldp_port": _cmd("lldp_port", "show lldp port {port} remote-system",
                          Verification.DOC_SYNTAX, f"{A8} p.18-63"),
    },
    strategies=(
        BounceStrategySpec(
            strategy=PortBounceStrategy.INTERFACE_ADMIN_STATE,
            down_template="interfaces port {port} admin-state disable",
            up_template="interfaces port {port} admin-state enable",
            verification=Verification.DOC_SYNTAX,
            source=f"{A8} p.1-3",
            notes="Syntax per 8.10R1. Early 8.x releases may differ: validate on your version.",
            verified_by=DOC_REVIEW, verified_at=DOC_REVIEW_DATE,
        ),
        BounceStrategySpec(
            strategy=PortBounceStrategy.LANPOWER_ADMIN_STATE,
            down_template="lanpower port {port} admin-state disable",
            up_template="lanpower port {port} admin-state enable",
            verification=Verification.DOC_EXAMPLE,
            source=f"{A8} p.2-4",
            unsupported_models=("OS6570M", "OS6900"),
            requires_poe_model=True,
            notes="PoE power cycle only; introduced in 8.1.1. Not supported on OS6570M/OS6900.",
            verified_by=DOC_REVIEW, verified_at=DOC_REVIEW_DATE,
        ),
    ),
)

AOS6_PROFILE = CommandProfile(
    key="AOS6",
    name="AOS 6.6/6.7 (OS6250/6350/6450)",
    family="AOS6",
    version_prefixes=("6.6", "6.7"),
    description=(
        "Verified against the ALE AOS 6250/6350/6450 CLI Reference Guide (6.7.1; commands "
        "introduced in 6.6.1). Ports are slot/port (e.g. 1/26). Other AOS 6 platforms (OS6400, "
        "OS6850E, OS6855, OS9000E) are NOT covered: their switches get 'Command profile "
        "unavailable'. Write strategies require admin lab approval per model and AOS version."
    ),
    sources=(A6,),
    supported_models=A6_PLATFORMS,
    pager_patterns=("More? [next screen <sp>, next line <cr>, filter pattern </>, quit </>]",),
    commands={
        "mac_lookup": _cmd("mac_lookup", "show mac-address-table {mac}",
                           Verification.DOC_SYNTAX, f"{A6} p.20-10"),
        "mac_on_port": _cmd("mac_on_port", "show mac-address-table {port}",
                            Verification.DOC_SYNTAX, f"{A6} p.20-10",
                            "Positional slot/port filter per the syntax line; lab-validate."),
        "vlan_port": _cmd("vlan_port", "show vlan port {port}", Verification.DOC_EXAMPLE,
                          f"{A6} p.25-15"),
        "vlan_linkagg": _cmd("vlan_linkagg", "show vlan port {agg}", Verification.DOC_SYNTAX,
                             f"{A6} p.25-15"),
        "port_detail": _cmd("port_detail", "show interfaces {port}", Verification.DOC_EXAMPLE,
                            f"{A6} p.23-49"),
        "port_admin": _cmd("port_admin", "show interfaces {port} port", Verification.DOC_EXAMPLE,
                           f"{A6} p.23-79"),
        "lldp_port": _cmd("lldp_port", "show lldp {port} remote-system", Verification.DOC_SYNTAX,
                          f"{A6} p.13-47"),
    },
    strategies=(
        BounceStrategySpec(
            strategy=PortBounceStrategy.INTERFACE_ADMIN,
            down_template="interfaces {port} admin down",
            up_template="interfaces {port} admin up",
            verification=Verification.DOC_EXAMPLE,
            source=f"{A6} p.23-15",
            verified_by=DOC_REVIEW, verified_at=DOC_REVIEW_DATE,
        ),
        BounceStrategySpec(
            strategy=PortBounceStrategy.LANPOWER_STOP_START,
            down_template="lanpower stop {port}",
            up_template="lanpower start {port}",
            verification=Verification.DOC_EXAMPLE,
            source=f"{A6} p.4-2, p.4-4",
            requires_poe_model=True,
            notes="PoE power cycle only.",
            verified_by=DOC_REVIEW, verified_at=DOC_REVIEW_DATE,
        ),
    ),
)

# AOS 7 shares most syntax with AOS 8 ([A8] release history says many commands were introduced in
# 7.1.1) but was NOT verified against an AOS 7 guide, so every command ships unverified/disabled.
AOS7_PROFILE = CommandProfile(
    key="AOS7",
    name="AOS 7.x (OS10K, early OS6900) — UNVERIFIED",
    family="AOS7",
    version_prefixes=("7.",),
    description=(
        "Not verified against an AOS 7 CLI guide. All commands are disabled until an administrator "
        "lab-validates them (clone this profile and mark commands lab_verified)."
    ),
    enabled=False,
    supported_models=("OS10K", "OS6900"),
    commands={
        name: replace(spec, verification=Verification.UNVERIFIED, verified_by="", verified_at="",
                      source="Unverified: syntax assumed from [A8] release history (7.1.1)")
        for name, spec in AOS8_PROFILE.commands.items()
    },
    strategies=(),
)

BUILTIN_PROFILES: dict[str, CommandProfile] = {
    p.key: p for p in (AOS8_PROFILE, AOS6_PROFILE, AOS7_PROFILE)
}

for _p in BUILTIN_PROFILES.values():
    _p.validate()


def version_matches_prefix(version: str, prefix: str) -> bool:
    """Dotted-boundary prefix match: '8.10' matches '8.10.94.R03' but not '8.1.1.R01'."""
    if not version or not prefix:
        return False
    prefix = prefix.rstrip(".")
    return version == prefix or version.startswith(prefix + ".")


def is_poe_model(model: str) -> bool:
    """ALE PoE models carry a 'P' in the suffix: OS6450-P24, OS6860E-P48, OS6560-P48Z16."""
    return bool(re.search(r"-[A-Z]*P\d", model or ""))


def model_matches(model: str, prefixes: tuple[str, ...]) -> bool:
    return any((model or "").upper().startswith(p.upper()) for p in prefixes)


_FAMILY = re.compile(r"^OS(\d{2,5}K?)([A-Z]?)")


def model_family(model: str | None) -> str | None:
    """OS6860E-P24 -> OS6860, OS6860N-P48M -> OS6860N, OS6570M-12 -> OS6570M, OS6450-P24 ->
    OS6450, OS10K -> OS10K. None when the model string is unknown/unrecognised."""
    m = _FAMILY.match((model or "").upper())
    if not m:
        return None
    digits, suffix = m.groups()
    return f"OS{digits}{suffix}" if suffix in {"N", "M"} else f"OS{digits}"


def profile_applicability(profile: CommandProfile, model: str | None,
                          version: str | None) -> tuple[bool, str]:
    """Is this verified profile applicable to this exact model family and AOS version?"""
    family = model_family(model)
    if family is None:
        return False, f"model {model or 'unknown'!r} is not recognised"
    if family not in profile.supported_models:
        return False, f"{family} is not a supported model of profile {profile.key}"
    if not version or not any(version_matches_prefix(version, v) or version.startswith(v)
                              for v in profile.version_prefixes):
        return False, f"AOS {version or 'unknown'} is not a supported version of {profile.key}"
    return True, f"{profile.key} applies to {family} AOS {version}"
