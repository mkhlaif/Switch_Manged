"""State model for simulated OmniSwitches (lab mode and automated tests)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class SimLldp:
    chassis_id: str
    port_id: str
    system_name: str
    system_description: str
    capabilities: str  # e.g. "Bridge Router", "Bridge, Telephone", "WLAN AP"
    port_description: str = "(null)"
    management_ip: str | None = None


@dataclass
class SimPort:
    port: str
    vlans: list[tuple[int, str]]  # (vlan id, raw type as the switch prints it)
    macs: list[tuple[int, str]] = field(default_factory=list)  # (vlan, 12-hex mac)
    alias: str = ""
    speed: int = 1000
    duplex: str = "Full"
    admin_up: bool = True
    cable_connected: bool = True
    poe: bool = False
    poe_on: bool = True
    powered_device: bool = False  # device loses power (and link) when PoE is off
    lldp: list[SimLldp] = field(default_factory=list)
    macs_hidden_until: float = 0.0
    status_changes: int = 1
    rx_errors: int = 0

    @property
    def link_up(self) -> bool:
        if not (self.admin_up and self.cable_connected):
            return False
        return not (self.poe and self.powered_device and not self.poe_on)

    def visible_macs(self) -> list[tuple[int, str]]:
        if not self.link_up or time.monotonic() < self.macs_hidden_until:
            return []
        return list(self.macs)


@dataclass
class SimLinkAgg:
    agg_id: int
    vlans: list[tuple[int, str]]
    macs: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class SimBehavior:
    auth_fail: bool = False
    connect_refused: bool = False
    hang_on: tuple[str, ...] = ()           # command substrings that never return a prompt
    silent_on: tuple[str, ...] = ()         # executed, but the response is lost (no prompt)
    error_on: tuple[str, ...] = ()          # command substrings answered with ERROR:
    malformed_on: tuple[str, ...] = ()      # command substrings answered with garbage
    fail_up_command: bool = False           # the "up/enable/start" command errors
    paginate_lines: int = 0                 # >0 enables AOS 6 style "more" mode
    command_delay: float = 0.0
    relearn_delay: float = 2.0
    banner: str = ""
    system_output: str = ""                 # replaces the "show system" answer (other vendor)


@dataclass
class SimSwitch:
    name: str
    family: str  # AOS6 | AOS8 | AOS7
    model: str
    version: str
    location: str = ""
    prompt: str = "->"
    username: str = "lab"
    password: str = "lab-password"
    ports: dict[str, SimPort] = field(default_factory=dict)
    linkaggs: dict[int, SimLinkAgg] = field(default_factory=dict)
    behavior: SimBehavior = field(default_factory=SimBehavior)
    base_mac: str = "e8e732000000"
    command_log: list[str] = field(default_factory=list)

    def all_mac_rows(self) -> list[tuple[int, str, str]]:
        """(vlan, mac, interface) for every visible MAC."""
        rows: list[tuple[int, str, str]] = []
        for port in self.ports.values():
            rows.extend((v, m, port.port) for v, m in port.visible_macs())
        for agg in self.linkaggs.values():
            rows.extend((v, m, f"0/{agg.agg_id}") for v, m in agg.macs)
        return rows
