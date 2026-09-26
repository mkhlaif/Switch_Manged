"""Port investigation after a MAC is located: VLANs, port status, LLDP, MAC count, classification.

Only the port the MAC was learned on is queried; no switch-wide tables are dumped. A command the
switch rejects degrades the result (with a warning) instead of failing the whole lookup.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.parsers.alcatel.lldp import LldpNeighbor
from app.parsers.alcatel.mac_table import MacEntry
from app.parsers.alcatel.port_status import PortDetail
from app.parsers.alcatel.vlan_port import VlanMembership, split_tagged
from app.services.alcatel.adapter import AlcatelAdapter
from app.services.classification.engine import (
    Classification,
    ClassificationInput,
    PortClass,
    Reason,
    classify_port,
)
from app.security.firewall import CommandBlocked, UnexpectedOutput
from app.services.ssh.errors import CommandFailed, UnsupportedSwitch


@dataclass
class PortInvestigation:
    entry: MacEntry
    declared_uplink: bool
    vlans: list[VlanMembership] | None = None
    detail: PortDetail | None = None
    lldp: list[LldpNeighbor] | None = None
    mac_count: int | None = None
    classification: Classification | None = None
    warnings: list[str] = field(default_factory=list)
    mac_distribution: list[dict] | None = None

    @property
    def tagged_vlans(self) -> list[int]:
        return split_tagged(self.vlans or [])[0]

    @property
    def untagged_vlan(self) -> int | None:
        return split_tagged(self.vlans or [])[1]

    def vlans_as_dicts(self) -> list[dict]:
        return [v.to_dict() for v in self.vlans or []]

    def lldp_as_dicts(self) -> list[dict]:
        return [n.to_dict() for n in self.lldp or []]


async def _try(coro, warnings: list[str], what: str):
    try:
        return await coro
    except CommandBlocked as exc:
        warnings.append(f"{what} blocked by the safety policy: {exc.reason}")
        return None
    except (CommandFailed, UnsupportedSwitch, UnexpectedOutput) as exc:
        warnings.append(f"{what} unavailable: {exc.reason}")
        return None


async def investigate(
    adapter: AlcatelAdapter,
    entry: MacEntry,
    *,
    uplink_ports: list[str],
    include_lldp: bool = True,
    include_mac_count: bool = True,
    switch_role: str = "",
    known_switches: frozenset[str] = frozenset(),
) -> PortInvestigation:
    port = entry.port
    declared = bool(port and port in set(uplink_ports or []))
    inv = PortInvestigation(entry=entry, declared_uplink=declared)

    if entry.is_linkagg:
        if adapter.has("vlan_linkagg"):
            inv.vlans = await _try(adapter.vlans_for_linkagg(entry.linkagg_id), inv.warnings,
                                   "Link aggregate VLAN membership")
        inv.classification = classify_port(ClassificationInput(
            port=None, is_linkagg=True, linkagg_id=entry.linkagg_id, vlans=inv.vlans))
        return inv

    if port is None:
        inv.warnings.append(
            f"The MAC was learned on interface '{entry.interface_raw}', which is not a local "
            "physical port (service/remote interface). Port details are not available."
        )
        inv.classification = Classification(
            PortClass.UNKNOWN, "Low", 0.2, 0, 0,
            [Reason("neutral", f"Interface '{entry.interface_raw}' is not a physical port.")],
        )
        return inv

    if adapter.has("vlan_port"):
        inv.vlans = await _try(adapter.vlans_for_port(port), inv.warnings, "VLAN membership")
    inv.detail = await _try(adapter.port_detail(port), inv.warnings, "Port status")
    if include_lldp and adapter.has("lldp_port"):
        inv.lldp = await _try(adapter.lldp_neighbors(port), inv.warnings, "LLDP")
    if include_mac_count and adapter.has("mac_on_port"):
        inv.mac_count = await _try(adapter.mac_count(port), inv.warnings, "MAC count")

    inv.classification = classify_port(ClassificationInput(
        port=port,
        declared_uplink=declared,
        vlans=inv.vlans,
        lldp=inv.lldp,
        mac_count=inv.mac_count,
        speed_mbps=inv.detail.speed_mbps if inv.detail else None,
        alias=inv.detail.alias if inv.detail else None,
        switch_role=switch_role,
        known_switches=known_switches,
    ))
    return inv
