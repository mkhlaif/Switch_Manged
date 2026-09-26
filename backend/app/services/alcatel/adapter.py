"""High-level, read-only AOS operations.

Every method requests a predefined operation from the Command Safety Firewall; this module never
builds, sees or sends command text.
"""

from __future__ import annotations

from app.parsers.alcatel.lldp import LldpNeighbor, parse_lldp_remote
from app.parsers.alcatel.mac_table import MacEntry, count_macs, find_mac, parse_mac_table
from app.parsers.alcatel.port_status import PortDetail, parse_interface_detail, parse_port_admin
from app.parsers.alcatel.vlan_port import VlanMembership, parse_vlan_port
from app.parsers.common import normalize_mac
from app.security.firewall import FirewallSession
from app.security.policy import Operation


class AlcatelAdapter:
    def __init__(self, session: FirewallSession) -> None:
        if session.profile is None:
            raise ValueError("A verified command profile must be bound to the session first.")
        self.fs = session
        self.profile = session.profile

    def has(self, name: str) -> bool:
        spec = self.profile.command(name)
        return spec is not None and spec.usable

    async def find_mac(self, mac: str) -> tuple[list[MacEntry], str]:
        output = await self.fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=mac)
        return find_mac(output, normalize_mac(mac)), output

    async def vlans_for_port(self, port: str) -> list[VlanMembership]:
        return parse_vlan_port(await self.fs.run(Operation.GET_PORT_VLAN, "vlan_port", port=port))

    async def vlans_for_linkagg(self, agg: int) -> list[VlanMembership]:
        return parse_vlan_port(
            await self.fs.run(Operation.GET_PORT_VLAN, "vlan_linkagg", agg=agg)
        )

    async def port_detail(self, port: str) -> PortDetail:
        detail = PortDetail()
        async with self.fs.operation(Operation.GET_PORT_STATUS) as op:
            if self.has("port_detail"):
                detail = parse_interface_detail(await op.run("port_detail", port=port))
            if self.has("port_admin"):
                admin = parse_port_admin(await op.run("port_admin", port=port), port)
                detail.admin_status = admin["admin_status"]
                detail.link_status = admin["link_status"]
                detail.alias = admin["alias"]
        return detail

    async def oper_status(self, port: str) -> str | None:
        output = await self.fs.run(Operation.GET_PORT_STATUS, "port_detail", port=port)
        return parse_interface_detail(output).oper_status

    async def lldp_neighbors(self, port: str) -> list[LldpNeighbor]:
        output = await self.fs.run(Operation.GET_LLDP, "lldp_port", port=port)
        neighbors = parse_lldp_remote(output)
        # The command is already filtered by port; the local-port check is a safety net.
        matching = [n for n in neighbors if n.local_port == port]
        return matching or neighbors

    async def port_macs(self, port: str) -> list[MacEntry]:
        return parse_mac_table(await self.fs.run(Operation.GET_PORT_MACS, "mac_on_port",
                                                 port=port))

    async def mac_count(self, port: str) -> int:
        return count_macs(await self.fs.run(Operation.GET_PORT_MACS, "mac_on_port", port=port))
