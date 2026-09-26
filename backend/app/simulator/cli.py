"""Simulated AOS command interpreter.

Output layouts follow the examples in the ALE CLI reference guides ([A8] AOS 8.10R1, [A6] AOS 6.7.1)
so that the real parsers are exercised against realistic text. Only the commands this application
uses are implemented; anything else returns an AOS-style ``ERROR: Invalid entry`` line.
"""

from __future__ import annotations

import re
import time

from app.simulator.model import SimPort, SimSwitch

_MAC = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
_P8 = r"(\d+/\d+/\d+[A-Z]?)"
_P6 = r"(\d+/\d+)"


def _mac(m12: str) -> str:
    return ":".join(m12[i : i + 2] for i in range(0, 12, 2))


def _invalid(command: str) -> str:
    word = command.split()[1] if len(command.split()) > 1 else command
    return f'ERROR: Invalid entry: "{word}"'


class SimCli:
    def __init__(self, switch: SimSwitch) -> None:
        self.sw = switch

    # ------------------------------------------------------------------------------------------
    def execute(self, command: str) -> str:
        cmd = " ".join(command.strip().split())
        self.sw.command_log.append(cmd)
        b = self.sw.behavior
        if any(s in cmd for s in b.error_on):
            return _invalid(cmd)
        if any(s in cmd for s in b.malformed_on):
            return "Domain  Vlan  Mac Addr\n---+---\nVLAN 2@@ 00:11:22:33:44\n\x00garbage ### ->x\n"
        if cmd == "show system":
            return self._show_system()
        handler = self._aos8 if self.sw.family in ("AOS8", "AOS7") else self._aos6
        return handler(cmd)

    # ------------------------------------------------------------------------------------------
    def _show_system(self) -> str:
        vendor = "Alcatel-Lucent Enterprise" if self.sw.family != "AOS6" else "Alcatel-Lucent"
        return (
            "System:\n"
            f"  Description:  {vendor} {self.sw.model} {self.sw.version} GA, June 12, 2024.,\n"
            "  Object ID:    1.3.6.1.4.1.6486.801.1.1.2.1.11.1.3,\n"
            "  Up Time:      12 days 3 hours 1 minutes and 44 seconds,\n"
            "  Contact:      Network Operations,\n"
            f"  Name:         {self.sw.name},\n"
            f"  Location:     {self.sw.location or 'Unknown'},\n"
            "  Services:     78,\n"
            "  Date & Time:  THU SEP 25 2026 18:22:01 (UTC)\n"
            "Flash Space:\n"
            "    Primary CMM:\n"
            "      Available (bytes):  1011867648,\n"
            "      Comments         :  None\n"
        )

    def _port(self, port: str) -> SimPort | None:
        return self.sw.ports.get(port)

    # ---------------------------------------------------------------- AOS 8 -------------------
    def _aos8(self, cmd: str) -> str:
        if m := re.fullmatch(rf"show mac-learning mac-address {_MAC}", cmd):
            target = m.group(1).replace(":", "").lower()
            rows = [r for r in self.sw.all_mac_rows() if r[1] == target]
            return self._mac_table8(rows)
        if m := re.fullmatch(rf"show mac-learning port {_P8}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._mac_table8([(v, mac, p.port) for v, mac in p.visible_macs()])
        if m := re.fullmatch(rf"show vlan members port {_P8}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._vlan_table(p.vlans, p.link_up)
        if m := re.fullmatch(r"show vlan members linkagg (\d+)", cmd):
            agg = self.sw.linkaggs.get(int(m.group(1)))
            return self._vlan_table(agg.vlans if agg else [], True)
        if m := re.fullmatch(rf"show interfaces port {_P8} alias", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._alias8(p)
        if m := re.fullmatch(rf"show interfaces port {_P8}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._interface_detail(p, "Chassis/Slot/Port")
        if m := re.fullmatch(rf"show lldp port {_P8} remote-system", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._lldp8(p)
        if m := re.fullmatch(rf"interfaces port {_P8} admin-state (enable|disable)", cmd):
            return self._set_admin(m.group(1), m.group(2) == "enable", cmd)
        if m := re.fullmatch(rf"lanpower port {_P8} admin-state (enable|disable)", cmd):
            return self._set_poe(m.group(1), m.group(2) == "enable", cmd)
        return _invalid(cmd)

    def _mac_table8(self, rows: list[tuple[int, str, str]]) -> str:
        out = [
            "Legend: Mac Address: * = address not valid,",
            "        Mac Address: & = duplicate static address,",
            "        ID = ISID/Vnid/vplsid",
            "",
            " Domain    Vlan/SrvcId[:ID]    Mac Address           Type          Operation"
            "          Interface",
            "------+----------------------+-------------------+------------------+-------------"
            "+-------------------------",
        ]
        for vlan, mac, iface in rows:
            out.append(f" VLAN       {vlan:<18} {_mac(mac)}    dynamic            bridging"
                       f"            {iface}")
        out += ["", f" Total number of Valid MAC addresses above = {len(rows)}"]
        return "\n".join(out)

    def _alias8(self, p: SimPort) -> str:
        return "\n".join([
            "Legends:WTS - Wait to shutdown",
            "        # - WTS Timer is Running & port is in wait-to-shutdown state",
            "",
            "Chas/",
            "Slot/   Admin     Link    WTR   WTS    Alias",
            "Port    Status   Status  (sec) (msec)",
            "-----+----------+---------+-----+----+----------------------------------",
            f"{p.port:<8} {'enable' if p.admin_up else 'disable':<9} "
            f"{'up' if p.link_up else 'down':<7} 0    0  \"{p.alias}\"",
        ])

    def _lldp8(self, p: SimPort) -> str:
        if not p.lldp or not p.link_up:
            return ""
        out = [f"Remote LLDP nearest-bridge Agents on Local Port {p.port}:", ""]
        for i, nb in enumerate(p.lldp, start=1):
            out += [
                f"    Chassis {nb.chassis_id}, Port {nb.port_id}:",
                f"      Remote ID                   = {i},",
                "      Chassis Subtype             = 4 (MAC Address),",
                "      Port Subtype                = 7 (Locally assigned),",
                f"      Port Description            = {nb.port_description},",
                f"      System Name                 = {nb.system_name},",
                f"      System Description          = {nb.system_description},",
                f"      Capabilities Supported      = {nb.capabilities},",
                f"      Capabilities Enabled        = {nb.capabilities},",
            ]
            if nb.management_ip:
                out.append(f"      Management IP Address       = {nb.management_ip},")
            out.append("")
        return "\n".join(out)

    # ---------------------------------------------------------------- AOS 6 -------------------
    def _aos6(self, cmd: str) -> str:
        if m := re.fullmatch(rf"show mac-address-table {_MAC}", cmd):
            target = m.group(1).replace(":", "").lower()
            return self._mac_table6([r for r in self.sw.all_mac_rows() if r[1] == target])
        if m := re.fullmatch(rf"show mac-address-table {_P6}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._mac_table6([(v, mac, p.port) for v, mac in p.visible_macs()])
        if m := re.fullmatch(rf"show vlan port {_P6}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._vlan_table(p.vlans, p.link_up)
        if m := re.fullmatch(r"show vlan port (\d+)", cmd):
            agg = self.sw.linkaggs.get(int(m.group(1)))
            return self._vlan_table(agg.vlans if agg else [], True)
        if m := re.fullmatch(rf"show interfaces {_P6} port", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._port6(p)
        if m := re.fullmatch(rf"show interfaces {_P6}", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._interface_detail(p, "Slot/Port")
        if m := re.fullmatch(rf"show lldp {_P6} remote-system", cmd):
            if (p := self._port(m.group(1))) is None:
                return _invalid(cmd)
            return self._lldp6(p)
        if m := re.fullmatch(rf"interfaces {_P6} admin (up|down)", cmd):
            return self._set_admin(m.group(1), m.group(2) == "up", cmd)
        if m := re.fullmatch(rf"lanpower (stop|start) {_P6}", cmd):
            return self._set_poe(m.group(2), m.group(1) == "start", cmd)
        return _invalid(cmd)

    def _mac_table6(self, rows: list[tuple[int, str, str]]) -> str:
        out = [
            "Legend: Mac Address: * = address not valid",
            "",
            " Vlan    Mac Address       Type     Protocol    Operation         Interface",
            "------+-------------------+--------------+-----------+------------+-----------",
        ]
        for vlan, mac, iface in rows:
            # AOS 6 pads single-digit port numbers inside the interface ("1/ 5"), per [A6].
            slot, _, port = iface.partition("/")
            shown = f"{slot}/{port:>2}" if iface.count("/") == 1 else iface
            out.append(f"{vlan:>5}  {_mac(mac)}     learned         0800     bridging"
                       f"          {shown}")
        out += ["", f"Total number of Valid MAC addresses above = {len(rows)}"]
        return "\n".join(out)

    def _port6(self, p: SimPort) -> str:
        return "\n".join([
            "Legends: * - Permanent Shutdown",
            "",
            "Slot/    Admin     Link    Violations   Recovery   Recovery  Alias",
            "Port     Status   Status                  Time        Max",
            "------+----------+---------+----------+----------+----------+----------",
            f" {p.port:<7} {'enable' if p.admin_up else 'disable':<9} "
            f"{'up' if p.link_up else 'down':<8} none        300          1      \"{p.alias}\"",
        ])

    def _lldp6(self, p: SimPort) -> str:
        if not p.lldp or not p.link_up:
            return ""
        out: list[str] = []
        for nb in p.lldp:
            out += [
                f"Remote LLDP Agents on Local Slot/Port: {p.port},",
                "      Chassis ID Subtype          = 4 (MAC Address),",
                f"      Chassis ID                  = {nb.chassis_id},",
                "      Port ID Subtype             = 7 (Locally assigned),",
                f"      Port ID                     = {nb.port_id},",
                f"      Port Description            = {nb.port_description},",
                f"      System Name                 = {nb.system_name},",
                f"      System Description          = {nb.system_description},",
                f"      Capabilities Supported      = {nb.capabilities},",
                f"      Capabilities Enabled        = {nb.capabilities},",
            ]
            if nb.management_ip:
                out.append(f"      Management IP Address       = {nb.management_ip},")
        return "\n".join(out)

    # ---------------------------------------------------------------- shared ------------------
    @staticmethod
    def _vlan_table(vlans: list[tuple[int, str]], link_up: bool) -> str:
        out = [" vlan     type         status", "+------+-----------+--------------+"]
        for vid, typ in vlans:
            status = "forwarding" if link_up else "inactive"
            out.append(f"{vid:>6}   {typ:<11} {status}")
        return "\n".join(out)

    @staticmethod
    def _interface_detail(p: SimPort, label: str) -> str:
        return "\n".join([
            f"{label}  {p.port} :",
            f" Operational Status     : {'up' if p.link_up else 'down'},",
            " Last Time Link Changed : THU SEP 25 17:40:12 2026,",
            f" Number of Status Change: {p.status_changes},",
            " Port-Down/Violation Reason: None,",
            " Type                   : Ethernet,",
            f" SFP/XFP                : {'SFP_10G_SR' if p.speed >= 10000 else 'N/A'},",
            f" Interface Type         : {'Fiber' if p.speed >= 10000 else 'Copper'},",
            " MAC address            : e8:e7:32:aa:01:1a,",
            f" BandWidth (Megabits)   :     {p.speed},         Duplex           : {p.duplex},",
            " Autonegotiation        :   1  [ 1000-F 100-F 100-H 10-F 10-H ],",
            " Long Frame Size(Bytes) : 9216,             Runt Size(Bytes) : 64,",
            " Rx              :",
            " Bytes Received  :           7967624, Unicast Frames :             11024,",
            " Broadcast Frames:            124186, M-cast Frames  :               290,",
            " UnderSize Frames:                 0, OverSize Frames:                 0,",
            f" Lost Frames     :                 0, Error Frames   :                 {p.rx_errors},",
            " CRC Error Frames:                 0, Alignments Err :                 0,",
            " Tx              :",
            " Bytes Xmitted   :         255804426, Unicast Frames :             24992,",
            " Broadcast Frames:           3178399, M-cast Frames  :            465789,",
            " UnderSize Frames:                 0, OverSize Frames:                 0,",
            " Lost Frames     :                 0, Collided Frames:                 0,",
            " Error Frames    :                 0, Collisions     :                 0,",
            " Late Collisions :                 0, Exc-Collisions :                 0",
        ])

    def _set_admin(self, port: str, up: bool, cmd: str) -> str:
        p = self._port(port)
        if p is None:
            return _invalid(cmd)
        if up and self.sw.behavior.fail_up_command:
            return "ERROR: Simulated failure enabling the port"
        was_up = p.link_up
        p.admin_up = up
        self._after_link_change(p, was_up)
        return ""

    def _set_poe(self, port: str, on: bool, cmd: str) -> str:
        p = self._port(port)
        if p is None:
            return _invalid(cmd)
        if not p.poe:
            return "ERROR: Port is not PoE capable"
        if on and self.sw.behavior.fail_up_command:
            return "ERROR: Simulated failure starting PoE"
        was_up = p.link_up
        p.poe_on = on
        self._after_link_change(p, was_up)
        return ""

    def _after_link_change(self, p: SimPort, was_up: bool) -> None:
        if p.link_up != was_up:
            p.status_changes += 1
        if p.link_up and not was_up:
            p.macs_hidden_until = time.monotonic() + self.sw.behavior.relearn_delay
