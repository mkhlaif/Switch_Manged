"""Parser for AOS MAC tables.

Handles both:

* AOS 8 ``show mac-learning ...``::

    Domain Vlan/SrvcId/[ISId/vnID] Mac Address       Type     Operation  Interface
    ------+----------------------+-----------------+--------+----------+-----------
    VLAN   10                     e8:e7:32:11:d4:78 dynamic  bridging   1/1/14
    SPB    3899:3899              e8:e7:32:42:e0:5c dynamic  servicing  sap:0/99:99

* AOS 6 ``show mac-address-table ...``::

    Vlan  Mac Address        Type     Protocol  Operation  Interface
    ------+-----------------+--------+---------+----------+-----------
    1     00:d0:95:6a:73:9a  learned  aaaa0003  bridging   10/23
    1     00:00:00:00:00:01  learned  0800      bridging   8/ 1

The parser anchors on the MAC address in each line: tokens before it are domain/VLAN, tokens after
it are type/[protocol]/operation/interface (interface is always last). A link aggregate is shown
as ``0/<agg_id>`` by both releases.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from app.parsers.common import (
    MAC_IN_OUTPUT,
    PORT_AOS6,
    PORT_AOS8,
    lines,
    mac_from_output,
    normalize_interface,
)

_OPERATIONS = {"bridging", "filtering", "servicing", "quarantined"}
_TOTAL_LINE = re.compile(r"Total number of Valid MAC addresses above\s*=\s*(\d+)", re.IGNORECASE)
_LINKAGG = re.compile(r"^0/(\d+)$")
_SAP = re.compile(r"^sap:(\d+(?:/\d+){1,2}[A-Z]?)(?::|$)", re.IGNORECASE)


@dataclass
class MacEntry:
    mac: str
    vlan_id: int | None
    domain: str
    service: str | None
    mac_type: str
    operation: str | None
    interface_raw: str
    port: str | None
    linkagg_id: int | None
    flags: str = ""

    @property
    def is_linkagg(self) -> bool:
        return self.linkagg_id is not None

    @property
    def valid(self) -> bool:
        return "*" not in self.flags

    def to_dict(self) -> dict:
        return asdict(self)


def interpret_interface(raw: str) -> tuple[str | None, int | None]:
    """Return (physical_port, linkagg_id) for an AOS interface string."""
    value = normalize_interface(raw)
    m = _LINKAGG.match(value)
    if m:
        return None, int(m.group(1))
    m = _SAP.match(value)
    if m:
        inner = m.group(1)
        agg = _LINKAGG.match(inner)
        if agg:
            return None, int(agg.group(1))
        return inner, None
    if PORT_AOS8.match(value) or PORT_AOS6.match(value):
        return value, None
    return None, None


def parse_mac_table(output: str) -> list[MacEntry]:
    entries: list[MacEntry] = []
    for line in lines(output):
        match = MAC_IN_OUTPUT.search(line)
        if not match:
            continue
        before = line[: match.start()].split()
        after = normalize_interface(line[match.end() :]).split()
        if not after:
            continue  # truncated line: no interface column

        domain = "VLAN"
        vlan_id: int | None = None
        service: str | None = None
        if before:
            last = before[-1]
            if last.isdigit():
                vlan_id = int(last)
            else:
                service = last
            if len(before) >= 2 and not before[0].isdigit():
                domain = before[0].upper()
        if domain != "VLAN" and vlan_id is None and service is None:
            continue

        interface_raw = after[-1]
        mac_type = after[0].lower() if len(after) >= 2 else ""
        operation = next((t.lower() for t in after[:-1] if t.lower() in _OPERATIONS), None)
        port, agg = interpret_interface(interface_raw)
        entries.append(
            MacEntry(
                mac=mac_from_output(match.group(1)),
                vlan_id=vlan_id if domain == "VLAN" else None,
                domain=domain,
                service=service,
                mac_type=mac_type,
                operation=operation,
                interface_raw=interface_raw,
                port=port,
                linkagg_id=agg,
                flags=match.group(2) or "",
            )
        )
    return entries


def find_mac(output: str, normalized_mac: str) -> list[MacEntry]:
    """Entries for exactly this MAC. Filtering here guards against switches that ignore the
    MAC filter and print their whole table."""
    return [e for e in parse_mac_table(output) if e.mac == normalized_mac]


def count_macs(output: str) -> int:
    entries = parse_mac_table(output)
    if entries:
        return len({(e.mac, e.vlan_id, e.service) for e in entries if e.valid})
    for line in lines(output):
        m = _TOTAL_LINE.search(line)
        if m:
            return int(m.group(1))
    return 0
