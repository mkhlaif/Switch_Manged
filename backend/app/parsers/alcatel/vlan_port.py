"""Parser for per-port VLAN membership (VPA) output.

AOS 8 ``show vlan members port 2/1/2``::

    vlan    type      status
    +------+---------+------------+
       1    untagged  forwarding
       2    tagged    forwarding
       5    dynamic   blocking

AOS 6 ``show vlan port 3/2``::

    vlan    type      status
    +------+---------+------------+
       1    default   forwarding
       2    qtagged   forwarding

Type vocabularies differ between releases, so they are mapped onto one normalized mode plus a
tagged/untagged flag. ``tagged`` is ``None`` when the type does not say (for example ``mirror``).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from app.parsers.common import PORT_AOS6, PORT_AOS8, lines

# raw type (lowercase, single-spaced) -> (normalized mode, tagged)
_MODE_MAP: dict[str, tuple[str, bool | None]] = {
    # AOS 8 [A8 p.5-13]
    "untagged": ("untagged", False),
    "tagged": ("tagged", True),
    "dynamic": ("dynamic", True),  # MVRP (AOS 8) / GVRP (AOS 6): learned from another switch
    "mirror": ("mirror", None),
    "mirrored": ("mirror", None),
    "spb": ("spb", True),
    "unp untagged": ("unp_untagged", False),
    "unp qtagged": ("unp_tagged", True),
    "unp tagged": ("unp_tagged", True),
    # AOS 6 [A6 p.25-15]
    "default": ("untagged", False),
    "qtagged": ("tagged", True),
    "vstkqtag": ("vstk_tagged", True),
    "mobile": ("mobile", False),
}

_ROW = re.compile(r"^\s*(\d{1,4})\s+(.+?)\s+([A-Za-z][A-Za-z\-]*)\s*$")


@dataclass
class VlanMembership:
    vlan_id: int
    mode: str
    mode_raw: str
    tagged: bool | None
    status: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_vlan_port(output: str) -> list[VlanMembership]:
    result: list[VlanMembership] = []
    seen: set[int] = set()
    for line in lines(output):
        m = _ROW.match(line)
        if not m:
            continue
        vlan_id = int(m.group(1))
        if not 1 <= vlan_id <= 4094:
            continue
        middle = m.group(2).split()
        # Tolerate the all-ports layout ("vlan port type status") by dropping a port column.
        if middle and (PORT_AOS8.match(middle[0]) or PORT_AOS6.match(middle[0])):
            middle = middle[1:]
        if not middle:
            continue
        raw_type = " ".join(middle)
        mode, tagged = _MODE_MAP.get(raw_type.lower(), ("other", None))
        if vlan_id in seen:
            continue
        seen.add(vlan_id)
        result.append(
            VlanMembership(
                vlan_id=vlan_id,
                mode=mode,
                mode_raw=raw_type,
                tagged=tagged,
                status=m.group(3).lower(),
            )
        )
    return result


def split_tagged(memberships: list[VlanMembership]) -> tuple[list[int], int | None]:
    """Return (tagged VLAN ids, untagged/default VLAN id)."""
    tagged = sorted(v.vlan_id for v in memberships if v.tagged is True)
    untagged = [v.vlan_id for v in memberships if v.tagged is False and v.mode == "untagged"]
    if not untagged:
        untagged = [v.vlan_id for v in memberships if v.tagged is False]
    return tagged, (untagged[0] if untagged else None)
