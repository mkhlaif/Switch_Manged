"""Parser for ``show lldp ... remote-system``.

AOS 8 [A8 p.18-63]::

    Remote LLDP nearest-bridge Agents on Local Port 1/1/16:
        Chassis e8:e7:32:a4:91:e9, Port 1030:
          Remote ID                   = 10,
          Chassis Subtype             = 4 (MAC Address),
          System Name                 = (null),
          Capabilities Supported      = Bridge Router,

AOS 6 [A6 p.13-47]::

    Remote LLDP Agents on Local Slot/Port: 2/47,
          Chassis ID Subtype = 4 (MAC Address),
          Chassis ID = 00:d0:95:e9:c9:2e,
          Port ID = 2048,

Each neighbor block is a list of ``Key = Value,`` lines; unknown keys are kept in ``extra``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.parsers.common import lines, normalize_interface, null_if_empty

_BLOCK_START = re.compile(
    r"Remote LLDP.*?Agents on Local (?:Port|Slot/Port)\s*:?\s*([0-9/ ]+[A-Z]?)\s*[,:]?\s*$",
    re.IGNORECASE,
)
_AOS8_CHASSIS = re.compile(r"^\s*Chassis\s+(\S+?),\s*Port\s+(.+?):?\s*$", re.IGNORECASE)
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /()\-.]*?)\s*=\s*(.*?)\s*,?\s*$")

KNOWN_CAPABILITIES = [
    ("wlan access point", "WLAN AP"),
    ("wlan ap", "WLAN AP"),
    ("station only", "Station"),
    ("station", "Station"),
    ("telephone", "Telephone"),
    ("bridge", "Bridge"),
    ("router", "Router"),
    ("repeater", "Repeater"),
    ("docsis", "DOCSIS"),
    ("other", "Other"),
]


def parse_capabilities(text: str | None) -> list[str]:
    if not text:
        return []
    value = text.lower()
    if "none" in value and not any(k in value for k, _ in KNOWN_CAPABILITIES[:-1]):
        return []
    found: list[str] = []
    for needle, label in KNOWN_CAPABILITIES:
        if needle in value and label not in found:
            found.append(label)
            value = value.replace(needle, " ")
    return found


@dataclass
class LldpNeighbor:
    local_port: str
    chassis_id: str | None = None
    chassis_subtype: str | None = None
    port_id: str | None = None
    port_subtype: str | None = None
    port_description: str | None = None
    system_name: str | None = None
    system_description: str | None = None
    capabilities_supported: list[str] = field(default_factory=list)
    capabilities_enabled: list[str] = field(default_factory=list)
    management_ip: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def capabilities(self) -> list[str]:
        return self.capabilities_enabled or self.capabilities_supported

    def to_dict(self) -> dict:
        data = asdict(self)
        data["capabilities"] = self.capabilities
        return data


_FIELD_MAP = {
    "chassis id": "chassis_id",
    "chassis subtype": "chassis_subtype",
    "chassis id subtype": "chassis_subtype",
    "port id": "port_id",
    "port subtype": "port_subtype",
    "port id subtype": "port_subtype",
    "port description": "port_description",
    "system name": "system_name",
    "system description": "system_description",
}


def parse_lldp_remote(output: str) -> list[LldpNeighbor]:
    neighbors: list[LldpNeighbor] = []
    current: LldpNeighbor | None = None
    local_port: str | None = None

    def start(port: str) -> LldpNeighbor:
        nb = LldpNeighbor(local_port=port)
        neighbors.append(nb)
        return nb

    for line in lines(output):
        if not line.strip():
            continue
        block = _BLOCK_START.search(line)
        if block:
            local_port = normalize_interface(block.group(1)).strip()
            current = start(local_port)
            continue
        if local_port is None:
            continue
        chassis = _AOS8_CHASSIS.match(line)
        if chassis:
            # AOS 8 may list several remote agents under one local port.
            if current is None or current.chassis_id is not None:
                current = start(local_port)
            current.chassis_id = chassis.group(1)
            current.port_id = chassis.group(2).strip().rstrip(":")
            continue
        kv = _KV.match(line)
        if not kv or current is None:
            continue
        key = re.sub(r"\s+", " ", kv.group(1).strip().lower())
        value = null_if_empty(kv.group(2))
        if key in _FIELD_MAP:
            attr = _FIELD_MAP[key]
            if attr == "chassis_id" and current.chassis_id and value and value != current.chassis_id:
                current = start(local_port)
            setattr(current, attr, value)
        elif key == "capabilities supported":
            current.capabilities_supported = parse_capabilities(value)
        elif key == "capabilities enabled":
            current.capabilities_enabled = parse_capabilities(value)
        elif "management" in key and ("ip" in key or "address" in key) and value:
            ip = re.search(r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,}", value)
            current.management_ip = ip.group(0) if ip else value
        elif value is not None:
            current.extra[key] = value
    return [n for n in neighbors if n.chassis_id or n.system_name or n.port_id]
