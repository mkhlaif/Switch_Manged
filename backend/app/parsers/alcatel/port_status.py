"""Parsers for interface detail and admin-status/alias output.

``show interfaces port 1/1/2`` (AOS 8) / ``show interfaces 1/2`` (AOS 6) print comma-separated
``key : value`` pairs, with Rx/Tx counter sections::

    Chassis/Slot/Port 1/1/2 :
    Operational Status     : up,
    BandWidth (Megabits)   :     1000,          Duplex           : Full,
    Rx              :
    Error Frames    :        0,  CRC Error Frames:          0,

``show interfaces port 1/1/2 alias`` (AOS 8) / ``show interfaces 1/2 port`` (AOS 6) print a one-row
table whose first three columns are port, admin status and link status, and whose last column
is the quoted alias.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.parsers.common import lines, normalize_interface, null_if_empty


@dataclass
class PortDetail:
    oper_status: str | None = None
    admin_status: str | None = None
    link_status: str | None = None
    alias: str | None = None
    speed_mbps: int | None = None
    duplex: str | None = None
    autonegotiation: str | None = None
    interface_type: str | None = None
    transceiver: str | None = None
    port_mac: str | None = None
    last_link_change: str | None = None
    status_changes: int | None = None
    down_reason: str | None = None
    rx: dict[str, int] = field(default_factory=dict)
    tx: dict[str, int] = field(default_factory=dict)

    @property
    def rx_errors(self) -> int | None:
        if not self.rx:
            return None
        return sum(self.rx.get(k, 0) for k in ("error_frames", "crc_error_frames", "alignments_err"))

    @property
    def tx_errors(self) -> int | None:
        if not self.tx:
            return None
        return sum(self.tx.get(k, 0) for k in ("error_frames", "collisions", "late_collisions"))

    def to_dict(self) -> dict:
        data = asdict(self)
        data["rx_errors"] = self.rx_errors
        data["tx_errors"] = self.tx_errors
        return data


def _key(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _counter_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _key(text)).strip("_")


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    m = re.search(r"-?\d+", value.replace(",", ""))
    return int(m.group(0)) if m else None


def _status(value: str | None) -> str | None:
    v = null_if_empty(value)
    if v is None:
        return None
    v = v.lower().strip("*")
    return {"en": "enabled", "enable": "enabled", "enabled": "enabled", "dis": "disabled",
            "disable": "disabled", "disabled": "disabled"}.get(v, v)


def parse_interface_detail(output: str) -> PortDetail:
    detail = PortDetail()
    section: str | None = None
    pairs: dict[str, str] = {}
    for line in lines(output):
        stripped = line.strip()
        if not stripped:
            continue
        head = _key(stripped.split(":", 1)[0])
        if head in {"rx", "tx"} and stripped.rstrip(",").endswith(":"):
            section = head
            continue
        for chunk in stripped.split(","):
            if ":" not in chunk:
                continue
            key, value = chunk.split(":", 1)
            key, value = _key(key), value.strip()
            if not key:
                continue
            if section in {"rx", "tx"}:
                number = _to_int(value)
                if number is not None:
                    getattr(detail, section)[_counter_key(key)] = number
                    continue
            pairs.setdefault(key, value)

    detail.oper_status = null_if_empty(pairs.get("operational status"))
    if detail.oper_status:
        detail.oper_status = detail.oper_status.lower()
    detail.speed_mbps = _to_int(pairs.get("bandwidth (megabits)"))
    detail.duplex = null_if_empty(pairs.get("duplex"))
    detail.autonegotiation = null_if_empty(pairs.get("autonegotiation"))
    detail.interface_type = null_if_empty(pairs.get("interface type") or pairs.get("type"))
    detail.transceiver = null_if_empty(pairs.get("sfp/xfp"))
    detail.port_mac = null_if_empty(pairs.get("mac address"))
    detail.last_link_change = null_if_empty(pairs.get("last time link changed"))
    detail.status_changes = _to_int(pairs.get("number of status change"))
    reason = null_if_empty(pairs.get("port-down/violation reason"))
    detail.down_reason = None if reason and reason.lower() == "none" else reason
    return detail


_ALIAS = re.compile(r'"([^"]*)"\s*$')


def parse_port_admin(output: str, port: str) -> dict[str, str | None]:
    """Extract admin status, link status and alias for ``port`` from the alias/port table."""
    for line in lines(output):
        normalized = normalize_interface(line)
        tokens = normalized.split()
        if len(tokens) < 3 or tokens[0].strip("*") != port:
            continue
        alias_match = _ALIAS.search(normalized)
        return {
            "admin_status": _status(tokens[1]),
            "link_status": (null_if_empty(tokens[2]) or "").lower() or None,
            "alias": null_if_empty(alias_match.group(1)) if alias_match else None,
        }
    return {"admin_status": None, "link_status": None, "alias": None}
