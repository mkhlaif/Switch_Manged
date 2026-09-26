"""Network path discovery (§17) — computed from data the search already collected.

No additional commands are sent. The path is derived from:

* the edge sighting (the access port the device is connected to);
* the sightings on inter-switch ports, whose LLDP neighbor names the next switch towards the
  device (a switch learns the MAC on the port facing the device);
* inventory topology roles (access / distribution / core).

Example result: ``Device → SW-ACCESS-01 1/1/24 → SW-DIST-01 1/1/49 → SW-CORE-01 1/1/1``.

The result is evidence, not a guess: every hop names the sighting and the LLDP neighbor that
links it. Sightings that cannot be chained are reported as ``unlinked`` rather than inserted.
"""

from __future__ import annotations

from dataclasses import dataclass

EDGE = {"ACCESS", "LIKELY_ACCESS"}


@dataclass
class Sighting:
    switch_name: str
    switch_host: str
    port: str
    interface: str
    classification: str
    vlan_id: int | None
    lldp_names: list[str]
    is_linkagg: bool


def _sightings(rows) -> list[Sighting]:
    out = []
    for r in rows:
        if getattr(r, "status", "") != "found":
            continue
        names = []
        for n in r.lldp or []:
            for key in ("system_name", "management_ip"):
                if n.get(key):
                    names.append(str(n[key]).lower())
        out.append(Sighting(r.switch_name, (r.switch_host or "").lower(), r.port or "",
                            r.interface_raw or r.port or "", r.classification or "UNKNOWN",
                            r.vlan_id, names, bool(r.is_linkagg)))
    return out


def build_path(rows, roles: dict[str, str] | None = None) -> dict:
    """Return ``{"status", "hops", "unlinked", "text", "notes"}``."""
    roles = roles or {}
    sightings = _sightings(rows)
    notes: list[str] = []
    if not sightings:
        return {"status": "NOT_FOUND", "hops": [], "unlinked": [], "text": "",
                "notes": ["The MAC was not found on any reachable switch."]}
    edges = [s for s in sightings if s.classification in EDGE and s.port and not s.is_linkagg]
    if len(edges) != 1:
        notes.append("No single access port was identified; the path cannot be anchored."
                     if not edges else f"The MAC is on {len(edges)} access-like ports; the path "
                     "is ambiguous.")
        return {"status": "AMBIGUOUS" if edges else "NO_EDGE", "hops": [],
                "unlinked": [_hop(s, roles) for s in sightings], "text": "", "notes": notes}

    edge = edges[0]
    hops = [_hop(edge, roles)]
    used = {id(edge)}
    current = {edge.switch_name.lower(), edge.switch_host}
    while True:
        nxt = [s for s in sightings if id(s) not in used and current & set(s.lldp_names)]
        if not nxt:
            break
        if len(nxt) > 1:
            notes.append(f"{len(nxt)} switches report {hops[-1]['switch_name']} as the LLDP "
                         "neighbor on the port where they learned the MAC; only the first is "
                         "shown (possible redundant uplinks).")
        s = nxt[0]
        used.add(id(s))
        hops.append({**_hop(s, roles), "towards": hops[-1]["switch_name"]})
        current = {s.switch_name.lower(), s.switch_host}
    unlinked = [_hop(s, roles) for s in sightings if id(s) not in used]
    if unlinked:
        notes.append("Some switches see the MAC but could not be linked by LLDP evidence "
                     "(LLDP not collected, disabled, or an unmanaged device in between).")
    text = "Device → " + " → ".join(f"{h['switch_name']} {h['interface']}" for h in hops)
    return {"status": "RESOLVED" if not unlinked else "PARTIAL", "hops": hops,
            "unlinked": unlinked, "text": text, "notes": notes}


def _hop(s: Sighting, roles: dict[str, str]) -> dict:
    return {"switch_name": s.switch_name, "interface": s.interface, "port": s.port,
            "classification": s.classification, "vlan_id": s.vlan_id,
            "role": roles.get(s.switch_name, "unknown")}
