"""Confidence-based access/trunk classification of the port a MAC was learned on.

The engine is deliberately conservative. It weighs independent pieces of evidence and never
decides "trunk" from VLAN count alone:

* Definitive: port declared as an uplink in inventory, or MAC learned on a link aggregate.
* VLAN membership: tagged vs untagged, protocol-learned (MVRP/GVRP/SPB) memberships.
  VLAN 1 as the untagged/default VLAN is never counted as trunk evidence on its own.
* LLDP neighbor capabilities: Bridge/Router (another switch) vs Telephone/Station (endpoint).
* Number of MACs learned on the port.
* Link speed (10G+ is typical of uplinks) and interface description keywords.
* Topology (inventory): an LLDP neighbor that is itself a managed switch in the inventory is
  definitive inter-switch evidence; ports of switches whose inventory role is core or
  distribution are reported as infrastructure (the restart policy blocks them).

Output categories, each with a confidence label (High/Medium/Low), a numeric confidence (0-1)
and the list of reasons:

* evidence-based: ACCESS, LIKELY_ACCESS, LIKELY_TRUNK, TRUNK, UNKNOWN — a LIKELY_* result with
  Low confidence is reported as UNKNOWN (insufficient confidence is never a restart candidate);
* definitive / role-based, which override the evidence: UPLINK (declared in the inventory),
  LAG (MAC learned on a link aggregate — "aggregation"), STACK and MANAGEMENT (port description),
  CORE and DISTRIBUTION (the switch's inventory role).

Only ACCESS and LIKELY_ACCESS are ever restart candidates (restart_policy.py decides further).
"""

from __future__ import annotations

import enum
import re
from dataclasses import asdict, dataclass, field

from app.parsers.alcatel.lldp import LldpNeighbor
from app.parsers.alcatel.vlan_port import VlanMembership


class PortClass(str, enum.Enum):
    ACCESS = "ACCESS"
    LIKELY_ACCESS = "LIKELY_ACCESS"
    UNKNOWN = "UNKNOWN"
    LIKELY_TRUNK = "LIKELY_TRUNK"
    TRUNK = "TRUNK"
    UPLINK = "UPLINK"
    LAG = "LAG"
    CORE = "CORE"
    DISTRIBUTION = "DISTRIBUTION"
    MANAGEMENT = "MANAGEMENT"
    STACK = "STACK"


TRUNKISH = {PortClass.LIKELY_TRUNK, PortClass.TRUNK}
RESTART_CANDIDATES = {PortClass.ACCESS, PortClass.LIKELY_ACCESS}
# Never restarted by anyone (no override): identified as structural links of the network.
HARD_BLOCKED = {PortClass.UPLINK, PortClass.LAG, PortClass.MANAGEMENT, PortClass.STACK,
                PortClass.UNKNOWN}
RISK_ORDER = {
    PortClass.ACCESS: 0,
    PortClass.LIKELY_ACCESS: 1,
    PortClass.UNKNOWN: 2,
    PortClass.LIKELY_TRUNK: 3,
    PortClass.TRUNK: 4,
    PortClass.DISTRIBUTION: 5,
    PortClass.CORE: 5,
    PortClass.MANAGEMENT: 6,
    PortClass.STACK: 6,
    PortClass.LAG: 6,
    PortClass.UPLINK: 6,
}

_UPLINK_WORDS = re.compile(
    r"(?i)\b(uplink|up-link|trunk|core|distribution|dist|backbone|isl|lag|inter-?switch|"
    r"to[-_ ]?(?:sw|switch|core|dist))\b"
)
_MANAGEMENT_WORDS = re.compile(r"(?i)\b(mgmt|management|oob|out-of-band)\b")
_STACK_WORDS = re.compile(r"(?i)\b(stack|stacking|vfl|virtual[- ]chassis)\b")


@dataclass
class Reason:
    indicates: str  # "trunk" | "access" | "neutral"
    text: str
    weight: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ClassificationInput:
    port: str | None
    is_linkagg: bool = False
    linkagg_id: int | None = None
    declared_uplink: bool = False
    vlans: list[VlanMembership] | None = None  # None = could not be read
    lldp: list[LldpNeighbor] | None = None      # None = not queried / failed
    mac_count: int | None = None
    speed_mbps: int | None = None
    alias: str | None = None
    switch_role: str = ""                        # inventory role: access/distribution/core/...
    known_switches: frozenset[str] = frozenset()  # lower-case names/IPs of inventory switches


@dataclass
class Classification:
    category: PortClass
    confidence: str
    confidence_score: float
    trunk_score: float
    access_score: float
    reasons: list[Reason] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "confidence": self.confidence,
            "confidence_score": round(self.confidence_score, 2),
            "trunk_score": self.trunk_score,
            "access_score": self.access_score,
            "reasons": [r.to_dict() for r in self.reasons],
        }


def _definitive(category: PortClass, text: str) -> Classification:
    return Classification(category, "High", 0.99, 10.0, 0.0, [Reason("trunk", text, 10.0)])


def classify_port(data: ClassificationInput) -> Classification:
    if data.declared_uplink:
        return _definitive(PortClass.UPLINK, "Port is declared as an uplink in the switch "
                                             "inventory.")
    if data.is_linkagg:
        return _definitive(
            PortClass.LAG,
            f"MAC is learned on link aggregate {data.linkagg_id} (a bundle of links, "
            "typically an uplink between switches).",
        )
    evidence = _classify_evidence(data)
    if data.alias and _STACK_WORDS.search(data.alias):
        return _override(PortClass.STACK, f"Interface description '{data.alias}' marks a "
                         "stacking / virtual-chassis link.", evidence)
    if data.alias and _MANAGEMENT_WORDS.search(data.alias):
        return _override(PortClass.MANAGEMENT, f"Interface description '{data.alias}' marks "
                         "a management / out-of-band connection.", evidence)
    role = (data.switch_role or "").lower()
    if role in {"core", "distribution"}:
        return _override(PortClass.CORE if role == "core" else PortClass.DISTRIBUTION,
                         f"The switch is a {role} switch (inventory topology role); its ports "
                         "are network infrastructure.", evidence)
    return evidence


def _override(category: PortClass, text: str, evidence: Classification) -> Classification:
    """Definitive category from inventory / description; the evidence is kept as reasons."""
    reasons = [Reason("trunk", text, 10.0),
               Reason("neutral", f"Evidence alone: {evidence.category.value} "
                      f"({evidence.confidence} confidence)."), *evidence.reasons]
    return Classification(category, "High", 0.99, evidence.trunk_score, evidence.access_score,
                          reasons)


def _voice_vlan_pattern(data: ClassificationInput) -> bool:
    """IP phone + PC: exactly one LLDP neighbor, which is a telephone (phones also advertise
    Bridge for their PC port), at most 3 learned MACs. The single tagged VLAN is then the voice
    VLAN, not trunk evidence."""
    if not data.lldp or len(data.lldp) != 1 or data.mac_count is None or data.mac_count > 3:
        return False
    caps = set(data.lldp[0].capabilities)
    return "Telephone" in caps and "WLAN AP" not in caps and "Router" not in caps


def _classify_evidence(data: ClassificationInput) -> Classification:

    reasons: list[Reason] = []
    trunk = 0.0
    access = 0.0
    strong_trunk = False

    def add(indicates: str, text: str, weight: float = 0.0) -> None:
        nonlocal trunk, access
        reasons.append(Reason(indicates, text, weight))
        if indicates == "trunk":
            trunk += weight
        elif indicates == "access":
            access += weight

    # --- VLAN membership ----------------------------------------------------------------------
    n_tagged = 0
    if data.vlans is None:
        add("neutral", "VLAN membership of the port could not be read.")
    elif not data.vlans:
        add("neutral", "No VLAN membership was reported for the port.")
    else:
        tagged = [v for v in data.vlans if v.tagged is True]
        untagged = [v for v in data.vlans if v.tagged is False]
        protocol = [v for v in data.vlans if v.mode in {"dynamic", "spb"}]
        n_tagged = len(tagged)
        add("neutral", f"Port has {len(data.vlans)} VLAN membership(s): "
            f"{len(tagged)} tagged, {len(untagged)} untagged.")
        if protocol:
            strong_trunk = True
            add("trunk", f"{len(protocol)} VLAN(s) learned via MVRP/GVRP/SPB "
                "(inter-switch protocols).", 3.0)
        if n_tagged == 0:
            add("access", "No tagged VLANs on the port.", 3.0)
            if len(untagged) == 1:
                vid = untagged[0].vlan_id
                add("access", f"Single untagged VLAN ({vid}).", 1.0)
                if vid == 1:
                    add("neutral", "The only VLAN is VLAN 1 (default VLAN); this is common on "
                        "unconfigured access ports and is not trunk evidence.")
        elif n_tagged == 1 and not protocol and _voice_vlan_pattern(data):
            add("access", f"1 tagged VLAN ({tagged[0].vlan_id}) with an IP phone as the only "
                "LLDP neighbor and at most 3 MACs: voice VLAN pattern (IP phone + PC).", 1.5)
        elif n_tagged == 1:
            add("trunk", f"1 tagged VLAN ({tagged[0].vlan_id}); consistent with a voice VLAN "
                "(IP phone + PC) or a small trunk.", 1.0)
        elif n_tagged <= 3:
            add("trunk", f"{n_tagged} tagged VLANs.", 2.5)
        else:
            add("trunk", f"{n_tagged} tagged VLANs.", 4.0)
        if any(v.vlan_id == 1 and v.tagged is False for v in data.vlans) and n_tagged:
            add("neutral", "VLAN 1 is the untagged/default VLAN; on its own this does not "
                "indicate a trunk.")
        if any(v.mode in {"unp_untagged", "unp_tagged"} for v in data.vlans):
            add("access", "VLAN assigned dynamically by UNP (user network profile, an "
                "access-port feature).", 1.0)
        if any(v.mode == "mobile" for v in data.vlans):
            add("access", "Mobile (rule-based) VLAN assignment, an access-port feature.", 1.0)

    # --- LLDP ---------------------------------------------------------------------------------
    if data.lldp is None:
        add("neutral", "LLDP information not available.")
    elif not data.lldp:
        add("access", "No LLDP neighbor detected (switches normally advertise LLDP; many "
            "endpoints do not).", 0.5)
    else:
        caps: set[str] = set()
        for nb in data.lldp:
            caps.update(nb.capabilities)
        names = ", ".join(n.system_name or n.chassis_id or "?" for n in data.lldp)
        if len(data.lldp) > 1:
            add("trunk", f"{len(data.lldp)} LLDP neighbors on one port ({names}); possibly a "
                "downstream unmanaged switch or hub.", 1.0)
        if caps & {"Bridge", "Router"} and not caps & {"Telephone", "WLAN AP"}:
            strong_trunk = True
            add("trunk", f"LLDP neighbor {names} advertises "
                f"{'/'.join(sorted(caps & {'Bridge', 'Router'}))} capability (another switch "
                "or router).", 4.0)
        if "Telephone" in caps:
            add("access", f"LLDP neighbor {names} is an IP phone (phone + PC access pattern).",
                1.5)
        if "WLAN AP" in caps:
            add("trunk", f"LLDP neighbor {names} is a wireless access point; restarting it "
                "disconnects all of its wireless clients.", 2.0)
        if "Station" in caps and not caps - {"Station"}:
            add("access", f"LLDP neighbor {names} is an end station.", 1.5)
        known = [n for n in data.lldp if data.known_switches and {
            (n.system_name or "").lower(), (n.management_ip or "").lower()
        } & data.known_switches]
        if known:
            strong_trunk = True
            add("trunk", "LLDP neighbor " + ", ".join(n.system_name or n.management_ip or "?"
                                                       for n in known)
                + " is a managed switch in the inventory (inter-switch link).", 5.0)

    # --- MAC count ----------------------------------------------------------------------------
    if data.mac_count is not None:
        n = data.mac_count
        if n <= 1:
            add("access", "Only one MAC address is learned on the port.", 1.5)
        elif n <= 3:
            add("access", f"{n} MAC addresses learned (e.g. IP phone + PC).", 0.5)
        elif n <= 9:
            add("trunk", f"{n} MAC addresses learned (downstream switch, AP or "
                "virtualization host?).", 1.0)
        else:
            add("trunk", f"{n} MAC addresses learned on the port.", 2.5)

    # --- Speed / description ------------------------------------------------------------------
    if data.speed_mbps and data.speed_mbps >= 10000:
        add("trunk", f"{data.speed_mbps // 1000}G link, typical of uplinks.", 1.5)
    if data.alias and _UPLINK_WORDS.search(data.alias):
        add("trunk", f"Interface description '{data.alias}' suggests an uplink.", 2.0)

    # --- Decision -----------------------------------------------------------------------------
    diff = trunk - access
    if data.vlans is None and not strong_trunk:
        category = PortClass.UNKNOWN
    elif strong_trunk and n_tagged >= 1 and diff >= 3:
        category = PortClass.TRUNK
    elif diff >= 2:
        category = PortClass.LIKELY_TRUNK
    elif access >= 4 and trunk == 0:
        category = PortClass.ACCESS
    elif diff <= -1:
        category = PortClass.LIKELY_ACCESS
    else:
        category = PortClass.UNKNOWN

    magnitude = abs(diff)
    if category is PortClass.UNKNOWN:
        confidence, score = "Low", 0.3
    elif category is PortClass.ACCESS:
        confidence = "High" if access >= 5 else "Medium"
        score = min(0.97, 0.7 + access * 0.04)
    elif category is PortClass.TRUNK:
        confidence, score = "High", min(0.97, 0.8 + magnitude * 0.02)
    else:
        confidence = "High" if magnitude >= 5 else "Medium" if magnitude >= 3 else "Low"
        score = min(0.95, 0.5 + magnitude * 0.07)
        if confidence == "Low":
            add("neutral", f"Evidence leans {category.value} but the confidence is too low to "
                "decide: reported as UNKNOWN (never a restart candidate).")
            category = PortClass.UNKNOWN
    return Classification(category, confidence, score, round(trunk, 2), round(access, 2), reasons)
