from app.parsers.alcatel.lldp import LldpNeighbor
from app.parsers.alcatel.vlan_port import VlanMembership
from app.services.classification.engine import ClassificationInput, PortClass, classify_port


def v(vid, tagged, mode=None):
    return VlanMembership(vid, mode or ("tagged" if tagged else "untagged"), "", tagged,
                          "forwarding")


def nb(caps, name="x"):
    return LldpNeighbor(local_port="1/1/1", system_name=name, capabilities_enabled=caps)


def classify(**kw):
    return classify_port(ClassificationInput(port="1/1/1", **kw))


def test_single_untagged_vlan_endpoint_is_access_high():
    c = classify(vlans=[v(206, False)], lldp=[], mac_count=1, speed_mbps=1000)
    assert c.category is PortClass.ACCESS and c.confidence == "High"
    assert any("No tagged VLANs" in r.text for r in c.reasons)


def test_phone_plus_pc_is_likely_access_not_trunk():
    c = classify(vlans=[v(206, False), v(300, True)],
                 lldp=[nb(["Telephone", "Bridge"], "ALE-8068s")], mac_count=2)
    assert c.category is PortClass.LIKELY_ACCESS


def test_vlan1_plus_one_vlan_is_not_trunk():
    """Spec §9: VLAN 1 + VLAN 206 does NOT prove a trunk."""
    c = classify(vlans=[v(1, False), v(206, True)], lldp=[], mac_count=1)
    assert c.category not in (PortClass.TRUNK, PortClass.LIKELY_TRUNK)
    assert any("VLAN 1" in r.text for r in c.reasons)


def test_only_vlan1_is_access():
    c = classify(vlans=[v(1, False)], lldp=[], mac_count=1)
    assert c.category is PortClass.ACCESS


def test_many_tagged_vlans_without_lldp_is_likely_trunk():
    vlans = [v(1, False)] + [v(x, True) for x in (10, 206, 207, 209, 685)]
    c = classify(vlans=vlans, lldp=None, mac_count=None)
    assert c.category is PortClass.LIKELY_TRUNK


def test_tagged_vlans_with_bridge_neighbor_is_trunk():
    vlans = [v(1, False)] + [v(x, True) for x in range(10, 17)]
    c = classify(vlans=vlans, lldp=[nb(["Bridge", "Router"], "SW-02")], mac_count=40,
                 speed_mbps=10000)
    assert c.category is PortClass.TRUNK and c.confidence == "High"
    assert any("LLDP neighbor SW-02" in r.text for r in c.reasons)


def test_access_point_is_likely_trunk():
    vlans = [v(10, False), v(20, True), v(30, True), v(40, True)]
    c = classify(vlans=vlans, lldp=[nb(["WLAN AP"], "AP1")], mac_count=13)
    assert c.category is PortClass.LIKELY_TRUNK


def test_mvrp_dynamic_vlans_are_strong_trunk_evidence():
    c = classify(vlans=[v(1, False), v(10, True, "dynamic"), v(20, True, "dynamic")], lldp=[],
                 mac_count=None)
    assert c.category in (PortClass.TRUNK, PortClass.LIKELY_TRUNK)


def test_unknown_when_vlans_unavailable():
    c = classify(vlans=None, lldp=[], mac_count=1)
    assert c.category is PortClass.UNKNOWN and c.confidence == "Low"


def test_linkagg_and_declared_uplink_are_definitive():
    assert classify_port(ClassificationInput(port=None, is_linkagg=True, linkagg_id=5)
                         ).category is PortClass.LAG
    c = classify(declared_uplink=True, vlans=[v(206, False)], mac_count=1)
    assert c.category is PortClass.UPLINK and c.confidence_score > 0.9


def test_uplink_description_counts_as_evidence():
    c = classify(vlans=[v(1, False), v(10, True), v(20, True)], lldp=None,
                 alias="Uplink to core")
    assert c.category is PortClass.LIKELY_TRUNK


def test_untagged_port_with_many_macs_is_not_plain_access():
    # Evidence leans access, but 15 MACs (a downstream unmanaged switch?) leave the confidence
    # Low: reported as UNKNOWN, never a restart candidate.
    c = classify(vlans=[v(10, False)], lldp=[], mac_count=15)
    assert c.category is PortClass.UNKNOWN and c.confidence == "Low"
    assert any("15 MAC" in r.text for r in c.reasons)
    assert any("too low to decide" in r.text for r in c.reasons)


def test_phone_plus_pc_voice_vlan_pattern_is_medium_confidence_access():
    c = classify(vlans=[v(206, False), v(300, True)],
                 lldp=[nb(["Telephone", "Bridge"], "ALE-8068s")], mac_count=2)
    assert c.category is PortClass.LIKELY_ACCESS and c.confidence == "Medium"
    assert any("voice VLAN pattern" in r.text for r in c.reasons)
    # Not the pattern: a second LLDP neighbour, or too many MACs behind the phone.
    two = classify(vlans=[v(206, False), v(300, True)],
                   lldp=[nb(["Telephone", "Bridge"], "P1"), nb(["Bridge"], "SW")], mac_count=2)
    assert two.category is not PortClass.LIKELY_ACCESS or two.confidence == "Low"
    many = classify(vlans=[v(206, False), v(300, True)],
                    lldp=[nb(["Telephone", "Bridge"], "P1")], mac_count=6)
    assert not any("voice VLAN pattern" in r.text for r in many.reasons)


def test_role_and_description_categories_override_the_evidence():
    endpoint = {"vlans": [v(206, False)], "lldp": [], "mac_count": 1}
    assert classify(**endpoint).category is PortClass.ACCESS
    core = classify(**endpoint, switch_role="core")
    assert core.category is PortClass.CORE and core.confidence == "High"
    assert any("Evidence alone: ACCESS" in r.text for r in core.reasons)
    assert classify(**endpoint, switch_role="distribution").category is PortClass.DISTRIBUTION
    assert classify(**endpoint, alias="MGMT - OOB").category is PortClass.MANAGEMENT
    assert classify(**endpoint, alias="VFL stacking").category is PortClass.STACK
    assert classify(**endpoint, switch_role="access", alias="PC 204").category is         PortClass.ACCESS


def test_low_confidence_trunk_lean_is_unknown():
    # 1 tagged VLAN + 4 MACs, no LLDP data: leans trunk, not enough to say so.
    c = classify(vlans=[v(10, False), v(20, True)], lldp=None, mac_count=4)
    assert c.category is PortClass.UNKNOWN and c.confidence == "Low"
    assert any("leans LIKELY_TRUNK" in r.text for r in c.reasons)
