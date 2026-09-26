"""Parser tests against output copied from the ALE CLI reference guide examples."""

from app.parsers.alcatel.lldp import parse_capabilities, parse_lldp_remote
from app.parsers.alcatel.mac_table import count_macs, find_mac, parse_mac_table
from app.parsers.alcatel.port_status import parse_interface_detail, parse_port_admin
from app.parsers.alcatel.system import parse_show_system
from app.parsers.alcatel.vlan_port import parse_vlan_port, split_tagged
from app.parsers.common import clean_output
from tests.conftest import fixture_text


# ------------------------------------------------------------------------------ MAC tables ---
def test_aos8_mac_learning_guide_example():
    entries = parse_mac_table(fixture_text("aos8/show_mac_learning_guide.txt"))
    assert len(entries) == 7
    first = entries[0]
    assert (first.mac, first.vlan_id, first.port, first.mac_type, first.operation) == (
        "e8e73211d478", 10, "1/1/14", "dynamic", "bridging")
    spb = entries[2]
    assert spb.domain == "SPB" and spb.vlan_id is None and spb.service == "3899:3899"
    assert spb.linkagg_id == 99 and spb.port is None  # sap:0/99:99 -> link aggregate 99
    vxlan = entries[4]
    assert vxlan.port == "1/1/20A"  # breakout suffix kept
    evpn = entries[6]
    assert evpn.domain == "EVPN-VXLAN" and evpn.port == "1/1/3"


def test_aos8_linkagg_and_invalid_flag():
    entries = parse_mac_table(fixture_text("aos8/show_mac_learning_linkagg.txt"))
    assert entries[0].is_linkagg and entries[0].linkagg_id == 29 and entries[0].port is None
    assert entries[1].flags == "*" and not entries[1].valid
    assert entries[1].port == "1/1/3"
    assert count_macs(fixture_text("aos8/show_mac_learning_linkagg.txt")) == 1


def test_aos6_mac_address_table_guide_example_with_padded_port():
    entries = parse_mac_table(fixture_text("aos6/show_mac_address_table_guide.txt"))
    assert [e.port for e in entries] == ["8/1", "10/23", "1/3", "2/1", None]
    assert entries[0].mac_type == "learned" and entries[0].vlan_id == 1
    assert entries[3].operation == "bridging"  # blank protocol column tolerated
    assert entries[4].linkagg_id == 29


def test_find_mac_filters_exact_mac():
    text = fixture_text("aos6/show_mac_address_table_guide.txt")
    assert [e.port for e in find_mac(text, "00d0956a739a")] == ["10/23"]
    assert find_mac(text, "001122334455") == []


def test_not_found_and_malformed_output():
    empty = ("Legend: Mac Address: * = address not valid\n\n Vlan Mac Address Type Protocol "
             "Operation Interface\n------+----\n\nTotal number of Valid MAC addresses above = 0")
    assert parse_mac_table(empty) == []
    assert count_macs(empty) == 0
    garbage = "VLAN 2@@ 00:11:22:33:44\n\x00### ->x\nERROR something 00:11:22:33:44:55"
    entries = parse_mac_table(garbage)
    # The only complete MAC is followed by no interface column -> nothing usable, no crash.
    assert all(e.port is None for e in entries)


# ------------------------------------------------------------------------------ VLANs --------
def test_aos8_vlan_members():
    vlans = parse_vlan_port(fixture_text("aos8/show_vlan_members_port.txt"))
    modes = {v.vlan_id: (v.mode, v.tagged, v.status) for v in vlans}
    assert modes[1] == ("untagged", False, "forwarding")
    assert modes[2] == ("tagged", True, "forwarding")
    assert modes[5] == ("dynamic", True, "blocking")
    assert modes[20] == ("unp_untagged", False, "forwarding")  # "UNP Untagged" has a space
    assert modes[21] == ("unp_tagged", True, "forwarding")
    tagged, untagged = split_tagged(vlans)
    assert tagged == [2, 3, 5, 21] and untagged == 1


def test_aos6_vlan_port_types():
    vlans = parse_vlan_port(fixture_text("aos6/show_vlan_port.txt"))
    modes = {v.vlan_id: (v.mode, v.tagged) for v in vlans}
    assert modes[1] == ("untagged", False)   # "default"
    assert modes[2] == ("tagged", True)      # "qtagged"
    assert modes[7] == ("mobile", False)
    assert modes[8] == ("vstk_tagged", True)


# ------------------------------------------------------------------------------ Ports --------
def test_interface_detail():
    d = parse_interface_detail(fixture_text("aos8/show_interfaces_port.txt"))
    assert d.oper_status == "up"
    assert d.speed_mbps == 1000 and d.duplex == "Full"
    assert d.transceiver == "GBIC_SX" and d.interface_type == "Fiber"
    assert d.status_changes == 1 and d.down_reason is None
    assert d.last_link_change == "Mon Jan  5 17:09:30 2019"
    assert d.rx["error_frames"] == 3 and d.rx["crc_error_frames"] == 2
    assert d.rx_errors == 5 and d.tx_errors == 0
    assert d.rx["unicast_frames"] == 0 and d.tx["unicast_frames"] == 24992


def test_port_admin_aos8_alias_table():
    info = parse_port_admin(fixture_text("aos8/show_interfaces_port_alias.txt"), "1/1/2")
    assert info == {"admin_status": "disabled", "link_status": "down", "alias": None}


def test_port_admin_aos6_port_table():
    text = fixture_text("aos6/show_interfaces_port_table.txt")
    assert parse_port_admin(text, "1/26") == {"admin_status": "enabled", "link_status": "up",
                                               "alias": "Room 204 PC"}
    assert parse_port_admin(text, "1/99")["admin_status"] is None


# ------------------------------------------------------------------------------ LLDP ---------
def test_lldp_aos8_guide_example():
    nbs = parse_lldp_remote(fixture_text("aos8/show_lldp_remote.txt"))
    assert len(nbs) == 1
    nb = nbs[0]
    assert nb.local_port == "1/1/16" and nb.chassis_id == "e8:e7:32:a4:91:e9"
    assert nb.port_id == "1030" and nb.system_name is None
    assert nb.capabilities == ["Bridge", "Router"]


def test_lldp_aos8_two_agents_phone_and_pc():
    nbs = parse_lldp_remote(fixture_text("aos8/show_lldp_remote_two_agents.txt"))
    assert [n.system_name for n in nbs] == ["ALE-8068s", "PC-204"]
    assert nbs[0].capabilities_enabled == ["Telephone"]
    assert nbs[0].capabilities_supported == ["Telephone", "Bridge"]
    assert nbs[0].management_ip == "10.30.0.12"
    assert nbs[1].capabilities == ["Station"]


def test_lldp_aos6_guide_example():
    nbs = parse_lldp_remote(fixture_text("aos6/show_lldp_remote.txt"))
    assert len(nbs) == 1
    assert nbs[0].local_port == "2/47" and nbs[0].chassis_id == "00:d0:95:e9:c9:2e"
    assert nbs[0].port_id == "2048" and nbs[0].capabilities == []


def test_capability_parsing():
    assert parse_capabilities("none supported") == []
    assert parse_capabilities("WLAN Access Point, Bridge") == ["WLAN AP", "Bridge"]


def test_no_lldp_output():
    assert parse_lldp_remote("") == []


# ------------------------------------------------------------------------------ System -------
def test_show_system_aos8_wrapped_description():
    info = parse_show_system(fixture_text("aos8/show_system.txt"))
    assert info.model == "OS6900-X40" and info.version == "8.3.1.313.R01" and info.major == 8
    assert info.name is None and info.location == "Unknown"


def test_show_system_aos6():
    info = parse_show_system(fixture_text("aos6/show_system.txt"))
    assert info.model == "OS6250-24" and info.version == "6.6.2.63.R02" and info.major == 6
    assert info.name == "OmniSwitch 6250"


def test_show_system_newer_version_formats():
    for desc, model, version in [
        ("Alcatel-Lucent Enterprise OS6860E-P24 8.7.354.R01 GA, June 1, 2021.,", "OS6860E-P24",
         "8.7.354.R01"),
        ("Alcatel-Lucent Enterprise OS6560-P48Z16 8.10.94.R03 GA, x.,", "OS6560-P48Z16",
         "8.10.94.R03"),
    ]:
        info = parse_show_system(f"System:\n  Description:  {desc}\n  Name: sw,\n")
        assert (info.model, info.version) == (model, version)


def test_clean_output_handles_pager_and_ansi():
    raw = "line1\r\nMore? [next screen <sp>, next line <cr>, filter pattern </>, quit </>]" \
          "\x1b[2K\rline2\r\nabc\b\bXY\n"
    assert clean_output(raw) == "line1\nline2\naXY\n"
