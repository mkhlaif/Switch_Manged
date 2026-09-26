"""Lab topology used by lab mode (ENABLE_SIMULATOR=true) and the automated tests.

    SIM-SW-02 (OS6900, AOS 8.10)  distribution
      ├── 1/1/1  ⇄ SIM-SW-01 1/1/49 (10G trunk, LLDP)
      └── 0/5    ⇄ SIM-SW-03 0/1 (link aggregate)
    SIM-SW-01 (OS6860E-P24, AOS 8.9)  access
    SIM-SW-03 (OS6450-P24, AOS 6.7)   access, "more" pagination enabled
    SIM-SW-04 auth failure · SIM-SW-05 command hang · SIM-SW-06 command error ·
    SIM-SW-07 AOS 7 (no verified profile)

Interesting MACs:
    00:11:22:33:44:55  SIM-SW-01 1/1/26 (ACCESS, VLAN 206) + seen on SIM-SW-02 trunk 1/1/1
    aa:bb:cc:00:12:34  SIM-SW-03 1/12 (PC behind IP phone) + seen on SIM-SW-02 link agg 5
    00:aa:00:00:00:77  SIM-SW-01 1/1/10 (wireless client behind an AP → LIKELY TRUNK)
    00:1b:21:00:05:05  SIM-SW-01 1/1/5 (single PC, ACCESS)
    00:de:ad:be:ef:01  nowhere (not found)
"""

from __future__ import annotations

from app.simulator.model import SimBehavior, SimLinkAgg, SimLldp, SimPort, SimSwitch

SIM_USERNAME = "lab"
SIM_PASSWORD = "lab-password"

MAC_ACCESS = "001122334455"
MAC_PHONE_PC = "aabbcc001234"
MAC_WIFI = "00aa00000077"
MAC_SINGLE_PC = "001b21000505"
MAC_NOWHERE = "00deadbeef01"


def _m(prefix: str, n: int) -> str:
    return f"{prefix}{n:04x}"[-12:]


def build_lab(relearn_delay: float = 2.0) -> dict[str, SimSwitch]:
    wifi_clients = [(20, _m("f0d5bf00", i)) for i in range(1, 12)] + [(30, MAC_WIFI)]
    sw1_edge = [
        (206, MAC_SINGLE_PC), (206, MAC_ACCESS), (206, "001b21121212"), (300, "00809f121212"),
        (10, "34e70baa0010"), *wifi_clients,
    ]
    sw3_edge = [(10, MAC_PHONE_PC), (300, "00809faabbcc"), (10, "001b21000305")] + [
        (10, _m("00e04c00", i)) for i in range(1, 9)
    ]

    sw1 = SimSwitch(
        name="SIM-SW-01", family="AOS8", model="OS6860E-P24", version="8.9.221.R03",
        location="Building A / Floor 1", prompt="->",
        behavior=SimBehavior(relearn_delay=relearn_delay),
        ports={
            "1/1/5": SimPort("1/1/5", [(206, "untagged")], [(206, MAC_SINGLE_PC)],
                             alias="Room 101 PC"),
            "1/1/10": SimPort(
                "1/1/10", [(10, "untagged"), (20, "tagged"), (30, "tagged"), (40, "tagged")],
                [(10, "34e70baa0010"), *wifi_clients], alias="AP-B1F1-01", poe=True,
                powered_device=True,
                lldp=[SimLldp("34:e7:0b:aa:00:10", "34:e7:0b:aa:00:10", "AP1201H-B1F1",
                              "Alcatel-Lucent Enterprise OAW-AP1201H", "WLAN AP",
                              management_ip="10.10.0.21")],
            ),
            "1/1/12": SimPort(
                "1/1/12", [(206, "untagged"), (300, "tagged")],
                [(300, "00809f121212"), (206, "001b21121212")], alias="Desk 12 phone+PC",
                poe=True, powered_device=True,
                lldp=[SimLldp("00:80:9f:12:12:12", "00:80:9f:12:12:12", "ALE-8068s-1212",
                              "ALE-8068s Premium DeskPhone", "Bridge, Telephone",
                              management_ip="10.30.0.12")],
            ),
            "1/1/26": SimPort("1/1/26", [(206, "untagged")], [(206, MAC_ACCESS)],
                              alias="Room 204 PC", poe=True),
            "1/1/49": SimPort(
                "1/1/49",
                [(1, "untagged"), (10, "tagged"), (20, "tagged"), (30, "tagged"), (40, "tagged"),
                 (206, "tagged"), (300, "tagged"), (685, "tagged")],
                [(10, _m("00e04c10", i)) for i in range(1, 30)] + [(10, MAC_PHONE_PC)],
                alias="Uplink to SIM-SW-02", speed=10000,
                lldp=[SimLldp("e8:e7:32:bb:00:02", "1001", "SIM-SW-02",
                              "Alcatel-Lucent Enterprise OS6900-X20 8.10.94.R03 GA",
                              "Bridge Router", "Alcatel-Lucent Enterprise OS6900 GNI 1/1/1",
                              "10.99.0.2")],
            ),
        },
    )

    sw2 = SimSwitch(
        name="SIM-SW-02", family="AOS8", model="OS6900-X20", version="8.10.94.R03",
        location="Building A / MDF", prompt="SIM-SW-02 ->",
        behavior=SimBehavior(relearn_delay=relearn_delay),
        ports={
            "1/1/1": SimPort(
                "1/1/1",
                [(1, "untagged"), (10, "tagged"), (20, "tagged"), (30, "tagged"), (40, "tagged"),
                 (206, "tagged"), (300, "tagged"), (685, "tagged")],
                sw1_edge, alias="Downlink SIM-SW-01", speed=10000,
                lldp=[SimLldp("e8:e7:32:bb:00:01", "1049", "SIM-SW-01",
                              "Alcatel-Lucent Enterprise OS6860E-P24 8.9.221.R03 GA",
                              "Bridge Router", management_ip="10.99.0.1")],
            ),
            "1/1/7": SimPort("1/1/7", [(685, "untagged")], [(685, "00505600aa07")],
                             alias="Printer B-MDF"),
        },
        linkaggs={5: SimLinkAgg(5, [(1, "untagged"), (10, "tagged"), (300, "tagged")], sw3_edge)},
    )

    sw3 = SimSwitch(
        name="SIM-SW-03", family="AOS6", model="OS6450-P24", version="6.7.2.191.R08",
        location="Building B / Floor 2", prompt="SIM-SW-03 ->",
        behavior=SimBehavior(paginate_lines=12, relearn_delay=relearn_delay),
        ports={
            "1/5": SimPort("1/5", [(10, "default")], [(10, "001b21000305")], alias="Room 205"),
            "1/12": SimPort(
                "1/12", [(10, "default"), (300, "qtagged")],
                [(10, MAC_PHONE_PC), (300, "00809faabbcc")], alias="Desk 12", poe=True,
                powered_device=True,
                lldp=[SimLldp("00:80:9f:aa:bb:cc", "00:80:9f:aa:bb:cc", "ALE-8068s",
                              "ALE-8068s IP Phone", "Bridge, Telephone",
                              management_ip="10.30.0.45")],
            ),
            "1/20": SimPort("1/20", [(10, "default")],
                            [(10, _m("00e04c00", i)) for i in range(1, 9)], alias="Lab bench"),
        },
        linkaggs={1: SimLinkAgg(1, [(1, "default"), (10, "qtagged"), (300, "qtagged")],
                                [(206, MAC_ACCESS), (206, MAC_SINGLE_PC)] +
                                [(10, _m("00e04c20", i)) for i in range(1, 40)])},
    )

    failing = [
        SimSwitch(name="SIM-SW-04", family="AOS8", model="OS6560-P24Z8", version="8.8.152.R02",
                  location="Building C", behavior=SimBehavior(auth_fail=True)),
        SimSwitch(name="SIM-SW-05", family="AOS6", model="OS6450-24", version="6.7.2.191.R08",
                  location="Building C", behavior=SimBehavior(hang_on=("mac-address-table",))),
        SimSwitch(name="SIM-SW-06", family="AOS8", model="OS6465-P12", version="8.9.221.R03",
                  location="Building D", behavior=SimBehavior(error_on=("mac-learning",))),
        SimSwitch(name="SIM-SW-07", family="AOS7", model="OS10K", version="7.3.4.380.R02",
                  location="Data Center"),
    ]
    switches = {s.name: s for s in (sw1, sw2, sw3, *failing)}
    for sw in switches.values():
        sw.username, sw.password = SIM_USERNAME, SIM_PASSWORD
    return switches
