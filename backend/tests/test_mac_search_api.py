"""End-to-end MAC search against the simulated lab."""

import json

from app.simulator import session as sim_session
from app.simulator.scenarios import MAC_ACCESS, MAC_NOWHERE, MAC_PHONE_PC, MAC_SINGLE_PC
from tests.conftest import seed_lab_switches, wait_for_search

WRITE_WORDS = ("admin", "lanpower", "shutdown", "flush", "reload", "write", "clear")


async def _search(api, mac: str) -> tuple[dict, list[dict]]:
    resp = await api.post("/api/mac/search", json={"mac": mac})
    assert resp.status_code == 202, resp.text
    search = await wait_for_search(api, resp.json()["id"])
    results = (await api.get(f"/api/mac/search/{search['id']}/results")).json()
    return search, results


async def test_mac_found_on_access_port_with_full_details(reader):
    await seed_lab_switches(["SIM-SW-01"])
    search, results = await _search(reader, "0011.2233.4455")
    assert search["status"] == "completed" and search["found_count"] == 1
    r = results[0]
    assert (r["switch_name"], r["port"], r["vlan_id"]) == ("SIM-SW-01", "1/1/26", 206)
    assert r["classification"] == "ACCESS" and r["classification_confidence"] == "High"
    assert r["untagged_vlan"] == 206 and r["tagged_vlans"] == []
    assert r["port_details"]["oper_status"] == "up"
    assert r["port_details"]["alias"] == "Room 204 PC"
    assert r["mac_count_on_port"] == 1 and r["lldp"] == []
    assert r["profile_key"] == "AOS8"
    assert "show mac-learning mac-address 00:11:22:33:44:55" in r["commands_executed"]


async def test_multiple_locations_are_all_reported(reader):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02", "SIM-SW-03"])
    search, results = await _search(reader, "00:11:22:33:44:55")
    found = [r for r in results if r["status"] == "found"]
    assert {(r["switch_name"], r["port"] or r["interface_raw"]) for r in found} == {
        ("SIM-SW-01", "1/1/26"), ("SIM-SW-02", "1/1/1"), ("SIM-SW-03", "0/1")}
    classes = {r["switch_name"]: r["classification"] for r in found}
    assert classes == {"SIM-SW-01": "ACCESS", "SIM-SW-02": "TRUNK", "SIM-SW-03": "TRUNK"}
    summary = search["summary"]
    assert summary["multiple_locations"] and len(summary["multiple_location_reasons"]) >= 5
    assert summary["likely_edge"]["switch_name"] == "SIM-SW-01"
    assert search["found_count"] == 3


async def test_aos6_switch_with_unknown_version_is_detected(reader, lab):
    ids = await seed_lab_switches(["SIM-SW-03"], unknown_version=("SIM-SW-03",))
    search, results = await _search(reader, "aa-bb-cc-00-12-34")
    r = results[0]
    assert r["status"] == "found" and r["profile_key"] == "AOS6"
    assert r["commands_executed"][0] == "show system"
    assert (r["port"], r["vlan_id"], r["untagged_vlan"], r["tagged_vlans"]) == ("1/12", 10, 10,
                                                                                  [300])
    assert r["classification"] == "LIKELY_ACCESS"
    assert r["lldp"][0]["system_name"] == "ALE-8068s"
    sw = (await reader.get(f"/api/switches/{ids['SIM-SW-03']}")).json()
    assert sw["aos_version"] == "6.7.2.191.R08" and sw["effective_profile"] == "AOS6"


async def test_mac_not_found(reader):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    search, results = await _search(reader, MAC_NOWHERE)
    assert search["found_count"] == 0 and not search["summary"]["found"]
    assert {r["status"] for r in results} == {"not_found"}


async def test_failures_are_reported_per_switch(reader):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-04", "SIM-SW-05", "SIM-SW-06", "SIM-SW-07"])
    search, results = await _search(reader, MAC_ACCESS)
    status = {r["switch_name"]: r["status"] for r in results}
    assert status == {"SIM-SW-01": "found", "SIM-SW-04": "auth_failed", "SIM-SW-05": "timeout",
                      "SIM-SW-06": "command_failed", "SIM-SW-07": "unsupported"}
    assert search["found_count"] == 1 and search["timeout_count"] == 1
    assert search["failed_count"] == 3
    errors = {r["switch_name"]: r["error_message"] for r in results}
    assert "No configuration changes were made" in errors["SIM-SW-06"]
    assert "not verified" in errors["SIM-SW-07"]
    switches = {s["name"]: s for s in (await reader.get("/api/switches")).json()}
    assert switches["SIM-SW-04"]["status"] == "auth_failed"
    assert switches["SIM-SW-01"]["status"] == "online"


async def test_search_is_strictly_read_only(reader, lab):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02", "SIM-SW-03"])
    for mac in (MAC_ACCESS, MAC_PHONE_PC, MAC_NOWHERE):
        await _search(reader, mac)
    sent = [c for sw in lab.values() for c in sw.command_log]
    assert sent, "expected commands to be sent"
    assert all(c.startswith("show ") for c in sent), sent
    assert not any(w in c.split() for c in sent for w in WRITE_WORDS)
    # Nothing dumps whole tables: every MAC lookup is filtered by MAC.
    assert not any(c in ("show mac-learning", "show mac-address-table") for c in sent)


async def test_mac_move_detection(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    first, _ = await _search(reader, MAC_SINGLE_PC)
    assert first["summary"]["mac_move"] is None
    sw1 = lab["SIM-SW-01"]
    sw1.ports["1/1/5"].macs = []
    sw1.ports["1/1/26"].macs.append((206, MAC_SINGLE_PC))
    second, _ = await _search(reader, MAC_SINGLE_PC)
    move = second["summary"]["mac_move"]
    assert move["previous"]["port"] == "1/1/5" and move["current"]["port"] == "1/1/26"


async def test_sse_progress_stream(reader):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    resp = await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})
    search_id = resp.json()["id"]
    events = []
    async with reader.client.stream("GET", f"/api/mac/search/{search_id}/events") as stream:
        async for line in stream.aiter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
                if events[-1]["type"] == "done":
                    break
    types = [e["type"] for e in events]
    assert types[0] == "snapshot" and types[-1] == "done"
    if len(events) > 2:  # search still running when we subscribed
        assert "switch" in types and "progress" in types


async def test_search_history_and_export(reader):
    await seed_lab_switches(["SIM-SW-01"])
    await _search(reader, MAC_ACCESS)
    await _search(reader, MAC_NOWHERE)
    hist = (await reader.get("/api/search-history")).json()
    assert hist["total"] == 2
    top = {i["mac"]: i for i in hist["items"]}
    assert top["00:11:22:33:44:55"]["result"] == "FOUND"
    assert top["00:11:22:33:44:55"]["port"] == "1/1/26"
    assert top["00:de:ad:be:ef:01"]["result"] == "NOT_FOUND"
    only = (await reader.get("/api/search-history", params={"mac": "001122334455"})).json()
    assert only["total"] == 1
    csv_resp = await reader.get("/api/search-history/export")
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "00:11:22:33:44:55" in csv_resp.text and csv_resp.text.startswith("time,user,mac")


async def test_live_port_info_endpoint(reader):
    ids = await seed_lab_switches(["SIM-SW-01"])
    resp = await reader.get(f"/api/switches/{ids['SIM-SW-01']}/ports/1/1/49",
                            params={"mac": "00:e0:4c:10:00:01"})
    data = resp.json()
    assert resp.status_code == 200, resp.text
    assert data["classification"]["category"] == "TRUNK"
    assert data["mac_on_port"] is True and data["lldp"][0]["system_name"] == "SIM-SW-02"
    bad = await reader.get(f"/api/switches/{ids['SIM-SW-01']}/ports/1/26")
    assert bad.status_code == 422  # AOS 8 needs chassis/slot/port


async def test_disabled_switches_are_not_searched(admin, reader, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    await admin.patch(f"/api/switches/{ids['SIM-SW-02']}", json={"enabled": False})
    search, results = await _search(reader, MAC_ACCESS)
    assert {r["switch_name"] for r in results} == {"SIM-SW-01"}
    assert search["total_switches"] == 1
    assert lab["SIM-SW-02"].command_log == []


async def test_dashboard(reader):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-04"])
    await _search(reader, MAC_ACCESS)
    data = (await reader.get("/api/dashboard")).json()
    stats = data["stats"]
    assert stats["total_switches"] == 2 and stats["online"] == 1 and stats["offline"] == 1
    assert stats["searches_today"] == 1 and stats["macs_found_today"] == 1
    assert stats["failed_ssh_today"] == 1
    assert "8.9" in stats["aos_versions"]
    assert data["recent_searches"][0]["mac"] == "00:11:22:33:44:55"


def test_registry_reset_between_tests(lab):
    assert sim_session.registry()["SIM-SW-01"].command_log == []
