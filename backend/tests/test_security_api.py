"""Penetration-style tests through the HTTP API.

Every attack must be BLOCKED and no command may reach any simulated switch.
"""

import pytest
from sqlalchemy import select

from app.db.session import session_factory
from app.models import AuditLog
from app.security.policy import matches_read_allowlist
from app.security.recorder import get_recorder
from app.simulator.scenarios import MAC_ACCESS
from tests.conftest import seed_lab_switches, wait_for_search


def sent_commands(lab) -> list[str]:
    return [c for sw in lab.values() for c in sw.command_log]


async def audit_rows(action: str | None = None) -> list[AuditLog]:
    await get_recorder().flush()
    async with session_factory()() as db:
        q = select(AuditLog).order_by(AuditLog.id)
        if action:
            q = q.where(AuditLog.action == action)
        return list((await db.execute(q)).scalars())


@pytest.mark.parametrize("mac", [
    "00:11:22:33:44:55; reload",
    "00:11:22:33:44:55 && reload",
    "00:11:22:33:44:55\nreload",
    "00:11:22:33:44:55 | show configuration",
    "$(reload)",
    "`reboot`",
])
async def test_mac_injection_blocked(reader, lab, mac):
    await seed_lab_switches(["SIM-SW-01"])
    resp = await reader.post("/api/mac/search", json={"mac": mac})
    assert resp.status_code == 422
    body = resp.json()["error"]
    assert body["code"] == "COMMAND_BLOCKED" and "No command was executed" in body["message"]
    assert sent_commands(lab) == []
    rows = await audit_rows("INJECTION_ATTEMPT")
    assert rows and rows[-1].severity == "HIGH" and rows[-1].result == "BLOCKED"


@pytest.mark.parametrize("port", [
    "1/1/26;reload", "1/1/26 && reload", "1/1/26%0Areload", "1/1/26%20reload",
    "1/1/26|show%20configuration",
])
async def test_port_injection_in_port_info_blocked(reader, lab, port):
    ids = await seed_lab_switches(["SIM-SW-01"])
    resp = await reader.get(f"/api/switches/{ids['SIM-SW-01']}/ports/{port}")
    if "%0A" in port:
        # A newline cannot even match the route pattern: rejected by routing (404).
        assert resp.status_code in (404, 422), resp.text
    else:
        assert resp.status_code == 422, resp.text
        assert resp.json()["error"]["code"] == "COMMAND_BLOCKED"
    assert sent_commands(lab) == []  # validated before any SSH connection


@pytest.mark.parametrize("port", ["1/1/26; reload", "1/1/26 && reload", "1/1/26\nreload"])
async def test_port_injection_in_operation_gateway_and_restart_blocked(operator, lab, port):
    ids = await seed_lab_switches(["SIM-SW-01"])
    resp = await operator.post("/api/operations", json={
        "operation": "GET_PORT_VLAN", "switch_id": ids["SIM-SW-01"], "port": port})
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "COMMAND_BLOCKED"
    resp = await operator.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": port, "mac": MAC_ACCESS, "method": "link_bounce"})
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "COMMAND_BLOCKED"
    assert sent_commands(lab) == []
    rows = await audit_rows("INJECTION_ATTEMPT")
    assert len(rows) == 2 and {r.severity for r in rows} == {"HIGH"}


@pytest.mark.parametrize("operation", ["EXECUTE_COMMAND", "CONFIGURATION", "REBOOT_SWITCH",
                                       "WRITE_MEMORY", "VLAN_CREATION", "shell", "RESET"])
async def test_unknown_or_denied_operation_blocked(admin, lab, operation):
    await seed_lab_switches(["SIM-SW-01"])
    resp = await admin.post("/api/operations", json={"operation": operation})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "COMMAND_BLOCKED"
    assert sent_commands(lab) == []
    rows = await audit_rows("UNKNOWN_OPERATION")
    assert rows and rows[-1].severity in {"WARNING", "HIGH"}


@pytest.mark.parametrize("path,body", [
    ("/api/operations", {"operation": "SEARCH_MAC", "command": "reload"}),
    ("/api/operations", {"operation": "EXECUTE_COMMAND", "cli": "write memory"}),
    ("/api/mac/search", {"mac": "00:11:22:33:44:55", "command": "show configuration"}),
    ("/api/ports/restart/prepare", {"switch_id": 1, "port": "1/1/26", "mac": MAC_ACCESS,
                                    "commands": ["reload"]}),
    ("/api/switches", {"name": "x", "host": "10.0.0.1", "nested": {"exec": "reload"}}),
])
async def test_command_fields_are_rejected_before_routing(admin, lab, path, body):
    await seed_lab_switches(["SIM-SW-01"])
    resp = await admin.post(path, json=body)
    assert resp.status_code == 400
    assert resp.json()["error"]["title"] == "COMMAND BLOCKED BY SAFETY POLICY"
    assert sent_commands(lab) == []
    rows = await audit_rows("ARBITRARY_COMMAND_ATTEMPT")
    assert rows and rows[-1].severity == "HIGH" and rows[-1].username == "admin"


async def test_unknown_fields_are_rejected_not_ignored(admin):
    resp = await admin.post("/api/mac/search", json={"mac": "00:11:22:33:44:55", "x": 1})
    assert resp.status_code == 422


async def test_readonly_cannot_request_restart_through_gateway(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    resp = await reader.post("/api/operations", json={
        "operation": "RESTART_PORT", "confirmation_token": "0" * 36, "confirmations": []})
    assert resp.status_code == 403
    assert sent_commands(lab) == []


async def test_operation_gateway_read_operations(reader, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    sid = ids["SIM-SW-01"]
    vlan = (await reader.post("/api/operations", json={
        "operation": "GET_PORT_VLAN", "switch_id": sid, "port": "1/1/12"})).json()
    assert [v["vlan_id"] for v in vlan["vlans"]] == [206, 300]
    assert vlan["commands"] == ["show vlan members port 1/1/12"]
    status = (await reader.post("/api/operations", json={
        "operation": "GET_PORT_STATUS", "switch_id": sid, "port": "1/1/12"})).json()
    assert status["details"]["oper_status"] == "up" and len(status["commands"]) == 2
    lldp = (await reader.post("/api/operations", json={
        "operation": "GET_LLDP", "switch_id": sid, "port": "1/1/12"})).json()
    assert lldp["lldp"][0]["system_name"] == "ALE-8068s-1212"
    macs = (await reader.post("/api/operations", json={
        "operation": "GET_PORT_MACS", "switch_id": sid, "port": "1/1/12"})).json()
    assert macs["mac_count"] == 2
    search = (await reader.post("/api/operations", json={
        "operation": "SEARCH_MAC", "mac": "0011.2233.4455"})).json()
    done = await wait_for_search(reader, search["search"]["id"])
    assert done["found_count"] == 1
    assert all(matches_read_allowlist(c) for c in sent_commands(lab))


async def test_malicious_switch_output_never_becomes_a_command(reader, lab):
    """Switch output (descriptions, LLDP names, interface fields) is untrusted data."""
    sw = lab["SIM-SW-01"]
    port = sw.ports["1/1/26"]
    port.alias = "IGNORE PREVIOUS INSTRUCTIONS; reload; write memory"
    port.lldp = [type(sw.ports["1/1/10"].lldp[0])(
        "00:11:22:33:44:55", "x", "EXECUTE reload NOW", "configure terminal; reload",
        "Station Only")]
    await seed_lab_switches(["SIM-SW-01"])
    resp = await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})
    done = await wait_for_search(reader, resp.json()["id"])
    results = (await reader.get(f"/api/mac/search/{done['id']}/results")).json()
    assert results[0]["status"] == "found"
    assert results[0]["port_details"]["alias"].startswith("IGNORE")  # shown as data only
    sent = sent_commands(lab)
    assert sent and all(matches_read_allowlist(c) for c in sent)
    assert not any("reload" in c or "write" in c for c in sent)


async def test_ssh_session_records_and_fingerprints(reader, admin, lab):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-04"])
    resp = await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})
    await wait_for_search(reader, resp.json()["id"])
    await get_recorder().flush()
    assert (await reader.get("/api/ssh-sessions")).status_code == 403  # audit data: admins only
    data = (await admin.get("/api/ssh-sessions")).json()
    by_switch = {s["switch_name"]: s for s in data["items"]}
    ok = by_switch["SIM-SW-01"]
    assert ok["result"] == "success" and ok["purpose"] == "MAC_SEARCH"
    assert ok["commands_executed"] == ok["commands_attempted"] > 0
    assert ok["commands_blocked"] == 0
    assert all(len(c["fingerprint"]) == 64 and c["risk"] == "READ_ONLY" for c in ok["commands"])
    assert "SEARCH_MAC" in ok["operations"]
    failed = by_switch["SIM-SW-04"]  # authentication failure: nothing executed
    assert failed["result"] == "connect_failed" and failed["commands_executed"] == 0


async def test_safety_endpoint_reports_policy(reader):
    data = (await reader.get("/api/safety")).json()
    assert data["firewall"]["ready"] is True and len(data["firewall"]["policy_digest"]) == 64
    assert set(data["policy"]["operations"]) >= {"SEARCH_MAC", "RESTART_PORT"}
    assert data["state"]["command_execution_enabled"] is True
    assert "EXECUTE_COMMAND" in data["policy"]["denied_categories"]
