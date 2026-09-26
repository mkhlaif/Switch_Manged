"""Platform features: search modes, path discovery, alerts, circuit breaker, topology,
NetBox / Zabbix (read-only, mocked HTTP), user management, lab verification, audit immutability.
"""

import json

import httpx
import pytest
from sqlalchemy import select, update

from app.db.session import session_factory
from app.models import AuditLog, Switch
from app.security.circuit_breaker import get_breaker
from app.security.recorder import get_recorder
from app.services.integrations.netbox import (
    IntegrationError,
    NetBoxClient,
    compare_device,
    compare_interface,
)
from app.services.integrations.zabbix import ZabbixClient
from app.simulator.scenarios import MAC_ACCESS, MAC_NOWHERE
from tests.conftest import seed_lab_switches, wait_for_search


async def search(api, mac, **extra):
    resp = await api.post("/api/mac/search", json={"mac": mac, **extra})
    assert resp.status_code == 202, resp.text
    return await wait_for_search(api, resp.json()["id"])


async def results(api, search_id):
    return (await api.get(f"/api/mac/search/{search_id}/results")).json()


def sent(lab, name):
    return [c for c in lab[name].command_log]


# ----------------------------------------------------------------------- search modes ---
async def test_fast_mode_runs_only_the_lookup(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    done = await search(reader, MAC_ACCESS, mode="FAST")
    assert done["mode"] == "FAST" and done["found_count"] == 1
    assert sent(lab, "SIM-SW-01") == ["show mac-learning mac-address 00:11:22:33:44:55"]
    row = (await results(reader, done["id"]))[0]
    assert row["classification"] == "UNKNOWN"
    assert "FAST mode" in row["classification_reasons"][0]["text"]


async def test_standard_mode_analyses_the_port(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    done = await search(reader, MAC_ACCESS)
    assert done["mode"] == "STANDARD"
    row = (await results(reader, done["id"]))[0]
    assert row["classification"] == "ACCESS" and row["mac_count_on_port"] == 1
    assert "mac_distribution" not in row["port_details"]


async def test_deep_mode_requires_a_small_explicit_selection(reader, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    resp = await reader.post("/api/mac/search", json={"mac": MAC_ACCESS, "mode": "DEEP"})
    assert resp.status_code == 422 and "never run against the whole network" in resp.text
    too_many = await reader.post("/api/mac/search", json={
        "mac": MAC_ACCESS, "mode": "DEEP", "switch_ids": list(range(1, 8))})
    assert too_many.status_code == 422
    done = await search(reader, MAC_ACCESS, mode="DEEP", switch_ids=[ids["SIM-SW-01"]])
    row = (await results(reader, done["id"]))[0]
    assert row["port_details"]["mac_distribution"] == [
        {"mac": MAC_ACCESS, "vlan_id": 206, "type": row["port_details"]["mac_distribution"][0][
            "type"]}]
    assert (await reader.post("/api/mac/search", json={"mac": MAC_ACCESS, "mode": "TURBO"})
            ).status_code == 422


# --------------------------------------------------------------------- path discovery ---
async def test_path_discovery_from_evidence(reader, lab):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"], roles={"SIM-SW-02": "distribution",
                                                                "SIM-SW-01": "access"})
    done = await search(reader, MAC_ACCESS)
    path = (await reader.get(f"/api/mac/search/{done['id']}/path")).json()
    assert path["status"] == "RESOLVED"
    assert path["text"] == "Device → SIM-SW-01 1/1/26 → SIM-SW-02 1/1/1"
    assert [h["role"] for h in path["hops"]] == ["access", "distribution"]
    assert done["summary"]["path"]["text"] == path["text"]
    before = len(sent(lab, "SIM-SW-01"))
    await reader.get(f"/api/mac/search/{done['id']}/path")
    assert len(sent(lab, "SIM-SW-01")) == before  # no commands for path discovery


async def test_path_not_found(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    done = await search(reader, MAC_NOWHERE)
    path = (await reader.get(f"/api/mac/search/{done['id']}/path")).json()
    assert path["status"] == "NOT_FOUND" and path["hops"] == []


# ------------------------------------------------------------------ topology awareness ---
async def test_lldp_neighbor_in_inventory_is_trunk_evidence(reader, lab):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    done = await search(reader, "aabbcc001234")  # also seen on SIM-SW-01 uplink 1/1/49
    rows = {(r["switch_name"], r["port"]): r for r in await results(reader, done["id"])}
    uplink = rows[("SIM-SW-01", "1/1/49")]
    assert uplink["classification"] == "TRUNK"
    assert any("managed switch in the inventory" in r["text"]
               for r in uplink["classification_reasons"])


async def test_core_switch_ports_are_infrastructure(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"], roles={"SIM-SW-01": "core"})
    plan = (await admin.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS})).json()
    assert plan["status"] == "denied" and "infrastructure" in plan["blocked_reason"]
    reasons = " ".join(r["text"] for r in plan["classification_reasons"])
    assert "core switch" in reasons


# ------------------------------------------------------------------------------ alerts ---
async def test_alerts_multiple_locations_and_ack(reader, operator, lab):
    lab["SIM-SW-03"].ports["1/5"].macs.append((10, MAC_ACCESS))
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-03"])
    await search(reader, MAC_ACCESS)
    await search(reader, MAC_ACCESS)  # deduplicated into the same alert
    await get_recorder().flush()
    data = (await reader.get("/api/alerts", params={"kind": "MULTIPLE_LOCATIONS"})).json()
    assert data["total"] == 1 and data["items"][0]["occurrences"] == 2
    alert_id = data["items"][0]["id"]
    assert (await reader.post(f"/api/alerts/{alert_id}/ack")).status_code == 403
    acked = (await operator.post(f"/api/alerts/{alert_id}/ack")).json()
    assert acked["status"] == "acknowledged" and acked["acknowledged_by"] == "operator"
    summary = (await reader.get("/api/alerts/summary")).json()
    still_open = (await reader.get("/api/alerts", params={"status": "open"})).json()
    assert summary["open"] == still_open["total"] == sum(summary["by_severity"].values())
    assert alert_id not in {a["id"] for a in still_open["items"]}


async def test_alert_undeclared_trunk(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    await search(reader, "00aa00000077")  # behind an AP: LIKELY_TRUNK, not declared
    await get_recorder().flush()
    data = (await reader.get("/api/alerts", params={"kind": "UNEXPECTED_TRUNK"})).json()
    assert data["total"] == 1 and data["items"][0]["port"] == "1/1/10"


# ----------------------------------------------------------------------- circuit breaker ---
async def test_circuit_breaker_trips_on_auth_failures_of_healthy_switches(admin, reader, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-02", "SIM-SW-03"])
    async with session_factory()() as db:
        await db.execute(update(Switch).values(status="online"))
        await db.commit()
    for name in ids:
        lab[name].behavior.auth_fail = True
    await search(reader, MAC_ACCESS)
    await get_breaker().flush()
    await get_recorder().flush()
    state = (await admin.get("/api/safety")).json()
    assert state["state"]["safe_mode"] is True and state["indicator"] == "SAFE MODE"
    assert "authentication" in state["state"]["safe_mode_reason"]
    alerts = (await admin.get("/api/alerts", params={"kind": "CIRCUIT_BREAKER"})).json()
    assert alerts["total"] == 1 and alerts["items"][0]["severity"] == "CRITICAL"
    events = (await admin.get("/api/safety/events")).json()["items"]
    assert events[0]["kind"] == "BREAKER_TRIP"
    # Read-only operations continue in SAFE MODE.
    for name in ids:
        lab[name].behavior.auth_fail = False
    assert (await search(reader, MAC_ACCESS))["found_count"] >= 1
    reset = (await admin.post("/api/safety/breaker/reset", json={"reason": "fixed RADIUS"}))
    assert reset.json()["state"]["safe_mode"] is False


async def test_circuit_breaker_ignores_already_offline_switches(admin, reader, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-02", "SIM-SW-03"])
    for name in ids:
        lab[name].behavior.auth_fail = True  # status stays "unknown": not previously healthy
    await search(reader, MAC_ACCESS)
    await get_breaker().flush()
    state = (await admin.get("/api/safety")).json()
    assert state["state"]["safe_mode"] is False


async def test_breaker_counts_validation_failures(app):
    from app.security.circuit_breaker import CircuitBreaker

    breaker = CircuitBreaker()
    for i in range(3):
        breaker.record_validation_failure(reason=f"INJECTION_ATTEMPT {i}")
    await breaker.flush()
    from app.services import system_settings

    async with session_factory()() as db:
        values = await system_settings.get_all(db)
    assert values["safe_mode"] is True and "validation" in values["safe_mode_reason"]


# ------------------------------------------------------------------ NetBox (read-only) ---
def _netbox(handler) -> NetBoxClient:
    return NetBoxClient("https://netbox.example", "nb-secret-token",
                        transport=httpx.MockTransport(handler))


async def test_netbox_client_is_get_only_with_token():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/dcim/devices/":
            return httpx.Response(200, json={"results": [{
                "id": 7, "name": "SIM-SW-01", "device_type": {"model": "OS6860E-P24"},
                "role": {"slug": "access"}, "site": {"slug": "bldg-a"},
                "status": {"value": "active"}, "primary_ip4": {"address": "10.99.0.1/24"}}]})
        return httpx.Response(200, json={"netbox-version": "4.1.0"})

    nb = _netbox(handler)
    assert (await nb.status())["netbox_version"] == "4.1.0"
    device = await nb.device("SIM-SW-01")
    assert device["model"] == "OS6860E-P24" and device["primary_ip"] == "10.99.0.1"
    assert all(r.method == "GET" for r in seen)
    assert all(r.headers["Authorization"] == "Token nb-secret-token" for r in seen)
    assert "nb-secret-token" not in repr(nb)
    with pytest.raises(IntegrationError, match="allowlist"):
        await nb._get("/api/dcim/devices/7/")
    with pytest.raises(IntegrationError):
        await nb.device("x; DROP TABLE")
    assert not any(hasattr(nb, m) for m in ("post", "put", "patch", "delete", "update"))


def test_netbox_reconciliation_rules():
    class Sw:
        name, host, model, role = "SW", "10.0.0.1", "OS6860E-P24", "access"

    mismatches = compare_device(Sw(), {"primary_ip": "10.0.0.2", "model": "OS6900-X20",
                                       "role": "core"})
    assert {m["field"] for m in mismatches} == {"management_ip", "model", "role"}
    assert compare_device(Sw(), {"primary_ip": "10.0.0.1", "model": "OS6860E-P24",
                                 "role": "access"}) == []
    assert compare_device(Sw(), None)[0]["field"] == "device"
    live = {"port": "1/1/26", "untagged_vlan": 206, "tagged_vlans": [], "admin_status": "enabled"}
    nb = {"mode": "access", "untagged_vlan": 207, "tagged_vlans": [], "enabled": True}
    assert [m["field"] for m in compare_interface(live, nb)] == ["untagged_vlan"]


async def test_integration_endpoints_not_configured(reader):
    resp = await reader.get("/api/integrations/status")
    assert resp.json() == {"netbox": {"configured": False}, "zabbix": {"configured": False}}
    assert (await reader.get("/api/integrations/netbox/reconcile")).status_code == 409


async def test_netbox_reconcile_endpoint_raises_mismatch_alerts(reader, lab, monkeypatch):
    from app.api.routes import integrations

    await seed_lab_switches(["SIM-SW-01"])

    def handler(request):
        return httpx.Response(200, json={"results": [{
            "name": "SIM-SW-01", "device_type": {"model": "OS6860E-P24"},
            "primary_ip4": {"address": "10.1.1.1/24"}, "role": {"slug": "access"}}]})

    monkeypatch.setattr(integrations, "get_netbox", lambda: _netbox(handler))
    data = (await reader.get("/api/integrations/netbox/reconcile")).json()
    assert data["total_mismatches"] == 1
    assert data["items"][0]["mismatches"][0]["field"] == "management_ip"
    await get_recorder().flush()
    alerts = (await reader.get("/api/alerts", params={"kind": "NETBOX_MISMATCH"})).json()
    assert alerts["total"] == 1


# ------------------------------------------------------------------ Zabbix (read-only) ---
async def test_zabbix_client_allowlist_and_bearer_token():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((body["method"], request.headers.get("Authorization")))
        if body["method"] == "host.get":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": [
                {"hostid": "10501", "host": "SIM-SW-01", "name": "SIM-SW-01", "status": "0",
                 "interfaces": [{"ip": "10.99.0.1", "available": "1"}]}]})
        if body["method"] == "problem.get":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": [
                {"eventid": "9", "name": "High CPU", "severity": "4", "clock": "1",
                 "acknowledged": "0"}]})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": "7.0.0"})

    zbx = ZabbixClient("https://zabbix.example", "zbx-token",
                       transport=httpx.MockTransport(handler))
    assert await zbx.version() == "7.0.0"
    host = await zbx.host("SIM-SW-01")
    problems = await zbx.problems(host["hostid"])
    assert host["monitored"] and problems[0]["severity"] == "High"
    assert calls[0] == ("apiinfo.version", None)
    assert calls[1] == ("host.get", "Bearer zbx-token")
    for method in ("host.update", "host.create", "host.delete", "user.login", "script.execute",
                   "configuration.import"):
        with pytest.raises(IntegrationError, match="allowlist"):
            await zbx._call(method, {})
    assert len(calls) == 3


# ---------------------------------------------------------------------- user management ---
async def test_admin_user_management_and_force_logout(admin, make_client):
    created = await admin.post("/api/users", json={
        "username": "test-macop", "password": "Test-MacOp-Passw0rd!!", "role": "mac_operator"})
    assert created.status_code == 201 and created.json()["role"] == "mac_operator"
    macuser = await make_client()
    assert (await macuser.login("test-macop", "Test-MacOp-Passw0rd!!")).status_code == 200
    users = {u["username"]: u for u in (await admin.get("/api/users")).json()}
    assert users["test-macop"]["active_sessions"] == 1 and users["test-macop"]["last_login_at"]
    resp = await admin.post(f"/api/users/{users['test-macop']['id']}/logout")
    assert resp.json()["sessions_terminated"] == 1
    assert (await macuser.get("/api/auth/me")).status_code == 401
    # Changing the role also ends the sessions (fresh login, new interface).
    await macuser.login("test-macop", "Test-MacOp-Passw0rd!!")
    await admin.patch(f"/api/users/{users['test-macop']['id']}", json={"role": "readonly"})
    assert (await macuser.get("/api/auth/me")).status_code == 401
    rows = (await admin.get("/api/audit", params={"action": "USER_FORCE_LOGOUT"})).json()
    assert rows["items"][0]["target_label"] == "test-macop"


# ---------------------------------------------------------------- lab verification run ---
async def test_read_verification_run_on_simulator_is_never_recorded(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-03"], unknown_version=("SIM-SW-03",))
    body = {"switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS}
    assert (await operator.post("/api/profiles/verifications/run", json=body)).status_code == 403
    result = (await admin.post("/api/profiles/verifications/run", json=body)).json()
    assert result["passed"] is True and result["recorded"] is False
    assert result["model_family"] == "OS6860" and result["version_prefix"] == "8.9"
    assert result["transport"] == "simulator" and result["evidence_level"] == "SIMULATED"
    statuses = {r["command_key"]: r["status"] for r in result["results"]}
    assert statuses["mac_lookup"] == statuses["port_detail"] == statuses["lldp_port"] == "ok"
    assert statuses["vlan_linkagg"] == "not_exercised"
    assert all(not c.startswith(("interfaces", "lanpower")) for c in lab["SIM-SW-01"].command_log)
    # A simulator run is SIMULATED evidence: it is never recorded as a lab verification.
    recorded = await admin.post("/api/profiles/verifications/run", json={**body, "record": True})
    assert recorded.status_code == 422 and "SIMULATED" in recorded.text
    assert (await admin.get("/api/profiles")).json()["verifications"] == []
    # An undiscovered switch cannot be used for verification at all.
    refused = await admin.post("/api/profiles/verifications/run", json={
        "switch_id": ids["SIM-SW-03"], "port": "1/12"})
    assert refused.status_code == 400 and refused.json()["error"]["code"] == "DISCOVERY_REQUIRED"


async def test_verification_run_fails_on_unexpected_output(admin, lab):
    lab["SIM-SW-01"].behavior.malformed_on = ("show lldp",)
    ids = await seed_lab_switches(["SIM-SW-01"])
    body = {"switch_id": ids["SIM-SW-01"], "port": "1/1/26", "record": True}
    resp = await admin.post("/api/profiles/verifications/run", json=body)
    assert resp.status_code == 422  # did not pass: nothing recorded
    assert (await admin.get("/api/profiles")).json()["verifications"] == []


# --------------------------------------------------------------------- audit immutability ---
async def test_audit_log_is_append_only(admin):
    async with session_factory()() as db:
        row = (await db.execute(select(AuditLog).limit(1))).scalar_one()
        with pytest.raises(Exception, match="append-only"):
            await db.execute(update(AuditLog).where(AuditLog.id == row.id)
                             .values(message="tampered"))
            await db.commit()
        await db.rollback()
        with pytest.raises(Exception, match="append-only"):
            await db.delete(row)
            await db.commit()


# ------------------------------------------------------------------ topology / roles ---
async def test_topology_is_built_from_stored_evidence_only(reader, macop, lab):
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"], roles={"SIM-SW-02": "distribution",
                                                                "SIM-SW-01": "access"})
    await search(reader, MAC_ACCESS)
    before = sum(len(sw.command_log) for sw in lab.values())
    topo = (await reader.get("/api/topology")).json()
    assert sum(len(sw.command_log) for sw in lab.values()) == before  # no command sent
    assert [n["name"] for n in topo["nodes"]] == ["SIM-SW-02", "SIM-SW-01"]  # by role
    assert {(l["a"], l["a_port"], l["b"]) for l in topo["links"]} == {
        ("SIM-SW-02", "1/1/1", "SIM-SW-01")}
    assert all(l["observed_at"] for l in topo["links"])
    assert (await macop.get("/api/topology")).status_code == 403


async def test_roles_matrix_is_admin_only(admin, reader):
    data = (await admin.get("/api/roles")).json()
    by_role = {r["role"]: set(r["permissions"]) for r in data["roles"]}
    assert by_role["mac_operator"] == {"simple_search", "simple_restart"}
    assert "restart_port" in by_role["operator"] and "manage_users" in by_role["admin"]
    assert len(data["permissions"]) == len({p for ps in by_role.values() for p in ps} | {
        p["permission"] for p in data["permissions"]})
    assert (await reader.get("/api/roles")).status_code == 403
