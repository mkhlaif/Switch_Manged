"""RBAC (§36) and the simplified MAC_OPERATOR experience (§61–78).

The simple UI is not a security boundary: every test here talks to the API directly, the way a
malicious user would.
"""

import re

import pytest
from sqlalchemy import select

from app.core.permissions import Permission, permissions_for
from app.db.session import session_factory
from app.models import AuditLog, Role
from app.security.recorder import get_recorder
from app.simulator.scenarios import MAC_ACCESS, MAC_NOWHERE, MAC_PHONE_PC, MAC_WIFI
from tests.conftest import approve, seed_lab_switches, set_mode

GENERIC = "Something went wrong. Please try again or contact IT support."
CANNOT = "This device cannot be restarted automatically. Please contact IT support."
TECHNICAL = re.compile(r"1/1/|\bvlan\b|\bssh\b|\baos\b|\bos\d|\d+\.\d+\.|\bport\b|"
                       r"\blldp\b|interfaces|trunk|\bshow\b|admin-state|\bcli\b",
                       re.IGNORECASE)


def writes(lab, name="SIM-SW-01"):
    return [c for c in lab[name].command_log if c.startswith(("interfaces", "lanpower"))]


def assert_non_technical(payload: dict) -> None:
    assert set(payload) <= {"state", "message", "location", "can_restart", "search_id",
                            "request_id"}, payload
    for key in ("message", "location"):
        text = str(payload.get(key, ""))
        assert not TECHNICAL.search(text), text
    assert "SIM-SW" not in str(payload)  # never the switch name


ACCESS_ROLES = {"SIM-SW-01": "access", "SIM-SW-03": "access", "SIM-SW-02": "distribution"}


async def seed_access(names: list[str]) -> dict[str, int]:
    """Lab switches with their topology roles (MAC_OPERATOR restarts need role 'access')."""
    return await seed_lab_switches(names, roles={n: ACCESS_ROLES.get(n, "unknown")
                                                 for n in names})


async def audit_rows(action: str) -> list[AuditLog]:
    async with session_factory()() as db:
        return (await db.execute(select(AuditLog).where(AuditLog.action == action)
                                 .order_by(AuditLog.id))).scalars().all()


async def simple_search(api, mac: str) -> dict:
    import asyncio

    started = (await api.post("/api/simple/search", json={"mac": mac})).json()
    if started["state"] != "searching":
        return started
    for _ in range(600):
        data = (await api.get(f"/api/simple/search/{started['search_id']}")).json()
        if data["state"] != "searching":
            return {**data, "search_id": started["search_id"]}
        await asyncio.sleep(0.05)
    raise AssertionError("simple search did not finish")


async def simple_restart_result(api, request_id: str) -> dict:
    import asyncio

    for _ in range(1200):
        data = (await api.get(f"/api/simple/restart/{request_id}")).json()
        if data["state"] != "running":
            return data
        await asyncio.sleep(0.05)
    raise AssertionError("simple restart did not finish")


async def go_live(admin):
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await admin.put("/api/settings", json={"values": {
        "dry_run_mode": False, "port_bounce_hold_seconds": 1, "post_restart_verify_seconds": 10}})
    await set_mode("MAINTENANCE")


# ------------------------------------------------------------------ permission model ---
def test_permission_matrix():
    macop = permissions_for(Role.MAC_OPERATOR)
    assert macop == {Permission.SIMPLE_SEARCH, Permission.SIMPLE_RESTART}
    reader = permissions_for(Role.READONLY)
    assert Permission.RESTART_PORT not in reader and Permission.MAC_SEARCH in reader
    assert Permission.SIMPLE_RESTART not in permissions_for(Role.ADMIN)
    assert Permission.MANAGE_SAFETY not in permissions_for(Role.OPERATOR)
    assert Permission.STOP_OPERATIONS in permissions_for(Role.OPERATOR)
    assert permissions_for("superuser") == frozenset()  # unknown role: nothing (fail closed)


async def test_me_selects_simple_interface(macop, admin):
    me = (await macop.get("/api/auth/me")).json()["user"]
    assert me["role"] == "mac_operator" and me["interface"] == "simple"
    assert me["permissions"] == ["simple_restart", "simple_search"]
    assert (await admin.get("/api/auth/me")).json()["user"]["interface"] == "full"


@pytest.mark.parametrize("method,path,body", [
    ("get", "/api/switches", None),
    ("get", "/api/switches/1", None),
    ("post", "/api/switches", {"name": "x", "host": "10.0.0.1"}),
    ("post", "/api/mac/search", {"mac": MAC_ACCESS}),
    ("get", "/api/search-history", None),
    ("post", "/api/ports/restart/prepare", {"switch_id": 1, "port": "1/1/26", "mac": MAC_ACCESS}),
    ("post", "/api/ports/restart", {"plan_token": "0" * 36, "confirmations": []}),
    ("get", "/api/ports/actions", None),
    ("get", "/api/audit", None),
    ("get", "/api/ssh-sessions", None),
    ("get", "/api/users", None),
    ("post", "/api/users", {"username": "evil", "password": "Evil-Passw0rd!!", "role": "admin"}),
    ("get", "/api/profiles", None),
    ("post", "/api/profiles/verifications", {"profile_key": "AOS8", "capability": "READ",
                                             "model_family": "*", "version_prefix": "8.9"}),
    ("get", "/api/safety", None),
    ("post", "/api/safety/mode", {"mode": "MAINTENANCE", "reason": "please"}),
    ("post", "/api/safety/kill-switch", {"active": False, "reason": "please"}),
    ("get", "/api/settings", None),
    ("get", "/api/alerts", None),
    ("get", "/api/dashboard", None),
    ("get", "/api/integrations/status", None),
    ("get", "/api/operations", None),
])
async def test_mac_operator_cannot_reach_technical_apis(macop, method, path, body):
    kwargs = {"json": body} if body is not None else {}
    resp = await getattr(macop, method)(path, **kwargs)
    assert resp.status_code == 403, (path, resp.status_code, resp.text)
    assert resp.json()["error"]["message"] == "You do not have permission for this action."


async def test_rbac_violation_is_audited_high(macop):
    await macop.get("/api/switches")
    rows = await audit_rows("RBAC_VIOLATION")
    assert rows and rows[-1].severity == "HIGH" and rows[-1].role == "mac_operator"
    assert rows[-1].details["path"] == "/api/switches"


@pytest.mark.parametrize("operation", ["SEARCH_MAC", "GET_PORT_STATUS", "RESTART_PORT",
                                       "EXECUTE_COMMAND", "GET_SWITCH_DETAILS",
                                       "GET_NETWORK_TOPOLOGY", "MODIFY_SWITCH"])
async def test_mac_operator_operation_gateway_is_closed(macop, lab, operation):
    await seed_lab_switches(["SIM-SW-01"])
    resp = await macop.post("/api/operations", json={
        "operation": operation, "switch_id": 1, "port": "1/1/26", "mac": MAC_ACCESS})
    assert resp.status_code in (400, 403)
    assert lab["SIM-SW-01"].command_log == []


async def test_other_roles_cannot_use_the_simple_api(reader, operator, admin):
    for api in (reader, operator, admin):
        assert (await api.post("/api/simple/search", json={"mac": MAC_ACCESS})).status_code == 403
        assert (await api.post("/api/simple/restart",
                               json={"search_id": "0" * 36})).status_code == 403


# ---------------------------------------------------------------------- simple search ---
async def test_simple_search_found_shows_only_the_location(macop, lab):
    await seed_access(["SIM-SW-01", "SIM-SW-02"])
    result = await simple_search(macop, "00-11-22-33-44-55")
    assert result["state"] == "found" and result["message"] == "Device Found"
    assert result["location"] == "Building A / Floor 1" and result["can_restart"] is True
    assert "switch_name" not in result
    assert_non_technical(result)


async def test_simple_search_shows_the_port_location_label(macop, lab):
    from app.models import Switch

    ids = await seed_access(["SIM-SW-01"])
    async with session_factory()() as db:
        sw = await db.get(Switch, ids["SIM-SW-01"])
        sw.site = "Main campus"
        sw.port_locations = {"1/1/26": "Building A - Floor 2 - Office 204"}
        await db.commit()
    result = await simple_search(macop, MAC_ACCESS)
    assert result["location"] == "Building A - Floor 2 - Office 204"
    assert_non_technical(result)
    # Without a port label: site and location, never the switch name.
    async with session_factory()() as db:
        sw = await db.get(Switch, ids["SIM-SW-01"])
        sw.port_locations = {}
        await db.commit()
    result = await simple_search(macop, MAC_ACCESS)
    assert result["location"] == "Main campus - Building A / Floor 1"


async def test_simple_search_offers_no_restart_on_switch_without_access_role(macop, lab):
    await seed_lab_switches(["SIM-SW-01"])  # role "unknown"
    result = await simple_search(macop, MAC_ACCESS)
    assert result["state"] == "found" and result["can_restart"] is False
    assert_non_technical(result)


async def test_simple_search_not_found(macop, lab):
    await seed_lab_switches(["SIM-SW-01"])
    result = await simple_search(macop, MAC_NOWHERE)
    assert result["state"] == "not_found"
    assert result["message"] == "Device Not Found. Please check the MAC address and try again."
    assert_non_technical(result)


async def test_simple_search_multiple_locations(macop, lab):
    lab["SIM-SW-03"].ports["1/5"].macs.append((10, MAC_ACCESS))  # duplicate / moved device
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-03"])
    result = await simple_search(macop, MAC_ACCESS)
    assert result["state"] == "multiple"
    assert result["message"] == "Multiple locations detected. Please contact IT support."
    assert "switch_name" not in result
    assert_non_technical(result)


async def test_simple_search_unreachable_switch_is_generic_and_blocks_restart(macop, lab):
    await seed_access(["SIM-SW-01", "SIM-SW-04"])  # SIM-SW-04: authentication failure
    result = await simple_search(macop, MAC_ACCESS)
    assert result["state"] == "found" and result["can_restart"] is False  # uncertainty
    assert_non_technical(result)
    nowhere = await simple_search(macop, MAC_NOWHERE)
    assert nowhere["state"] == "error" and nowhere["message"] == GENERIC


async def test_simple_search_invalid_and_injection(macop):
    resp = (await macop.post("/api/simple/search", json={"mac": "00:11:22:33:44:55; reload"}))
    assert resp.json() == {"state": "invalid", "message": "Please enter a valid MAC address."}
    rows = await audit_rows("INJECTION_ATTEMPT")
    assert rows and rows[-1].username == "macop" and rows[-1].severity in {"HIGH", "CRITICAL"}


async def test_simple_search_errors_are_generic(macop):
    # No switches in the inventory: the technical error never reaches the user.
    resp = (await macop.post("/api/simple/search", json={"mac": MAC_ACCESS})).json()
    assert resp == {"state": "error", "message": GENERIC}


async def test_simple_search_of_another_user_is_invisible(macop, make_client, lab):
    await seed_lab_switches(["SIM-SW-01"])
    result = await simple_search(macop, MAC_ACCESS)
    async with session_factory()() as db:
        from app.core.security import hash_password
        from app.models import User

        db.add(User(username="jane", full_name="Jane", role=Role.MAC_OPERATOR.value,
                    password_hash=hash_password("Jane-Passw0rd!!")))
        await db.commit()
    jane = await make_client()
    await jane.login("jane", "Jane-Passw0rd!!")
    peek = (await jane.get(f"/api/simple/search/{result['search_id']}")).json()
    assert peek == {"state": "error", "message": GENERIC}
    restart = (await jane.post("/api/simple/restart",
                               json={"search_id": result["search_id"]})).json()
    assert restart["state"] == "blocked" and restart["message"] == CANNOT
    assert writes(lab) == []


# --------------------------------------------------------------------- simple restart ---
async def test_simple_restart_end_to_end(macop, admin, lab):
    await seed_access(["SIM-SW-01", "SIM-SW-02"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    assert found["can_restart"] is True
    started = (await macop.post("/api/simple/restart",
                                json={"search_id": found["search_id"]})).json()
    assert started["state"] == "running"
    assert_non_technical(started)
    done = await simple_restart_result(macop, started["request_id"])
    assert done == {"state": "success", "message": "Device restarted successfully."}
    assert writes(lab) == ["interfaces port 1/1/26 admin-state disable",
                           "interfaces port 1/1/26 admin-state enable"]
    await get_recorder().flush()
    row = [r for r in await audit_rows("PORT_RESTART") if r.result == "SUCCESS"][-1]
    assert row.username == "macop" and row.role == "mac_operator"
    assert row.switch_name == "SIM-SW-01" and row.port == "1/1/26" and row.mac == MAC_ACCESS
    assert row.approval == "simple confirmation (MAC_OPERATOR)"
    assert len(row.command_fingerprint) == 64


async def test_simple_restart_blocked_outside_maintenance(macop, admin, lab):
    await seed_access(["SIM-SW-01", "SIM-SW-02"])
    await go_live(admin)
    await set_mode("NORMAL")
    found = await simple_search(macop, MAC_ACCESS)
    resp = (await macop.post("/api/simple/restart", json={"search_id": found["search_id"]}))
    assert resp.json() == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []
    rows = await audit_rows("SIMPLE_RESTART_BLOCKED")
    assert rows and "MAINTENANCE" in rows[-1].message  # the reason is logged, not shown


@pytest.mark.parametrize("mac,switches", [
    (MAC_WIFI, ["SIM-SW-01"]),                    # behind an access point: LIKELY_TRUNK
    (MAC_PHONE_PC, ["SIM-SW-02", "SIM-SW-03"]),   # phone + PC: only LIKELY_ACCESS
])
async def test_simple_restart_refuses_uncertain_ports(macop, admin, lab, mac, switches):
    await seed_access(switches)
    await go_live(admin)
    found = await simple_search(macop, mac)
    assert found.get("can_restart") is not True
    resp = (await macop.post("/api/simple/restart", json={"search_id": found["search_id"]}))
    assert resp.json() == {"state": "blocked", "message": CANNOT}
    for name in switches:
        assert writes(lab, name) == []


async def test_simple_restart_refuses_infrastructure_switch(macop, admin, lab):
    await seed_lab_switches(["SIM-SW-01"], roles={"SIM-SW-01": "distribution"})
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    resp = (await macop.post("/api/simple/restart", json={"search_id": found["search_id"]}))
    assert resp.json()["state"] == "blocked"
    assert writes(lab) == []


async def test_simple_restart_parameter_tampering_is_rejected(macop, admin, lab):
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    for extra in ({"switch_id": 1}, {"port": "1/1/5"}, {"command": "reload"},
                  {"confirmations": ["RESTART PORT 1/1/5"]}):
        resp = await macop.post("/api/simple/restart",
                                json={"search_id": found["search_id"], **extra})
        assert resp.status_code in (400, 422)
    assert writes(lab) == []
