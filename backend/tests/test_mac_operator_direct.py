"""MAC_OPERATOR direct endpoint restart: no administrator approval, but every technical safety
check is mandatory (endpoint evidence gate, NetBox evidence, fresh state validation, firewall,
locks, safety modes, post-restart verification)."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from sqlalchemy import select

from app.db.session import session_factory
from app.models import AuditLog, PortAction, Switch
from app.security.restart_policy import endpoint_evidence_problems
from app.services.integrations.netbox import NetBoxClient, endpoint_port_evidence
from app.simulator.scenarios import MAC_ACCESS
from tests.conftest import PASSWORDS, approve, seed_lab_switches, set_mode, set_setting
from tests.test_rbac_simple import (
    CANNOT,
    assert_non_technical,
    seed_access,
    simple_restart_result,
    simple_search,
    writes,
)

GOOD = {"mac_on_port": True, "mac_vlan": 206, "classification": "ACCESS", "confidence": "High",
        "declared_uplink": False, "vlans_known": True,
        "vlans": [{"vlan_id": 206, "tagged": False}], "lldp_known": True, "lldp": [],
        "mac_count": 1, "admin_status": "enabled", "oper_status": "up", "speed": 1000,
        "alias": "Room 204 PC"}


async def go_live(admin):
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await admin.put("/api/settings", json={"values": {
        "dry_run_mode": False, "port_bounce_hold_seconds": 1, "post_restart_verify_seconds": 10}})
    await set_mode("MAINTENANCE")


async def restart(macop, search_id: str) -> dict:
    return (await macop.post("/api/simple/restart", json={"search_id": search_id})).json()


async def last_block_reason() -> str:
    async with session_factory()() as db:
        rows = (await db.execute(select(AuditLog).where(
            AuditLog.action == "SIMPLE_RESTART_BLOCKED").order_by(AuditLog.id))).scalars().all()
    return rows[-1].message if rows else ""


# ------------------------------------------------------------- endpoint evidence gate ---
def test_gate_accepts_a_clean_endpoint_port():
    assert endpoint_evidence_problems(GOOD, "access") == []


@pytest.mark.parametrize("change,role,expected", [
    ({}, "unknown", "switch role is 'unknown'"),
    ({}, "distribution", "switch role is 'distribution'"),
    ({"mac_on_port": False}, "access", "not learned"),
    ({"classification": "LIKELY_ACCESS"}, "access", "not ACCESS/High"),
    ({"confidence": "Medium"}, "access", "not ACCESS/High"),
    ({"classification": "UNKNOWN", "confidence": "Low"}, "access", "not ACCESS/High"),
    ({"declared_uplink": True}, "access", "declared as an uplink"),
    ({"vlans_known": False}, "access", "VLAN membership could not be read"),
    ({"vlans": [{"vlan_id": 206, "tagged": False}, {"vlan_id": 300, "tagged": True}]},
     "access", "tagged VLAN"),
    ({"vlans": []}, "access", "0 untagged VLANs"),
    ({"mac_vlan": 300}, "access", "not in the port's access VLAN"),
    ({"lldp_known": False}, "access", "LLDP"),
    ({"mac_count": None}, "access", "number of MACs"),
    ({"mac_count": 5}, "access", "5 MACs"),
    ({"admin_status": "disabled"}, "access", "admin state is disabled"),
    ({"admin_status": None}, "access", "admin state is unknown"),
    ({"oper_status": "down"}, "access", "operational state is down"),
    ({"speed": 10000}, "access", "uplink speed"),
    ({"alias": "MGMT switch B"}, "access", "indicates infrastructure"),
    ({"alias": "stack link"}, "access", "indicates infrastructure"),
    ({"alias": "Uplink to core"}, "access", "indicates infrastructure"),
])
def test_gate_blocks_on_any_missing_or_contradicting_evidence(change, role, expected):
    problems = endpoint_evidence_problems({**GOOD, **change}, role)
    assert any(expected in p for p in problems), problems


# ------------------------------------------------------------------- NetBox evidence ---
def _netbox(results: list | None = None, status: int = 200) -> NetBoxClient:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET" and request.url.path == "/api/dcim/interfaces/"
        return httpx.Response(status, json={"results": results or []})

    return NetBoxClient("https://netbox.example", "t", transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("iface,verdict", [
    ({"name": "1/1/26", "mode": {"value": "access"}, "enabled": True}, "consistent"),
    ({"name": "1/1/26", "mode": {"value": "tagged"}, "enabled": True}, "contradicts"),
    ({"name": "1/1/26", "mode": {"value": "tagged-all"}}, "contradicts"),
    ({"name": "1/1/26", "mgmt_only": True}, "contradicts"),
    ({"name": "1/1/26", "lag": {"id": 3, "name": "lag3"}}, "contradicts"),
    ({"name": "1/1/26", "type": {"value": "lag"}}, "contradicts"),
    ({"name": "1/1/26", "enabled": False}, "contradicts"),
])
async def test_netbox_interface_evidence(iface, verdict):
    got, _ = await endpoint_port_evidence("SW", "1/1/26", client=_netbox([iface]))
    assert got == verdict


async def test_netbox_not_documented_and_unavailable():
    assert (await endpoint_port_evidence("SW", "1/1/26", client=_netbox([])))[0] == \
        "not_documented"
    assert (await endpoint_port_evidence("SW", "1/1/26", client=_netbox(status=500)))[0] == \
        "unavailable"
    assert (await endpoint_port_evidence("SW", "1/1/26"))[0] == "not_configured"


@pytest.mark.parametrize("verdict,blocked", [("contradicts", True), ("unavailable", True),
                                             ("consistent", False), ("not_documented", False)])
async def test_netbox_verdict_decides_mac_operator_restart(macop, admin, lab, monkeypatch,
                                                           verdict, blocked):
    async def fake(device, port, client=None):
        return verdict, f"NetBox says {verdict}"

    monkeypatch.setattr("app.services.port_control.service.endpoint_port_evidence", fake)
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    result = await restart(macop, found["search_id"])
    if blocked:
        assert result == {"state": "blocked", "message": CANNOT}
        assert writes(lab) == []
        assert f"NetBox says {verdict}" in await last_block_reason()
    else:
        assert result["state"] == "running"
        done = await simple_restart_result(macop, result["request_id"])
        assert done["state"] == "success"


# -------------------------------------------------------- direct restart, no approval ---
async def test_direct_restart_records_checks_before_and_after_state(macop, admin, lab):
    ids = await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    started = await restart(macop, found["search_id"])
    assert started["state"] == "running"  # no approval step
    done = await simple_restart_result(macop, started["request_id"])
    assert done == {"state": "success", "message": "Device restarted successfully."}
    async with session_factory()() as db:
        action = (await db.execute(select(PortAction).where(
            PortAction.switch_id == ids["SIM-SW-01"]))).scalars().all()[-1]
        assert action.verification["verified"] is True
        assert action.verification["verification_problems"] == []
        steps = [s["step"] for s in action.steps]
        assert steps[:4] == ["recheck", "pre_restart_verification", "down", "up"]
        final = (await db.execute(select(AuditLog).where(
            AuditLog.action == "PORT_RESTART", AuditLog.result == "SUCCESS"))).scalars().all()[-1]
    assert final.role == "mac_operator" and final.approval == "simple confirmation (MAC_OPERATOR)"
    assert final.before_state["mac_on_port"] and final.after_state["mac_on_port"]
    assert final.before_state["classification"] == "ACCESS"


async def test_restart_blocked_when_switch_role_changes_after_search(macop, admin, lab):
    ids = await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    assert found["can_restart"] is True
    async with session_factory()() as db:
        (await db.get(Switch, ids["SIM-SW-01"])).role = "unknown"
        await db.commit()
    assert await restart(macop, found["search_id"]) == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []


async def test_restart_blocked_when_vlan_changes_after_search(macop, admin, lab):
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    port = lab["SIM-SW-01"].ports["1/1/26"]
    port.vlans = [(300, "untagged")]
    port.macs = [(300, MAC_ACCESS)]
    result = await restart(macop, found["search_id"])
    assert result == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []
    assert "changed since the search" in await last_block_reason()


async def test_restart_blocked_when_mac_moves_after_search(macop, admin, lab):
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    lab["SIM-SW-01"].ports["1/1/26"].macs = []
    lab["SIM-SW-01"].ports["1/1/5"].macs.append((206, MAC_ACCESS))
    assert await restart(macop, found["search_id"]) == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []


async def test_administratively_disabled_port_is_never_restarted(operator, admin, lab):
    """A link bounce ends with 'enable': on a disabled port that would be a config change."""
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    port = lab["SIM-SW-01"].ports["1/1/26"]
    port.admin_up = False
    port.visible_macs = lambda: list(port.macs)  # the MAC is still in the table
    plan = (await operator.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS})).json()
    assert plan["status"] == "denied" and "administratively disabled" in plan["blocked_reason"]
    assert writes(lab) == []


async def test_kill_switch_blocks_mac_operator(macop, admin, lab):
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    await admin.post("/api/safety/kill-switch", json={"active": True, "reason": "incident"})
    found = await simple_search(macop, MAC_ACCESS)
    assert await restart(macop, found["search_id"]) == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []


async def test_safe_mode_blocks_mac_operator(macop, admin, lab):
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    await set_setting("safe_mode", True)
    await set_setting("safe_mode_reason", "repeated SSH failures")
    found = await simple_search(macop, MAC_ACCESS)
    assert await restart(macop, found["search_id"]) == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []


async def test_old_search_result_requires_a_new_search(macop, admin, lab):
    from datetime import timedelta

    from app.core.timeutil import utcnow
    from app.models import MacSearch

    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    async with session_factory()() as db:
        (await db.get(MacSearch, found["search_id"])).finished_at = utcnow() - timedelta(
            minutes=11)
        await db.commit()
    assert await restart(macop, found["search_id"]) == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []


# ----------------------------------------------------------------------- concurrency ---
async def test_two_mac_operators_restarting_the_same_port_restart_once(macop, admin, lab,
                                                                       make_client):
    from app.core.security import hash_password
    from app.models import User

    async with session_factory()() as db:
        db.add(User(username="test-macop2", full_name="Second", role="mac_operator",
                    password_hash=hash_password(PASSWORDS["macop"])))
        await db.commit()
    second = await make_client()
    await second.login("test-macop2", PASSWORDS["macop"])
    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    a, b = await asyncio.gather(simple_search(macop, MAC_ACCESS),
                                simple_search(second, MAC_ACCESS))
    ra, rb = await asyncio.gather(restart(macop, a["search_id"]), restart(second, b["search_id"]))
    # One restart runs; the other is refused (port lock / same-port minimum interval).
    assert sorted([ra["state"] == "running", rb["state"] == "running"]) == [False, True], (ra, rb)
    refused = rb if ra["state"] == "running" else ra
    assert refused["state"] in {"blocked", "error"} and "request_id" not in refused
    running = ra if ra["state"] == "running" else rb
    runner = macop if running is ra else second
    await simple_restart_result(runner, running["request_id"])
    assert writes(lab) == ["interfaces port 1/1/26 admin-state disable",
                           "interfaces port 1/1/26 admin-state enable"]


async def test_restart_status_of_another_user_is_invisible(macop, admin, lab, make_client):
    from app.core.security import hash_password
    from app.models import User

    await seed_access(["SIM-SW-01"])
    await go_live(admin)
    found = await simple_search(macop, MAC_ACCESS)
    started = await restart(macop, found["search_id"])
    async with session_factory()() as db:
        db.add(User(username="test-macop3", full_name="Third", role="mac_operator",
                    password_hash=hash_password(PASSWORDS["macop"])))
        await db.commit()
    other = await make_client()
    await other.login("test-macop3", PASSWORDS["macop"])
    peek = (await other.get(f"/api/simple/restart/{started['request_id']}")).json()
    assert peek == {"state": "error",
                    "message": "Something went wrong. Please try again or contact IT support."}
    await simple_restart_result(macop, started["request_id"])


# ---------------------------------------------------------------- API manipulation ---
@pytest.mark.parametrize("method,path,body", [
    ("patch", "/api/users/1", {"role": "admin"}),
    ("post", "/api/users/1/logout", {}),
    ("patch", "/api/switches/1", {"role": "access"}),
    ("delete", "/api/switches/1", None),
    ("put", "/api/settings", {"values": {"dry_run_mode": False}}),
    ("post", "/api/credentials", {"name": "x", "username": "y", "password": "z"}),
    ("get", "/api/topology", None),
    ("get", "/api/switches/1/ports/1/1/26", None),
    ("get", "/api/switches/export", None),
    ("post", "/api/switches/import/validate", {"format": "csv", "content": "x"}),
    ("get", "/api/integrations/netbox/switches/1", None),
    ("post", "/api/safety/breaker/reset", {"reason": "please"}),
])
async def test_mac_operator_cannot_modify_anything(macop, lab, method, path, body):
    await seed_lab_switches(["SIM-SW-01"])
    kwargs = {"json": body} if body is not None else {}
    resp = await getattr(macop, method)(path, **kwargs)
    assert resp.status_code in (403, 404, 405), (path, resp.status_code, resp.text)
    assert resp.status_code != 200
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch))).scalars().first()
        assert sw.role == "unknown"


@pytest.mark.parametrize("body", [
    {"search_id": "0" * 36, "role": "admin"},
    {"search_id": "0" * 36, "vlan": 10},
    {"search_id": "0" * 36, "profile": "AOS8"},
    {"search_id": "0" * 36, "mac": "00:11:22:33:44:55"},
    {"search_id": "' OR 1=1 --" + "x" * 25},
])
async def test_simple_restart_field_injection(macop, lab, body):
    resp = await macop.post("/api/simple/restart", json=body)
    assert resp.status_code in (400, 422) or resp.json()["state"] in {"blocked", "error"}
    assert writes(lab) == []


async def test_simple_search_response_is_role_aware_not_css(macop, lab):
    """The server itself never returns technical fields to the MAC_OPERATOR."""
    await seed_access(["SIM-SW-01", "SIM-SW-02"])
    started = (await macop.post("/api/simple/search", json={"mac": MAC_ACCESS})).json()
    raw = await simple_search(macop, MAC_ACCESS)
    for payload in (started, raw):
        assert_non_technical(payload)
        text = str(payload)
        for leak in ("1/1/26", "206", "SIM-SW", "OS6860", "8.9", "lldp", "vlan"):
            assert leak not in text, (leak, payload)
