"""Operation modes, kill switch, SAFE MODE, rate limits, switch/port locks and the restore
exemption (end to end)."""

import asyncio

import pytest

from app.core.config import get_settings
from app.services.port_control.service import acquire_locks
from app.simulator.scenarios import MAC_ACCESS, MAC_SINGLE_PC
from tests.conftest import (
    approve,
    seed_lab_switches,
    set_setting,
    wait_for_action,
    wait_for_search,
)

WRITE_PREFIXES = ("interfaces", "lanpower")


def writes(lab, name="SIM-SW-01"):
    return [c for c in lab[name].command_log if c.startswith(WRITE_PREFIXES)]


async def go_live(admin, *, mode="MAINTENANCE", **extra):
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    values = {"dry_run_mode": False, "port_bounce_hold_seconds": 1,
              "post_restart_verify_seconds": 10, **extra}
    assert (await admin.put("/api/settings", json={"values": values})).status_code == 200
    resp = await admin.post("/api/safety/mode", json={"mode": mode, "reason": "test window"})
    assert resp.status_code == 200, resp.text


async def prepare(api, sid, port, mac):
    resp = await api.post("/api/ports/restart/prepare", json={
        "switch_id": sid, "port": port, "mac": mac, "method": "link_bounce"})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def execute(api, plan):
    return await api.post("/api/ports/restart", json={
        "plan_token": plan["plan_token"], "confirmations": plan["required_phrases"]})


@pytest.mark.parametrize("mode,needle", [
    ("NORMAL", "State-changing operations require MAINTENANCE mode"),
    ("READ_ONLY", "Operation mode is READ_ONLY"),
])
async def test_non_maintenance_modes_block_restart_but_not_reads(admin, reader, lab, mode,
                                                                 needle):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin, mode=mode)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert plan["execution_allowed"] is False and needle in plan["execution_note"]
    resp = await execute(admin, plan)
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["code"] == "COMMAND_BLOCKED" and "PORT RESTART BLOCKED" in err["message"]
    assert writes(lab) == []
    action = (await admin.get(f"/api/ports/actions/{plan['id']}")).json()
    assert action["status"] == "denied"
    assert action["safety_report"]["result"] == "NO COMMAND SENT"
    # Read-only operations continue.
    search = (await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})).json()
    assert (await wait_for_search(reader, search["id"]))["found_count"] == 1


async def test_kill_switch_blocks_restart_and_is_audited(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    # Operators may ENGAGE the kill switch (safety-increasing) ...
    resp = await operator.post("/api/safety/kill-switch",
                               json={"active": True, "reason": "incident INC-42"})
    assert resp.status_code == 200 and resp.json()["indicator"] == "STOPPED"
    # ... but only an administrator may release it.
    resp = await operator.post("/api/safety/kill-switch", json={"active": False, "reason": "x x"})
    assert resp.status_code == 403
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert "STOP ALL NETWORK OPERATIONS" in plan["execution_note"]
    assert (await execute(admin, plan)).status_code == 403
    assert writes(lab) == []
    events = (await admin.get("/api/safety/events")).json()["items"]
    assert events[0]["kind"] == "KILL_SWITCH" and events[0]["reason"] == "incident INC-42"
    audit = (await admin.get("/api/audit", params={"action": "KILL_SWITCH_ON"})).json()
    assert audit["items"][0]["severity"] == "CRITICAL"
    resp = await admin.post("/api/safety/kill-switch", json={"active": False, "reason": "resolved"})
    assert resp.json()["indicator"] == "ACTIVE"


async def test_env_read_only_mode_forces_block(admin, lab, monkeypatch):
    monkeypatch.setattr(get_settings(), "read_only_mode", True)
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert "READ_ONLY_MODE environment" in plan["execution_note"]
    assert (await execute(admin, plan)).status_code == 403
    assert writes(lab) == []
    state = (await admin.get("/api/safety")).json()
    assert state["env_read_only_mode"] is True and state["state"]["mode"] == "READ_ONLY"
    assert state["state"]["configured_mode"] == "MAINTENANCE"
    assert state["indicator"] == "READ ONLY"


async def test_env_kill_switch_forces_block(admin, lab, monkeypatch):
    monkeypatch.setattr(get_settings(), "network_command_execution", "DISABLED")
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert "NETWORK_COMMAND_EXECUTION=DISABLED" in plan["execution_note"]
    assert (await execute(admin, plan)).status_code == 403
    assert writes(lab) == []


@pytest.mark.parametrize("value", ["DISABLE", "", "off", "enabled please"])
async def test_env_kill_switch_fails_closed_on_unexpected_values(admin, monkeypatch, value):
    monkeypatch.setattr(get_settings(), "network_command_execution", value)
    state = (await admin.get("/api/safety")).json()["state"]
    assert state["command_execution_enabled"] is False and state["indicator"] == "STOPPED"


async def test_safe_mode_blocks_until_admin_reset(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    await set_setting("safe_mode", True)
    await set_setting("safe_mode_reason", "5 consecutive SSH failures")
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert "SAFE MODE" in plan["execution_note"]
    assert (await execute(admin, plan)).status_code == 403
    assert (await operator.post("/api/safety/breaker/reset",
                                json={"reason": "checked"})).status_code == 403
    resp = await admin.post("/api/safety/breaker/reset", json={"reason": "switches fixed"})
    assert resp.status_code == 200 and resp.json()["state"]["safe_mode"] is False
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert plan["execution_allowed"] is True


async def test_dry_run_produces_command_safety_test(operator, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert plan["required_phrases"] == ["RESTART PORT 1/1/26"]
    done = (await execute(operator, plan)).json()
    report = done["safety_report"]
    assert done["status"] == "dry_run"
    assert report["operation"] == "RESTART_PORT" and report["safety"] == "PASS"
    assert report["execution"] == "DISABLED" and report["result"] == "NO COMMAND SENT"
    assert [c["text"] for c in report["commands"]] == [
        "interfaces port 1/1/26 admin-state disable", "interfaces port 1/1/26 admin-state enable"]
    assert all(len(c["fingerprint"]) == 64 for c in report["commands"])
    assert writes(lab) == []


async def test_unknown_classification_blocks_restart(admin, lab):
    lab["SIM-SW-01"].behavior.error_on = ("show vlan members port 1/1/5",)
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/5", MAC_SINGLE_PC)
    assert plan["classification"] == "UNKNOWN" and plan["status"] == "denied"
    assert "uncertain" in plan["blocked_reason"]
    assert writes(lab) == []


async def test_restart_rate_limit_per_user(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin, max_restarts_per_10_minutes=1)
    first = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    done = await wait_for_action(admin, (await execute(admin, first)).json()["id"])
    assert done["status"] == "success"
    second = await prepare(admin, ids["SIM-SW-01"], "1/1/5", MAC_SINGLE_PC)
    resp = await execute(admin, second)
    assert resp.status_code == 429 and "per 10 minutes" in resp.json()["error"]["message"]
    assert writes(lab) == ["interfaces port 1/1/26 admin-state disable",
                           "interfaces port 1/1/26 admin-state enable"]


async def test_same_port_minimum_interval(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    first = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    await wait_for_action(admin, (await execute(admin, first)).json()["id"])
    await asyncio.sleep(0.5)  # let the MAC relearn so the plan can be prepared
    second = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    resp = await execute(admin, second)
    assert resp.status_code == 429 and "less than 60s" in resp.json()["error"]["message"]
    assert len(writes(lab)) == 2


async def test_port_lock_prevents_parallel_actions(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    await acquire_locks(ids["SIM-SW-01"], "SIM-SW-01", "1/1/26", 999_999, "someone-else")
    locks = (await admin.get("/api/safety/locks")).json()["items"]
    assert {(lk["scope"], lk["locked_by"]) for lk in locks} == {
        ("switch", "someone-else"), ("port", "someone-else")}
    resp = await execute(admin, plan)
    assert resp.status_code == 409
    assert "PORT LOCKED" in resp.json()["error"]["message"]
    assert writes(lab) == []


async def test_switch_lock_prevents_parallel_actions_on_other_port(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    await acquire_locks(ids["SIM-SW-01"], "SIM-SW-01", "1/1/5", 999_999, "someone-else")
    resp = await execute(admin, plan)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SWITCH_LOCKED"
    assert writes(lab) == []


async def test_concurrent_execution_on_same_port_sends_one_restart(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin)
    p1 = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    p2 = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    r1, r2 = await asyncio.gather(execute(admin, p1), execute(admin, p2))
    codes = sorted([r1.status_code, r2.status_code])
    assert codes[0] == 200 and codes[1] in (409, 429)
    ok = r1 if r1.status_code == 200 else r2
    await wait_for_action(admin, ok.json()["id"])
    assert len(writes(lab)) == 2  # exactly one down + one up


async def test_kill_switch_during_restart_still_restores_port(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin, port_bounce_hold_seconds=2)
    plan = await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    started = (await execute(admin, plan)).json()
    for _ in range(100):  # wait until the port is down
        if writes(lab):
            break
        await asyncio.sleep(0.05)
    assert writes(lab) == ["interfaces port 1/1/26 admin-state disable"]
    await admin.post("/api/safety/kill-switch", json={"active": True, "reason": "stop now"})
    done = await wait_for_action(admin, started["id"])
    assert done["status"] == "success"
    assert writes(lab)[-1] == "interfaces port 1/1/26 admin-state enable"
    assert lab["SIM-SW-01"].ports["1/1/26"].admin_up
    # New restarts are now blocked.
    plan2 = await prepare(admin, ids["SIM-SW-01"], "1/1/5", MAC_SINGLE_PC)
    assert (await execute(admin, plan2)).status_code == 403


async def test_mode_changes_are_admin_only_and_audited(admin, operator):
    resp = await operator.post("/api/safety/mode", json={"mode": "MAINTENANCE", "reason": "x y z"})
    assert resp.status_code == 403
    # Dedicated safety keys cannot be changed through the generic settings API.
    resp = await admin.put("/api/settings", json={"values": {"operation_mode": "MAINTENANCE"}})
    assert resp.status_code == 422
    resp = await admin.put("/api/settings",
                           json={"values": {"network_command_execution": False}})
    assert resp.status_code == 422
    resp = await admin.post("/api/safety/mode", json={"mode": "MAINTENANCE",
                                                      "reason": "CHG-1234 access refresh"})
    assert resp.status_code == 200 and resp.json()["indicator"] == "ACTIVE"
    audit = (await admin.get("/api/audit", params={"action": "MODE_CHANGE"})).json()
    assert "CHG-1234" in audit["items"][0]["message"]
    events = (await admin.get("/api/safety/events")).json()["items"]
    assert (events[0]["kind"], events[0]["old_value"], events[0]["new_value"]) == (
        "MODE_CHANGE", "NORMAL", "MAINTENANCE")
    bad = await admin.post("/api/safety/mode", json={"mode": "YOLO", "reason": "xxx"})
    assert bad.status_code == 422


async def test_default_mode_is_normal_read_only(admin):
    state = (await admin.get("/api/safety")).json()
    assert state["state"]["mode"] == "NORMAL" and state["indicator"] == "READ ONLY"
    assert state["state"]["state_changes_enabled"] is False


async def test_emergency_mode_blocks_operators(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await go_live(admin, mode="EMERGENCY")
    plan = await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)
    assert plan["execution_allowed"] is False
    assert "EMERGENCY mode" in plan["execution_note"]
    assert (await execute(operator, plan)).status_code == 403
    assert writes(lab) == []
