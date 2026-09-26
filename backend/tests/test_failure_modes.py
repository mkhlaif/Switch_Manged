"""Failure modes that must never turn into an unsafe network operation."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import OperationalError

from app.simulator.scenarios import MAC_ACCESS
from tests.conftest import approve, seed_lab_switches, set_mode, wait_for_action
from tests.test_port_restart import disable_dry_run, execute, prepare
from tests.test_rbac_simple import CANNOT, seed_access, simple_search, writes


async def test_switch_unreachable_after_down_is_critical_and_down_is_never_resent(
        admin, lab, maintenance, monkeypatch):
    """The switch 'disappears' right after the down command: the up command times out and
    every reconnect is refused. The result is a CRITICAL failure with manual instructions —
    the down command is sent exactly once and nothing else is attempted blindly."""
    from app.services.port_control import service

    monkeypatch.setattr(service, "RECOVERY_WINDOW_SECONDS", 2)
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    sw = lab["SIM-SW-01"]
    sw.behavior.hang_on = ("admin-state enable",)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    started = (await execute(admin, plan)).json()

    original_hold = service.asyncio.sleep

    async def hold_then_disappear(seconds, *a, **kw):
        if seconds == 1:  # the hold between down and up
            sw.behavior.connect_refused = True
        return await original_hold(seconds, *a, **kw)

    monkeypatch.setattr(service.asyncio, "sleep", hold_then_disappear)
    done = await wait_for_action(admin, started["id"], timeout=90)
    assert done["status"] == "failed"
    assert "CRITICAL" in done["error_message"] and "may still be DOWN" in done["error_message"]
    downs = [c for c in sw.command_log if c.endswith("admin-state disable")]
    assert downs == ["interfaces port 1/1/26 admin-state disable"]


async def test_database_failure_during_simple_restart_executes_nothing(macop, admin, lab,
                                                                       monkeypatch):
    await seed_access(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await admin.put("/api/settings", json={"values": {"dry_run_mode": False}})
    await set_mode("MAINTENANCE")
    found = await simple_search(macop, MAC_ACCESS)

    async def db_down(*a, **kw):
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    monkeypatch.setattr("app.api.routes.simple.prepare_restart", db_down)
    resp = (await macop.post("/api/simple/restart", json={"search_id": found["search_id"]}))
    assert resp.json() == {"state": "error",
                           "message": "Something went wrong. Please try again or contact IT "
                                      "support."}
    assert writes(lab) == []


async def test_database_failure_during_search_is_generic_for_mac_operator(macop, lab,
                                                                          monkeypatch):
    await seed_access(["SIM-SW-01"])

    async def db_down(*a, **kw):
        raise OperationalError("INSERT", {}, Exception("disk I/O error"))

    monkeypatch.setattr("app.api.routes.simple.start_search", db_down)
    resp = (await macop.post("/api/simple/search", json={"mac": MAC_ACCESS})).json()
    assert resp == {"state": "error",
                    "message": "Something went wrong. Please try again or contact IT support."}


@pytest.mark.parametrize("behavior,value", [
    ("hang_on", ("show mac-learning",)),      # SSH command timeout
    ("malformed_on", ("show mac-learning",)),  # invalid AOS response
    ("silent_on", ("show mac-learning",)),     # command executed, prompt never returns
    ("auth_fail", True),                       # SSH authentication failure
    ("connect_refused", True),                 # switch unreachable
])
async def test_switch_failures_never_offer_a_restart(macop, admin, lab, behavior, value):
    await seed_access(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await set_mode("MAINTENANCE")
    setattr(lab["SIM-SW-01"].behavior, behavior, value)
    result = await simple_search(macop, MAC_ACCESS)
    assert result["state"] == "error" and result.get("can_restart") is not True
    resp = (await macop.post("/api/simple/restart", json={"search_id": result["search_id"]}))
    assert resp.json() == {"state": "blocked", "message": CANNOT}
    assert writes(lab) == []
