"""Port restart safety: policy, confirmations, dry run, approvals, execution and verification.

All switches are simulated; no test can restart a real switch.
"""

from sqlalchemy import select

from app.db.session import session_factory
from app.models import AuditLog
from app.simulator.scenarios import MAC_ACCESS, MAC_PHONE_PC, MAC_WIFI
from tests.conftest import (
    approve,
    seed_lab_switches,
    set_mode,
    wait_for_action,
    wait_for_search,
)

WRITE_PREFIXES = ("interfaces", "lanpower")


def writes(lab, name):
    return [c for c in lab[name].command_log if c.startswith(WRITE_PREFIXES)]


async def prepare(api, switch_id, port, mac, method="link_bounce"):
    return await api.post("/api/ports/restart/prepare", json={
        "switch_id": switch_id, "port": port, "mac": mac, "method": method})


async def execute(api, plan, confirmations=None, reason="test"):
    return await api.post("/api/ports/restart", json={
        "plan_token": plan["plan_token"],
        "confirmations": plan["required_phrases"] if confirmations is None else confirmations,
        "reason": reason})


async def disable_dry_run(admin):
    resp = await admin.put("/api/settings", json={"values": {"dry_run_mode": False,
                                                             "port_bounce_hold_seconds": 1,
                                                             "post_restart_verify_seconds": 10}})
    assert resp.status_code == 200


async def test_access_port_prepare_rechecks_and_defaults_to_dry_run(operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    resp = await prepare(operator, ids["SIM-SW-01"], "1/1/26", "00:11:22:33:44:55")
    plan = resp.json()
    assert resp.status_code == 200, resp.text
    assert plan["status"] == "planned" and plan["available"]
    assert plan["classification"] == "ACCESS" and plan["risk_level"] == "normal"
    assert plan["required_phrases"] == ["RESTART PORT 1/1/26"]
    assert plan["commands"] == ["interfaces port 1/1/26 admin-state disable",
                                "interfaces port 1/1/26 admin-state enable"]
    assert plan["dry_run"] is True and plan["execution_allowed"] is False  # not verified yet
    assert "not verified (DRAFT)" in plan["execution_note"]
    assert plan["steps"][0]["step"] == "recheck" and plan["steps"][0]["ok"]
    assert writes(lab, "SIM-SW-01") == []


async def test_dry_run_executes_nothing(operator, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    resp = await execute(operator, plan)
    done = resp.json()
    assert resp.status_code == 200, resp.text
    assert done["status"] == "dry_run"
    assert "NO COMMANDS WERE EXECUTED" in done["result_message"]
    assert done["commands_executed"] == []
    assert writes(lab, "SIM-SW-01") == []
    assert lab["SIM-SW-01"].ports["1/1/26"].admin_up


async def test_confirmation_must_match_exactly(operator, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    # (Execution is rate limited to 5/min per user, so keep the attempts few.)
    for wrong in (["RESTART PORT"], ["restart port 1/1/26"], ["RESTART PORT 1/1/25"]):
        resp = await execute(operator, plan, wrong)
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "CONFIRMATION_MISMATCH"
    # The plan is still usable after a typo.
    assert (await execute(operator, plan)).json()["status"] == "dry_run"
    # ...but only once.
    assert (await execute(operator, plan)).status_code == 409


async def test_plan_is_bound_to_the_user_who_prepared_it(operator, admin, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    resp = await execute(admin, plan)
    assert resp.status_code == 403


async def test_operator_cannot_restart_trunk_or_ap(operator):
    ids = await seed_lab_switches(["SIM-SW-01"])
    ap = (await prepare(operator, ids["SIM-SW-01"], "1/1/10", MAC_WIFI)).json()
    assert ap["classification"] == "LIKELY_TRUNK"
    assert ap["status"] == "denied" and not ap["available"]
    assert "trunk/uplink" in ap["blocked_reason"] and "No command was executed" in \
        ap["blocked_reason"]
    trunk = (await prepare(operator, ids["SIM-SW-01"], "1/1/49", MAC_PHONE_PC)).json()
    assert trunk["classification"] == "TRUNK" and trunk["status"] == "denied"


async def test_admin_trunk_override_requires_emergency_mode_and_second_phrase(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await set_mode("EMERGENCY")
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/49", MAC_PHONE_PC)).json()
    assert plan["available"] and plan["risk_level"] == "high" and plan["trunk_override"]
    assert plan["required_phrases"] == ["I UNDERSTAND THIS IS A TRUNK", "RESTART PORT 1/1/49"]
    assert any("HIGH RISK" in w for w in plan["warnings"])
    assert (await execute(admin, plan, ["RESTART PORT 1/1/49"])).status_code == 422
    assert (await execute(admin, plan)).json()["status"] == "dry_run"
    assert writes(lab, "SIM-SW-01") == []


async def test_trunk_restart_blocked_by_default_even_for_admin(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/49", MAC_PHONE_PC)).json()
    assert plan["classification"] == "TRUNK"
    assert plan["status"] == "denied"
    assert plan["blocked_reason"] == ("PORT RESTART BLOCKED. This port appears to be a "
                                      "trunk/uplink. No command was executed.")
    assert writes(lab, "SIM-SW-01") == []


async def test_declared_uplink_and_linkagg_are_hard_blocked(admin):
    ids = await seed_lab_switches(["SIM-SW-01"], uplinks={"SIM-SW-01": ["1/1/26"]})
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    assert plan["status"] == "denied" and "declared as an uplink" in plan["blocked_reason"]


async def test_restart_refused_when_mac_not_on_port(operator):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/5", MAC_ACCESS)).json()
    assert plan["status"] == "denied" and "no longer learned on 1/1/5" in plan["blocked_reason"]


async def test_poe_cycle_not_offered_on_non_poe_model(admin):
    ids = await seed_lab_switches(["SIM-SW-02"])
    plan = (await prepare(admin, ids["SIM-SW-02"], "1/1/7", "00:50:56:00:aa:07",
                          method="poe_cycle")).json()
    assert plan["status"] == "denied" and "PORT RESTART NOT AVAILABLE" in plan["blocked_reason"]


async def test_approved_live_restart_with_verification(admin, operator, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    assert plan["execution_allowed"] and not plan["dry_run"]
    started = (await execute(operator, plan, reason="User PC frozen")).json()
    assert started["status"] == "running"
    done = await wait_for_action(operator, started["id"])
    assert done["status"] == "success", done
    assert done["commands_executed"] == plan["commands"]
    assert writes(lab, "SIM-SW-01") == plan["commands"]
    v = done["verification"]
    assert v["port_status"] == "up" and v["mac_learned"] and v["mac_vlan"] == 206
    assert v["vlan_matches"] is True
    assert "PORT RESTART COMPLETED" in done["result_message"]
    assert [s["step"] for s in done["steps"]][:4] == ["recheck", "pre_restart_verification",
                                                        "down", "up"]
    assert lab["SIM-SW-01"].ports["1/1/26"].admin_up


async def test_aos6_live_restart_uses_aos6_syntax(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-03"])
    await approve("AOS6", "INTERFACE_ADMIN", "6.7")
    await disable_dry_run(admin)
    plan = (await prepare(admin, ids["SIM-SW-03"], "1/5", "00:1b:21:00:03:05")).json()
    assert plan["commands"] == ["interfaces 1/5 admin down", "interfaces 1/5 admin up"]
    done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"])
    assert done["status"] == "success", done
    assert writes(lab, "SIM-SW-03") == plan["commands"]


async def test_global_dry_run_wins_over_approval(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    assert plan["execution_allowed"] and plan["dry_run"]
    assert (await execute(admin, plan)).json()["status"] == "dry_run"
    assert writes(lab, "SIM-SW-01") == []


async def test_failed_up_command_is_reported_as_critical(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    lab["SIM-SW-01"].behavior.fail_up_command = True
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    started = (await execute(admin, plan)).json()
    # Shorten the recovery window for the test.
    from app.services.port_control import service
    service.RECOVERY_WINDOW_SECONDS = 1
    try:
        done = await wait_for_action(admin, started["id"], timeout=60)
    finally:
        service.RECOVERY_WINDOW_SECONDS = 90
    assert done["status"] == "failed"
    assert "CRITICAL" in done["error_message"] and "may still be DOWN" in done["error_message"]
    assert "interfaces port 1/1/26 admin-state enable" in done["error_message"]


async def test_final_recheck_aborts_when_mac_moved(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    lab["SIM-SW-01"].ports["1/1/26"].macs = []  # device unplugged after the plan was made
    done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"])
    assert done["status"] == "aborted" and "Nothing was changed" in done["result_message"]
    assert done["result_message"].startswith(
        "Network state changed since confirmation. Operation cancelled for safety.")
    assert writes(lab, "SIM-SW-01") == []


async def test_restart_from_search_result(operator):
    await seed_lab_switches(["SIM-SW-01"])
    search_id = (await operator.post("/api/mac/search", json={"mac": MAC_ACCESS})).json()["id"]
    await wait_for_search(operator, search_id)
    result = (await operator.get(f"/api/mac/search/{search_id}/results")).json()[0]
    plan = (await operator.post("/api/ports/restart/prepare", json={
        "search_result_id": result["id"], "method": "link_bounce"})).json()
    assert plan["status"] == "planned" and plan["port"] == "1/1/26"
    assert plan["search_id"] == search_id


async def test_port_actions_are_audited(operator, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    await execute(operator, plan, ["nope"])
    await execute(operator, plan)
    async with session_factory()() as db:
        rows = (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars().all()
    trail = [(r.action, r.result) for r in rows if r.action.startswith("PORT_RESTART")]
    assert trail == [("PORT_RESTART_PREPARE", "INFO"), ("PORT_RESTART", "DENIED"),
                     ("PORT_RESTART_DRY_RUN", "SUCCESS")]
    dry = [r for r in rows if r.action == "PORT_RESTART_DRY_RUN"][0]
    assert dry.switch_name == "SIM-SW-01" and dry.port == "1/1/26" and dry.mac == MAC_ACCESS
    listing = (await operator.get("/api/ports/actions")).json()
    assert listing["items"][0]["status"] == "dry_run"


# ------------------------------------------------------------------ platform additions ---
async def test_state_change_after_confirmation_aborts(admin, lab, maintenance):
    """§21: VLAN membership changed between confirmation and execution → cancelled."""
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    port = lab["SIM-SW-01"].ports["1/1/26"]
    port.vlans = [*port.vlans, (999, "qtagged")]  # someone re-configured the port meanwhile
    done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"])
    assert done["status"] == "aborted"
    assert "Network state changed since confirmation. Operation cancelled for safety." in \
        done["result_message"]
    assert writes(lab, "SIM-SW-01") == []


async def test_identity_change_after_confirmation_aborts(admin, lab, maintenance):
    """The device is re-identified in the execution session itself, before the down command:
    a switch upgraded (or swapped) between confirmation and execution is never touched."""
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    assert plan["execution_allowed"]
    lab["SIM-SW-01"].version = "8.9.221.R04"
    lab["SIM-SW-01"].command_log.clear()
    done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"])
    assert done["status"] == "aborted" and "identity changed" in done["result_message"]
    assert done["outcome"] == "BLOCKED" and done["error_category"] == "SAFETY_CHECK_FAILED"
    assert lab["SIM-SW-01"].command_log == ["show system"]  # nothing else was sent
    sw = (await admin.get(f"/api/switches/{ids['SIM-SW-01']}")).json()
    assert sw["discovery_status"] == "mismatch"


async def test_change_report_and_structured_audit(admin, operator, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    plan = (await prepare(operator, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    done = await wait_for_action(operator, (await execute(operator, plan)).json()["id"])
    assert done["status"] == "success"
    report = (await operator.get(f"/api/ports/actions/{done['id']}/report")).json()
    assert set(report["snapshots"]) == {"plan", "before", "after"}
    assert report["snapshots"]["before"]["data"]["classification"] == "ACCESS"
    assert report["snapshots"]["after"]["data"]["mac_on_port"] is True
    changed = {c["field"] for c in report["changes"] if c["changed"]}
    assert "vlans" not in changed and "classification" not in changed
    assert len(report["fingerprints"]) == 2 and all(len(f) == 64 for f in report["fingerprints"])
    async with session_factory()() as db:
        row = (await db.execute(select(AuditLog).where(
            AuditLog.action == "PORT_RESTART", AuditLog.result == "SUCCESS"))).scalar_one()
    assert row.role == "operator" and row.operation == "RESTART_PORT"
    assert row.command_fingerprint == report["fingerprints"][0]
    assert row.approval == "confirmed: RESTART PORT 1/1/26"
    assert row.vlan == 206 and row.profile == "AOS8" and row.risk_level == "normal"
    assert row.before_state["mac_on_port"] and row.after_state["oper_status"] == "up"


async def test_mac_not_relearned_is_reported_and_alerted(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    lab["SIM-SW-01"].behavior.relearn_delay = 600  # the device never comes back
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"], timeout=60)
    assert done["status"] == "success"
    assert "WARNING: MAC has not been relearned" in done["result_message"]
    assert done["verification"]["warning"] == "WARNING: MAC has not been relearned"
    from app.security.recorder import get_recorder

    await get_recorder().flush()
    alerts = (await admin.get("/api/alerts", params={"kind": "MAC_NOT_RETURNED"})).json()
    assert alerts["total"] == 1 and alerts["items"][0]["port"] == "1/1/26"


async def test_ambiguous_down_timeout_not_applied(admin, lab, maintenance):
    """The down command gets no answer and was NOT applied: it is never re-sent, the admin
    state is read, and no restore command is needed."""
    from app.services.port_control import service

    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    lab["SIM-SW-01"].behavior.hang_on = ("admin-state disable",)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    service.RECOVERY_WINDOW_SECONDS = 20
    try:
        done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"],
                                     timeout=90)
    finally:
        service.RECOVERY_WINDOW_SECONDS = 90
    assert writes(lab, "SIM-SW-01") == []  # nothing applied, nothing re-sent, no restore
    recovery = [s for s in done["steps"] if s["step"] == "recovery"]
    assert recovery and "restore command was not needed" in recovery[-1]["message"]
    assert lab["SIM-SW-01"].ports["1/1/26"].admin_up


async def test_ambiguous_down_timeout_applied(admin, lab, maintenance):
    """The down command WAS applied but its answer was lost: the down command is never
    re-sent; the admin state is read (disabled) and the port is restored exactly once."""
    from app.services.port_control import service

    ids = await seed_lab_switches(["SIM-SW-01"])
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await disable_dry_run(admin)
    lab["SIM-SW-01"].behavior.silent_on = ("admin-state disable",)
    plan = (await prepare(admin, ids["SIM-SW-01"], "1/1/26", MAC_ACCESS)).json()
    service.RECOVERY_WINDOW_SECONDS = 20
    try:
        done = await wait_for_action(admin, (await execute(admin, plan)).json()["id"],
                                     timeout=90)
    finally:
        service.RECOVERY_WINDOW_SECONDS = 90
    assert writes(lab, "SIM-SW-01") == ["interfaces port 1/1/26 admin-state disable",
                                        "interfaces port 1/1/26 admin-state enable"]
    assert lab["SIM-SW-01"].ports["1/1/26"].admin_up
    assert done["status"] == "success", done["result_message"]
