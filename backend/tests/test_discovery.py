"""Automatic discovery: registry and fixtures, vendor / version normalisation, identity storage,
expected metadata and mismatches, re-verification before a restart, background jobs, profile
evidence and the MAC_OPERATOR boundary. All switches are simulated."""

from __future__ import annotations

import asyncio
import pathlib
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.db.session import session_factory
from app.models import AuditLog, CommandVerification, DiscoveryJob, PortAction, Switch
from app.parsers.alcatel.system import detect_vendor, parse_show_system
from app.services.discovery.registry import (
    DISCOVERY_PROFILES,
    expected_train,
    match_profile,
    normalize_discovered_version,
    output_matches,
)
from app.services.discovery.service import apply_discovery, identity_problems
from app.simulator.scenarios import MAC_ACCESS, MAC_PHONE_PC
from tests.conftest import approve, seed_lab_switches, wait_for_search

ROOT = pathlib.Path(__file__).resolve().parents[1]
CISCO_SHOW_SYSTEM = ("System:\n  Description:  Cisco IOS Software, C2960X Software,\n"
                     "  Object ID:    1.3.6.1.4.1.9.1.1208,\n  Name:         core-1,\n")


# ------------------------------------------------------------------ registry & parsing ---
def test_registry_entries_are_documented_read_only_and_fixture_backed():
    assert {p.generation for p in DISCOVERY_PROFILES} == {"AOS8", "AOS6"}
    for entry in DISCOVERY_PROFILES:
        assert entry.command == "show system" and entry.command_key == "system_info"
        assert entry.safety == "READ_ONLY" and entry.vendor == "ALE"
        assert entry.sources and all("CLI Reference Guide" in s for s in entry.sources)
        assert entry.verification in {"doc_example", "doc_syntax"}
        for fixture in entry.fixtures:
            text = (ROOT / fixture).read_text(encoding="utf-8")
            assert output_matches(entry, text), fixture
            info = parse_show_system(text)
            version = normalize_discovered_version(info.version)
            assert info.vendor == "ALE" and version is not None
            assert match_profile(info.vendor, info.model, version) is entry


def test_vendor_needs_both_the_description_and_the_enterprise_oid():
    ale = "Alcatel-Lucent Enterprise OS6860E-P24 8.9.221.R03 GA, June 12, 2024."
    assert detect_vendor(ale, "1.3.6.1.4.1.6486.801.1.1.2.1.11.1.3") == "ALE"
    assert detect_vendor(ale, "1.3.6.1.4.1.9.1.1208") is None      # other vendor's OID
    assert detect_vendor("Cisco IOS Software", "1.3.6.1.4.1.6486.801.1") is None
    assert detect_vendor(ale, None) is None
    info = parse_show_system(CISCO_SHOW_SYSTEM)
    assert info.vendor is None and info.model is None


@pytest.mark.parametrize("raw,train", [("8.9.221.R03", "8.9"), ("8.10.94.R03", "8.10"),
                                       ("6.7.2.191.R08", "6.7")])
def test_discovered_versions_are_normalised_strictly(raw, train):
    assert normalize_discovered_version(raw).train == train


@pytest.mark.parametrize("raw", ["8.10R1", "8.10", "8.9.221", "8.9.221.R03; reload",
                                 "v8.9.221.R03", "", None, "8.9.221.R03\nshow run"])
def test_malformed_versions_are_rejected(raw):
    assert normalize_discovered_version(raw) is None


def test_expected_versions_compare_on_major_minor():
    assert expected_train("8.10R1") == "8.10" and expected_train("6.7.1") == "6.7"
    assert expected_train("8.9.221.R03") == "8.9" and expected_train("garbage") is None


def test_unsupported_generation_matches_no_registry_entry():
    assert match_profile("ALE", "OS10K", normalize_discovered_version("7.3.4.380.R02")) is None
    assert match_profile("ALE", "OS6450-P24", normalize_discovered_version("8.9.221.R03")) \
        is None  # an AOS 6 platform can never run AOS 8
    assert match_profile(None, "OS6860E-P24", normalize_discovered_version("8.9.221.R03")) \
        is None


# ------------------------------------------------------------------ identity evaluation ---
def _switch(**kw) -> SimpleNamespace:
    base = {"discovery_status": "not_discovered", "model": "", "aos_version": "", "vendor": "",
            "expected_model": "", "expected_aos_version": "", "discovery_category": "",
            "discovery_error": "", "system_name": "", "system_description": "",
            "system_object_id": "", "discovery_profile": "", "discovered_at": None}
    return SimpleNamespace(**{**base, **kw})


def _info(model="OS6860E-P24", version="8.9.221.R03", vendor="ALE"):
    return SimpleNamespace(vendor=vendor, model=model, version=version, name="SW",
                           description=f"Alcatel-Lucent Enterprise {model} {version}",
                           object_id="1.3.6.1.4.1.6486.801.1")


def test_identity_is_stored_and_expected_metadata_is_compared():
    sw = _switch(expected_model="OS6860", expected_aos_version="8.9R1")
    outcome = apply_discovery(sw, _info())
    assert outcome.ok and sw.discovery_status == "discovered"
    assert (sw.vendor, sw.model, sw.aos_version) == ("ALE", "OS6860E-P24", "8.9.221.R03")
    assert sw.discovery_profile == "ALE_AOS8_SHOW_SYSTEM"
    wrong = _switch(expected_model="OS6450", expected_aos_version="8.10R1")
    outcome = apply_discovery(wrong, _info())
    assert outcome.status == "mismatch" and len(outcome.mismatches) == 2
    assert wrong.discovery_category == "SAFETY_CHECK_FAILED"


def test_a_changed_device_becomes_mismatch():
    sw = _switch()
    apply_discovery(sw, _info())
    upgraded = apply_discovery(sw, _info(version="8.10.94.R03"))
    assert upgraded.status == "mismatch" and "AOS version changed" in upgraded.reason
    replaced = apply_discovery(_switch(discovery_status="not_discovered", vendor="ALE",
                                       model="OS6860E-P24", aos_version="8.9.221.R03"),
                               _info(model="OS6900-X20"))  # e.g. after an address change
    assert replaced.status == "mismatch" and "model changed" in replaced.reason


def test_unidentified_devices_fail_closed():
    for info in (_info(vendor=None), _info(version="8.9"), _info(model=None)):
        sw = _switch()
        outcome = apply_discovery(sw, info)
        assert outcome.status == "discovery_failed" and sw.model == ""
        assert outcome.category == "DISCOVERY_FAILED"
    # An identified device no command profile covers: discovered, but PROFILE_NOT_FOUND.
    sw = _switch()
    outcome = apply_discovery(sw, _info(model="OS10K", version="7.3.4.380.R02"))
    assert outcome.ok and sw.discovery_category == "PROFILE_NOT_FOUND"


def test_identity_problems_before_a_state_change():
    sw = _switch(vendor="ALE", model="OS6860E-P24", aos_version="8.9.221.R03")
    assert identity_problems(sw, _info()) == []
    assert identity_problems(sw, _info(version="8.9.221.R04"))
    assert identity_problems(sw, _info(model="OS6860E-P48"))
    assert identity_problems(sw, _info(vendor=None))


# ----------------------------------------------------------------------------- API flows ---
async def test_mismatch_blocks_restart_until_an_admin_accepts(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01"], unknown_version=("SIM-SW-01",))
    async with session_factory()() as db:
        sw = await db.get(Switch, ids["SIM-SW-01"])
        sw.expected_model, sw.role = "OS6450-P24", "access"
        await db.commit()
    result = (await admin.post(f"/api/switches/{ids['SIM-SW-01']}/discover")).json()
    assert result["status"] == "mismatch" and "expected model OS6450-P24" in result["reason"]
    prepared = await operator.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS,
        "method": "link_bounce"})
    body = prepared.json()["error"]
    assert body["code"] == "DISCOVERY_REQUIRED" and body["category"] == "DISCOVERY_FAILED"
    assert lab["SIM-SW-01"].command_log == ["show system"]  # nothing after the refusal
    assert (await operator.post(f"/api/switches/{ids['SIM-SW-01']}/discovery/accept",
                                json={"reason": "replaced by OS6860"})).status_code == 403
    accepted = await admin.post(f"/api/switches/{ids['SIM-SW-01']}/discovery/accept",
                                json={"reason": "switch replaced by an OS6860"})
    assert accepted.status_code == 200
    sw = accepted.json()
    assert sw["discovery_status"] == "discovered" and sw["expected_model"] == "OS6860E-P24"
    assert sw["effective_profile"] == "AOS8"
    again = await admin.post(f"/api/switches/{ids['SIM-SW-01']}/discovery/accept",
                             json={"reason": "twice"})
    assert again.status_code == 409
    from app.security.recorder import get_recorder

    await get_recorder().flush()
    alerts = (await admin.get("/api/alerts", params={"kind": "DISCOVERY_MISMATCH"})).json()
    assert alerts["total"] == 1 and alerts["items"][0]["severity"] == "HIGH"
    audit = (await admin.get("/api/audit", params={"action": "DISCOVERY_ACCEPT"})).json()
    assert audit["items"][0]["details"]["expected_model"] == "OS6450-P24"


async def test_search_discovers_unidentified_switches_and_stores_the_identity(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-03"], unknown_version=("SIM-SW-03",))
    resp = await admin.post("/api/mac/search", json={"mac": MAC_PHONE_PC})
    data = await wait_for_search(admin, resp.json()["id"])
    assert data["found_count"] == 1
    assert lab["SIM-SW-03"].command_log[0] == "show system"
    sw = (await admin.get(f"/api/switches/{ids['SIM-SW-03']}")).json()
    assert sw["discovery_status"] == "discovered" and sw["aos_version"] == "6.7.2.191.R08"
    async with session_factory()() as db:
        entry = (await db.execute(select(AuditLog).where(
            AuditLog.action == "DEVICE_DISCOVERY"))).scalars().one()
        assert entry.details["source"] == "mac-search" and entry.result == "SUCCESS"
    # The next search uses the stored identity: no second discovery command.
    lab["SIM-SW-03"].command_log.clear()
    resp = await admin.post("/api/mac/search", json={"mac": MAC_PHONE_PC})
    await wait_for_search(admin, resp.json()["id"])
    assert "show system" not in lab["SIM-SW-03"].command_log


async def test_other_vendor_answer_is_discovery_failed_and_nothing_else_runs(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-01"], unknown_version=("SIM-SW-01",))
    lab["SIM-SW-01"].behavior.system_output = CISCO_SHOW_SYSTEM
    resp = await admin.post("/api/mac/search", json={"mac": MAC_ACCESS})
    await wait_for_search(admin, resp.json()["id"])
    rows = (await admin.get(f"/api/mac/search/{resp.json()['id']}/results")).json()
    assert rows[0]["status"] == "discovery_failed"
    assert "DISCOVERY FAILED" in rows[0]["error_message"]
    assert lab["SIM-SW-01"].command_log == ["show system"]
    sw = (await admin.get(f"/api/switches/{ids['SIM-SW-01']}")).json()
    assert sw["discovery_status"] == "discovery_failed" and sw["model"] == ""
    assert sw["discovery_category"] == "DISCOVERY_FAILED"


async def test_restart_prepare_reverifies_the_identity_first(admin, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"], roles={"SIM-SW-01": "access"})
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9", model_family="OS6860")
    lab["SIM-SW-01"].version = "8.10.94.R03"  # upgraded behind the platform's back
    resp = await admin.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS,
        "method": "link_bounce"})
    plan = resp.json()
    assert plan["status"] == "denied" and "no longer matches" in plan["blocked_reason"]
    assert plan["outcome"] == "BLOCKED" and plan["error_category"] == "SAFETY_CHECK_FAILED"
    assert lab["SIM-SW-01"].command_log == ["show system"]  # no port was even read
    sw = (await admin.get(f"/api/switches/{ids['SIM-SW-01']}")).json()
    assert sw["discovery_status"] == "mismatch" and sw["aos_version"] == "8.10.94.R03"
    from app.security.circuit_breaker import get_breaker

    assert get_breaker().counters()["profile_mismatches"] == 1


async def test_live_restart_records_outcome_category_profile_version_and_site(
        admin, operator, lab, maintenance):
    ids = await seed_lab_switches(["SIM-SW-01"])
    async with session_factory()() as db:
        (await db.get(Switch, ids["SIM-SW-01"])).site = "Campus North"
        await db.commit()
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9", model_family="OS6860")
    await admin.put("/api/settings", json={"values": {
        "dry_run_mode": False, "port_bounce_hold_seconds": 1,
        "post_restart_verify_seconds": 10}})
    plan = (await operator.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": "1/1/26", "mac": MAC_ACCESS,
        "method": "link_bounce"})).json()
    assert plan["execution_allowed"] and len(plan["profile_version"]) == 12
    from tests.conftest import wait_for_action

    started = (await operator.post("/api/ports/restart", json={
        "plan_token": plan["plan_token"], "confirmations": plan["required_phrases"],
        "reason": "frozen PC"})).json()
    done = await wait_for_action(operator, started["id"])
    assert done["status"] == "success" and done["outcome"] == "SUCCESS", done
    assert done["error_category"] == "" and done["verification"]["verified"] is True
    async with session_factory()() as db:
        entry = (await db.execute(select(AuditLog).where(
            AuditLog.action == "PORT_RESTART", AuditLog.result == "SUCCESS"))).scalars().one()
        assert (entry.site, entry.outcome, entry.profile_version) == (
            "Campus North", "SUCCESS", plan["profile_version"])


async def test_discovery_jobs_api(admin, operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-03", "SIM-SW-04"],
                                  unknown_version=("SIM-SW-01", "SIM-SW-03", "SIM-SW-04"))
    assert (await operator.post("/api/discovery/jobs",
                                json={"all_enabled": True})).status_code == 403
    assert (await admin.post("/api/discovery/jobs", json={})).status_code == 422
    job = (await admin.post("/api/discovery/jobs", json={"all_enabled": True})).json()
    for _ in range(200):
        job = (await admin.get(f"/api/discovery/jobs/{job['id']}")).json()
        if job["status"] not in ("queued", "running"):
            break
        await asyncio.sleep(0.05)
    assert job["status"] == "completed" and (job["total"], job["discovered"], job["failed"]) \
        == (3, 2, 1), job
    failed = next(r for r in job["results"] if r["switch_id"] == ids["SIM-SW-04"])
    assert failed["category"] == "AUTHENTICATION_FAILED"
    # Only one manual job at a time.
    async with session_factory()() as db:
        db.add(DiscoveryJob(created_by="x", status="running", switch_ids=[], total=0))
        await db.commit()
    busy = await admin.post("/api/discovery/jobs", json={"switch_ids": [ids["SIM-SW-01"]]})
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "DISCOVERY_RUNNING"
    registry = (await operator.get("/api/discovery/registry")).json()
    assert {p["command"] for p in registry["profiles"]} == {"show system"}


async def test_switch_created_with_simulator_is_discovered_automatically(admin, lab):
    from app.simulator.scenarios import SIM_PASSWORD, SIM_USERNAME

    cred = (await admin.post("/api/credentials", json={
        "name": "lab", "username": SIM_USERNAME, "password": SIM_PASSWORD})).json()
    created = (await admin.post("/api/switches", json={
        "name": "SIM-SW-02", "host": "SIM-SW-02", "transport": "simulator",
        "credential_id": cred["id"], "environment": "lab"})).json()
    for _ in range(100):
        sw = (await admin.get(f"/api/switches/{created['id']}")).json()
        if sw["discovery_status"] != "not_discovered":
            break
        await asyncio.sleep(0.05)
    assert sw["discovery_status"] == "discovered" and sw["model"] == "OS6900-X20"
    assert sw["effective_profile"] == "AOS8"
    # Changing the address makes it a possibly different device again.
    moved = (await admin.patch(f"/api/switches/{created['id']}",
                               json={"host": "SIM-SW-01"})).json()
    assert moved["discovery_status"] == "not_discovered" or moved["discovery_status"] ==         "mismatch"  # the rediscovery job may already have finished
    for _ in range(100):
        sw = (await admin.get(f"/api/switches/{created['id']}")).json()
        if sw["discovery_status"] != "not_discovered":
            break
        await asyncio.sleep(0.05)
    assert sw["discovery_status"] == "mismatch" and "model changed" in sw["discovery_error"]


# ------------------------------------------------------------- production evidence ---
async def _verification(capability: str, family: str = "OS6860", prefix: str = "8.9") -> int:
    async with session_factory()() as db:
        row = CommandVerification(profile_key="AOS8", capability=capability,
                                  model_family=family, version_prefix=prefix,
                                  verified_by="test-admin")
        db.add(row)
        await db.commit()
        return row.id


async def test_production_promotion_requires_real_switch_evidence(admin):
    strategy_id = await _verification("INTERFACE_ADMIN_STATE")
    read_id = await _verification("READ")

    async def promote(rid):
        return await admin.post(f"/api/profiles/verifications/{rid}/status",
                                json={"status": "PRODUCTION_VERIFIED",
                                      "reason": "validated in the lab"})

    async with session_factory()() as db:
        sim = Switch(name="SIM", host="SIM", transport="simulator", model="OS6860E-P24",
                     aos_version="8.9.221.R03", discovery_status="discovered")
        real = Switch(name="LAB-1", host="10.20.0.1", transport="ssh", model="OS6860E-P48",
                      aos_version="8.9.221.R03", discovery_status="discovered")
        db.add_all([sim, real])
        await db.flush()
        # A verified live restart on the simulator is SIMULATED evidence only.
        db.add(PortAction(switch_id=sim.id, switch_name="SIM", port="1/1/26", mac="x",
                          method="link_bounce",
                          profile_key="AOS8", strategy="INTERFACE_ADMIN_STATE",
                          aos_version="8.9.221.R03", dry_run=False, outcome="SUCCESS",
                          status="success", requested_by="t"))
        await db.commit()
    assert (await promote(strategy_id)).status_code == 422
    assert (await promote(read_id)).status_code == 422
    async with session_factory()() as db:
        db.add(PortAction(switch_id=real.id, switch_name="LAB-1", port="1/1/26", mac="x",
                          method="link_bounce",
                          profile_key="AOS8", strategy="INTERFACE_ADMIN_STATE",
                          aos_version="8.9.221.R03", dry_run=False, outcome="SUCCESS",
                          status="success", requested_by="t"))
        db.add(AuditLog(username="admin", action="PROFILE_VERIFICATION_RUN", result="SUCCESS",
                        profile="AOS8", switch_name="LAB-1",
                        details={"transport": "ssh", "model_family": "OS6860",
                                 "aos_version": "8.9.221.R03"}))
        await db.commit()
    promoted = await promote(strategy_id)
    assert promoted.status_code == 200, promoted.text
    row = next(v for v in promoted.json()["verifications"] if v["id"] == strategy_id)
    assert row["status"] == "PRODUCTION_VERIFIED"
    assert row["evidence"]["production"]["kind"] == "verified_live_restart"
    assert (await promote(read_id)).status_code == 200
    audit = (await admin.get("/api/audit", params={"action": "PROFILE_STATE_CHANGE"})).json()
    assert audit["total"] == 2 and audit["items"][0]["severity"] == "WARNING"


async def test_required_level_and_verification_states(app):
    """Production switches need PRODUCTION_VERIFIED; lab switches and the simulator
    LAB_VERIFIED. "*" records never reach production; BLOCKED wins; DEPRECATED is ignored."""
    from app.services.alcatel.registry import required_level, verification_status

    assert required_level(SimpleNamespace(transport="ssh", environment="production")) ==         "PRODUCTION_VERIFIED"
    assert required_level(SimpleNamespace(transport="ssh", environment="lab")) ==         "LAB_VERIFIED"
    assert required_level(SimpleNamespace(transport="simulator", environment="production"))         == "LAB_VERIFIED"

    async def status(minimum, family="OS6860E-P24", version="8.9.221.R03"):
        async with session_factory()() as db:
            return await verification_status(db, "AOS8", "INTERFACE_ADMIN_STATE", family,
                                             version, minimum=minimum)

    assert "DRAFT" in (await status("LAB_VERIFIED")).detail
    async with session_factory()() as db:
        db.add(CommandVerification(profile_key="AOS8", capability="INTERFACE_ADMIN_STATE",
                                   model_family="*", version_prefix="8.9",
                                   verified_by="t", status="PRODUCTION_VERIFIED"))
        db.add(CommandVerification(profile_key="AOS8", capability="INTERFACE_ADMIN_STATE",
                                   model_family="OS6860", version_prefix="8",
                                   verified_by="t", status="PRODUCTION_VERIFIED"))
        await db.commit()
    lab_ok = await status("LAB_VERIFIED")
    assert lab_ok.verified and lab_ok.level == "LAB_VERIFIED"  # "*" capped; "8" ignored
    prod = await status("PRODUCTION_VERIFIED")
    assert not prod.verified and "need PRODUCTION_VERIFIED" in prod.detail
    async with session_factory()() as db:
        row = CommandVerification(profile_key="AOS8", capability="INTERFACE_ADMIN_STATE",
                                  model_family="OS6860", version_prefix="8.9", verified_by="t",
                                  status="PRODUCTION_VERIFIED")
        db.add(row)
        await db.commit()
        rid = row.id
    assert (await status("PRODUCTION_VERIFIED")).verified
    assert not (await status("PRODUCTION_VERIFIED", version="8.10.94.R03")).verified
    async with session_factory()() as db:
        (await db.get(CommandVerification, rid)).status = "DEPRECATED"
        await db.commit()
    assert not (await status("PRODUCTION_VERIFIED")).verified
    async with session_factory()() as db:
        (await db.get(CommandVerification, rid)).status = "BLOCKED"
        await db.commit()
    blocked = await status("LAB_VERIFIED")
    assert not blocked.verified and blocked.level == "BLOCKED"  # wins over the "*" record


# --------------------------------------------------------------------- circuit breaker ---
@pytest.mark.parametrize("hook,word", [("record_profile_mismatch", "mismatch"),
                                       ("record_verification_failure", "verified")])
async def test_breaker_trips_on_mismatches_and_verification_failures(app, hook, word):
    from app.security.circuit_breaker import CircuitBreaker
    from app.services import system_settings

    breaker = CircuitBreaker()
    for i in range(3):
        getattr(breaker, hook)(switch_name=f"SW-{i}", detail="test")
    await breaker.flush()
    async with session_factory()() as db:
        values = await system_settings.get_all(db)
    assert values["safe_mode"] is True and word in values["safe_mode_reason"]


# ---------------------------------------------------------------- MAC_OPERATOR boundary ---
async def test_mac_operator_errors_never_reveal_technical_details(macop):
    for body in ({"mac": "x" * 500}, {"mac": MAC_ACCESS, "switch_id": 1},
                 {"search_id": "abc", "port": "1/1/1"}, {}):
        for path in ("/api/simple/search", "/api/simple/restart"):
            resp = await macop.post(path, json=body)
            text = resp.text
            assert resp.status_code in (200, 422), text
            for leak in ("switch_id", "port", "mac:", "String should", "Extra inputs",
                         "category", "loc", "VALIDATION"):
                assert leak not in text, (path, body, text)
    missing = await macop.get("/api/simple/nothing-here")
    assert "Not Found" not in missing.text and missing.status_code == 404
    # Discovery / inventory endpoints are not reachable at all.
    for path in ("/api/discovery/jobs", "/api/discovery/registry", "/api/switches"):
        assert (await macop.get(path)).status_code == 403
