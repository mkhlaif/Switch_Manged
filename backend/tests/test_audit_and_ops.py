"""Audit logging, secret redaction, settings, profiles/approvals, switch operations, migrations."""

import logging
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect

from app.core.logging import REDACTED, RedactingFilter, redact
from tests.conftest import PASSWORDS, seed_lab_switches


async def test_audit_log_records_admin_actions(admin):
    ids = await seed_lab_switches(["SIM-SW-01"])
    await admin.post("/api/credentials", json={"name": "c1", "username": "u",
                                                "password": "Secret-1234567"})
    await admin.patch(f"/api/switches/{ids['SIM-SW-01']}", json={"location": "B2"})
    await admin.post(f"/api/switches/{ids['SIM-SW-01']}/test")
    await admin.put("/api/settings", json={"values": {"port_bounce_hold_seconds": 7}})
    data = (await admin.get("/api/audit")).json()
    actions = [i["action"] for i in data["items"]]
    for expected in ("LOGIN_SUCCESS", "CREDENTIAL_CREATE", "SWITCH_UPDATE", "SWITCH_TEST",
                     "SETTINGS_UPDATE"):
        assert expected in actions
    assert "Secret-1234567" not in str(data)
    export = await admin.get("/api/audit/export")
    assert export.text.startswith("time,user,action")


class _Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


async def test_passwords_never_reach_the_logs(make_client):
    """Checks raw (pre-redaction) log messages: secrets must never even be passed to a logger."""
    root = logging.getLogger()
    collector = _Collect()
    root.addHandler(collector)
    old_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        api = await make_client()
        await api.login("admin", "Wrong-Password-XYZ")
        await api.login("admin")
        await api.post("/api/credentials", json={"name": "c2", "username": "u",
                                                  "password": "Very-Secret-Switch-99"})
        ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-04"])
        await api.post(f"/api/switches/{ids['SIM-SW-04']}/test")
    finally:
        root.removeHandler(collector)
        root.setLevel(old_level)
    text = "\n".join(collector.messages)
    assert "LOGIN_FAILED" in text and "SWITCH_TEST" in text  # the collector did see the logs
    for secret in ("Wrong-Password-XYZ", PASSWORDS["admin"], "Very-Secret-Switch-99",
                   "lab-password"):
        assert secret not in text
    # The app's own handler carries the redaction filter as a second line of defence.
    assert any(isinstance(f, RedactingFilter) for h in root.handlers for f in h.filters)


def test_redaction_filter():
    assert redact("login password=hunter2 ok") == f"login password={REDACTED} ok"
    assert redact("{'password': 'abc', 'x': 1}") == f"{{'password': {REDACTED}, 'x': 1}}"
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "token=%s", ("abc",), None)
    RedactingFilter().filter(record)
    assert record.getMessage() == f"token={REDACTED}"


async def test_switch_test_connection_uses_show_system_only(operator, lab):
    ids = await seed_lab_switches(["SIM-SW-01", "SIM-SW-04"])
    ok = (await operator.post(f"/api/switches/{ids['SIM-SW-01']}/test")).json()
    assert ok["ok"] and ok["model"] == "OS6860E-P24" and ok["commands"] == ["show system"]
    assert lab["SIM-SW-01"].command_log == ["show system"]
    bad = (await operator.post(f"/api/switches/{ids['SIM-SW-04']}/test")).json()
    assert not bad["ok"] and bad["title"] == "SSH AUTHENTICATION FAILED"


async def test_discovery_identifies_switch_and_selects_profile(admin, lab):
    ids = await seed_lab_switches(["SIM-SW-03"], unknown_version=("SIM-SW-03",))
    before = (await admin.get(f"/api/switches/{ids['SIM-SW-03']}")).json()
    assert before["discovery_status"] == "not_discovered" and before["effective_profile"] is None
    for route in ("discover", "detect"):  # detect = former name of the same endpoint
        result = (await admin.post(f"/api/switches/{ids['SIM-SW-03']}/{route}")).json()
        assert result["ok"] and result["status"] == "discovered", result
        assert result["vendor"] == "ALE" and result["model"] == "OS6450-P24"
        assert result["version"] == "6.7.2.191.R08" and result["profile"] == "AOS6"
        assert result["discovery_profile"] == "ALE_AOS6_SHOW_SYSTEM"
        assert result["commands"] == ["show system"]
    assert lab["SIM-SW-03"].command_log == ["show system", "show system"]
    sw = (await admin.get(f"/api/switches/{ids['SIM-SW-03']}")).json()
    assert sw["discovery_status"] == "discovered" and sw["effective_profile"] == "AOS6"
    assert sw["system_object_id"].startswith("1.3.6.1.4.1.6486.")
    audit = (await admin.get("/api/audit", params={"action": "DEVICE_DISCOVERY"})).json()
    assert audit["items"][0]["result"] == "SUCCESS"


async def test_switch_inventory_crud_and_validation(admin):
    cred = (await admin.post("/api/credentials", json={"name": "c", "username": "u",
                                                        "password": "p"})).json()
    body = {"name": "SW-ACCESS-01", "host": "192.0.2.10", "expected_model": "OS6450-P24",
            "expected_aos_version": "6.7.2.191.R08", "location": "Building A",
            "credential_id": cred["id"], "uplink_ports": ["1/25", "1/26"]}
    # Model / AOS version are discovered, never entered.
    for field, value in (("model", "OS6450-P24"), ("aos_version", "6.7.2.191.R08")):
        typed = await admin.post("/api/switches", json={**body, field: value})
        assert typed.status_code == 422, typed.text
    created = await admin.post("/api/switches", json=body)
    assert created.status_code == 201, created.text
    sw = created.json()
    assert sw["model"] == "" and sw["aos_version"] == ""
    assert sw["expected_model"] == "OS6450-P24" and sw["environment"] == "production"
    assert sw["discovery_status"] == "not_discovered" and sw["effective_profile"] is None
    assert "not been discovered" in sw["profile_reason"]
    assert sw["credential_name"] == "c" and sw["host_key_trusted"] is False
    bad_fp = await admin.post("/api/switches", json={
        **body, "name": "z", "host": "192.0.2.99", "expected_host_key_fingerprint": "abc"})
    assert bad_fp.status_code == 422
    assert (await admin.post("/api/switches", json=body)).status_code == 409
    assert (await admin.post("/api/switches", json={**body, "name": "x", "host": "bad host;"})
            ).status_code == 422
    assert (await admin.post("/api/switches", json={**body, "name": "y",
                                                     "uplink_ports": ["uplink"]})).status_code == 422
    upd = (await admin.patch(f"/api/switches/{sw['id']}", json={"enabled": False})).json()
    assert upd["enabled"] is False
    assert (await admin.delete(f"/api/credentials/{cred['id']}")).status_code == 409
    assert (await admin.delete(f"/api/switches/{sw['id']}")).status_code == 204


async def test_real_ssh_switch_without_host_key_fails_safely(admin):
    cred = (await admin.post("/api/credentials", json={"name": "c", "username": "u",
                                                        "password": "p"})).json()
    sw = (await admin.post("/api/switches", json={
        "name": "NO-KEY", "host": "127.0.0.1", "ssh_port": 1, "credential_id": cred["id"],
        "expected_aos_version": "8.10.94.R03"})).json()
    result = (await admin.post(f"/api/switches/{sw['id']}/test")).json()
    assert not result["ok"] and result["status"] == "hostkey_error"
    # Discovery refuses to run without a trusted key (and without an expected fingerprint).
    outcome = (await admin.post(f"/api/switches/{sw['id']}/discover")).json()
    assert not outcome["ok"] and outcome["status"] == "discovery_failed"
    assert outcome["category"] == "HOST_KEY_UNTRUSTED" and outcome["commands"] == []


async def test_profiles_listing_and_verifications(admin):
    data = (await admin.get("/api/profiles")).json()
    keys = {p["key"]: p for p in data["profiles"]}
    assert set(keys) >= {"AOS6", "AOS7", "AOS8"} and keys["AOS7"]["enabled"] is False
    assert keys["AOS8"]["commands"]["mac_lookup"]["template"] ==         "show mac-learning mac-address {mac}"
    assert "OS6860" in keys["AOS8"]["supported_models"]
    assert "OS6450" in keys["AOS6"]["supported_models"]
    assert keys["AOS8"]["commands"]["mac_lookup"]["verified_by"]

    async def add(**kw):
        body = {"profile_key": "AOS8", "capability": "INTERFACE_ADMIN_STATE",
                "model_family": "OS6900", "version_prefix": "8.10", **kw}
        return await admin.post("/api/profiles/verifications", json=body)

    assert (await add(capability="INTERFACE_ADMIN")).status_code == 422  # AOS 6 strategy
    assert (await add(version_prefix="6.7")).status_code == 422        # wrong AOS family
    assert (await add(model_family="OS6450")).status_code == 422       # AOS 6-only platform
    assert (await add(model_family="OS6860; reload")).status_code == 422
    ok = await add(notes="validated on OS6900 lab switch")
    assert ok.status_code == 201
    record = ok.json()["verifications"][0]
    assert record["verified_by"] == "admin" and record["model_family"] == "OS6900"
    assert record["status"] == "LAB_VERIFIED"
    assert (await add()).status_code == 409
    # Nobody verifies "every model" or a whole major release.
    assert (await add(capability="READ", model_family="*")).status_code == 422
    assert (await add(capability="READ", version_prefix="8")).status_code == 422
    read = await add(capability="READ")
    assert read.status_code == 201
    assert data["profile_states"] == ["DRAFT", "LAB_VERIFIED", "PRODUCTION_VERIFIED",
                                      "BLOCKED", "DEPRECATED"]
    assert keys["AOS8"]["evidence_level"] == "FIXTURE_TESTED" and keys["AOS8"]["version"]
    assert {d["key"] for d in data["discovery_profiles"]} == {"ALE_AOS8_SHOW_SYSTEM",
                                                             "ALE_AOS6_SHOW_SYSTEM"}

    async def status(rid, to, reason="lab review"):
        return await admin.post(f"/api/profiles/verifications/{rid}/status",
                                json={"status": to, "reason": reason})

    # PRODUCTION_VERIFIED needs recorded evidence from a real switch: there is none.
    promote = await status(record["id"], "PRODUCTION_VERIFIED")
    assert promote.status_code == 422 and "No production evidence" in promote.text
    assert (await status(record["id"], "BLOCKED", "x")).status_code == 422  # reason too short
    blocked = await status(record["id"], "BLOCKED", "wrong syntax on 8.10R2")
    assert blocked.status_code == 200
    assert (await add()).status_code == 409  # BLOCKED is not silently re-verified
    assert (await status(record["id"], "PRODUCTION_VERIFIED")).status_code == 409
    assert (await status(record["id"], "LAB_VERIFIED", "fixed in 8.10R3")).status_code == 200
    # Revoke = DEPRECATED (kept for history); adding it again revives it.
    revoked = await admin.delete(f"/api/profiles/verifications/{record['id']}")
    assert revoked.status_code == 200
    row = next(v for v in revoked.json()["verifications"] if v["id"] == record["id"])
    assert row["status"] == "DEPRECATED"
    revived = await add(notes="re-tested")
    assert revived.status_code == 201
    row = next(v for v in revived.json()["verifications"] if v["id"] == record["id"])
    assert row["status"] == "LAB_VERIFIED" and row["notes"] == "re-tested"
    changes = (await admin.get("/api/audit", params={"action": "PROFILE_STATE_CHANGE"})).json()
    assert [i["result"] for i in changes["items"]] == ["SUCCESS", "SUCCESS"]


async def test_custom_profile_is_linted(admin):
    created = await admin.post("/api/profiles", json={"key": "AOS8_EARLY", "name": "AOS 8.1",
                                                       "clone_from": "AOS8"})
    assert created.status_code == 201 and created.json()["enabled"] is False
    evil = await admin.put("/api/profiles/AOS8_EARLY", json={"commands": {
        "mac_lookup": {"template": "interfaces port {port} admin-state disable"}}})
    assert evil.status_code == 422
    evil_write = await admin.put("/api/profiles/AOS8_EARLY", json={"strategies": [{
        "strategy": "INTERFACE_ADMIN_STATE", "down_template": "reload",
        "up_template": "interfaces port {port} admin-state enable", "verification": "doc_syntax"}]})
    assert evil_write.status_code == 422
    ok = await admin.put("/api/profiles/AOS8_EARLY", json={"strategies": [{
        "strategy": "INTERFACE_ADMIN_STATE", "down_template": "interfaces {port} admin-state disable",
        "up_template": "interfaces {port} admin-state enable", "verification": "lab_verified",
        "source": "Lab-validated on 8.1.1"}]})
    assert ok.status_code == 200
    edited = await admin.put("/api/profiles/AOS8_EARLY", json={"commands": {
        "mac_lookup": {"template": "show mac-learning mac-address {mac}"},
        "vlan_port": {"template": "show vlan port {port}"}}})  # allowlisted alternative
    assert edited.json()["commands"]["vlan_port"]["verification"] == "unverified"
    not_allowlisted = await admin.put("/api/profiles/AOS8_EARLY", json={"commands": {
        "vlan_port": {"template": "show vlan members {port}"}}})
    assert not_allowlisted.status_code == 422
    assert (await admin.put("/api/profiles/AOS8", json={"enabled": False})).status_code == 422


async def test_settings_validation(admin, reader):
    assert (await admin.put("/api/settings", json={"values": {"port_bounce_hold_seconds": 0}})
            ).status_code == 422
    assert (await admin.put("/api/settings", json={"values": {"unknown": 1}})).status_code == 422
    assert (await admin.put("/api/settings", json={"values": {
        "operator_restart_classes": ["TRUNK"]}})).status_code == 422
    values = (await reader.get("/api/settings")).json()["values"]
    assert values["dry_run_mode"] is True  # safe default


def test_alembic_migrations_upgrade_to_head(tmp_path):
    backend = Path(__file__).resolve().parents[1]
    db = tmp_path / "migrate.db"
    env = {"DATABASE_URL": f"sqlite+aiosqlite:///{db.as_posix()}", "PATH": ""}
    import os
    env = {**os.environ, **env}
    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=backend,
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    tables = set(inspect(create_engine(f"sqlite:///{db.as_posix()}")).get_table_names())
    assert {"users", "switches", "credentials", "command_profiles", "mac_searches",
            "mac_search_results", "port_actions", "audit_logs", "system_settings",
            "command_verifications", "mac_sightings", "user_sessions", "alerts",
            "safety_events", "port_snapshots", "operation_locks", "ssh_sessions"} <= tables
    assert "strategy_approvals" not in tables and "port_locks" not in tables
    import sqlite3

    con = sqlite3.connect(db)
    triggers = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert {"audit_logs_no_update", "audit_logs_no_delete"} <= triggers
    con.close()
