"""Bulk switch import (CSV / JSON) and export: validation, preview, confirmation, background
batches, idempotency, transaction safety, RBAC and secret exclusion."""

from __future__ import annotations

import asyncio
import csv
import io
import json

import pytest
from sqlalchemy import func, select

from app.core.crypto import encrypt_secret
from app.db.session import session_factory
from app.models import AuditLog, Credential, ImportJob, Switch
from app.services.inventory import bulk
from app.simulator.scenarios import MAC_ACCESS
from tests.conftest import seed_lab_switches

HEADER = "name,hostname,management_ip,model,aos_version,site,role,ssh_port,enabled,credential\n"
GOOD = (HEADER
        + "R-BY-NET-SW-1,sw01,172.17.2.10,OS6360,8.10R1,Main,access,22,true,switch-ro\n"
        + "R-BY-NET-SW-2,sw02,172.17.2.11,OS6450,6.7.1,Main,access,22,true,switch-ro\n")


async def make_credential(name: str = "switch-ro") -> int:
    async with session_factory()() as db:
        cred = Credential(name=name, username="netops-ro",
                          password_encrypted=encrypt_secret("Not-A-Real-Passw0rd"))
        db.add(cred)
        await db.commit()
        return cred.id


async def validate(api, content: str, fmt: str = "csv", filename: str = "switches.csv"):
    return await api.post("/api/switches/import/validate",
                          json={"filename": filename, "format": fmt, "content": content})


async def run_to_end(api, job_id: str, *, on_existing: str = "skip",
                     skip_invalid: bool = False, mode: str = "atomic") -> dict:
    resp = await api.post(f"/api/switches/import/{job_id}/confirm",
                          json={"on_existing": on_existing, "skip_invalid": skip_invalid,
                                "mode": mode})
    assert resp.status_code == 200, resp.text
    for _ in range(600):
        job = (await api.get(f"/api/switches/import/{job_id}")).json()
        if job["status"] not in ("queued", "running"):
            return job
        await asyncio.sleep(0.05)
    raise AssertionError("import did not finish")


async def switch_count() -> int:
    async with session_factory()() as db:
        return (await db.execute(select(func.count()).select_from(Switch))).scalar_one()


def row(job: dict, line: int) -> dict:
    return next(r for r in job["rows"] if r["line"] == line)


# ------------------------------------------------------------------------ happy path ---
async def test_csv_import_preview_confirm_and_idempotency(admin):
    await make_credential()
    preview = (await validate(admin, GOOD)).json()
    assert preview["status"] == "validated"
    assert (preview["total"], preview["valid"], preview["invalid"], preview["duplicates"]) == \
        (2, 2, 0, 0)
    assert preview["new"] == 2
    assert await switch_count() == 0  # nothing is written before confirmation

    # model / aos_version columns are EXPECTED metadata; the fingerprint is missing.
    assert any("ssh_host_key_fingerprint" in w for w in row(preview, 2)["warnings"])
    job = await run_to_end(admin, preview["id"])
    assert job["status"] == "completed" and job["mode"] == "atomic"
    assert (job["imported"], job["updated"], job["unchanged"], job["failed"]) == (2, 0, 0, 0)
    assert job["discovery_job_id"] is None  # no trusted / expected host key: nothing to reach
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch).where(Switch.name == "R-BY-NET-SW-1"))).scalar_one()
        assert (sw.host, sw.hostname, sw.expected_model, sw.expected_aos_version, sw.site,
                sw.role, sw.ssh_port, sw.enabled, sw.transport) == (
            "172.17.2.10", "sw01", "OS6360", "8.10R1", "Main", "access", 22, True, "ssh")
        # The identity is never taken from the file.
        assert (sw.model, sw.aos_version, sw.discovery_status) == ("", "", "not_discovered")
        assert sw.credential_id is not None and sw.host_key == ""
        audit = (await db.execute(select(AuditLog).where(
            AuditLog.action == "SWITCH_IMPORT"))).scalars().all()
        assert audit and audit[-1].details["imported"] == 2

    # Re-importing the same file creates nothing (idempotent).
    again = (await validate(admin, GOOD)).json()
    assert again["new"] == 0 and again["existing_unchanged"] == 2
    job = await run_to_end(admin, again["id"])
    assert (job["imported"], job["unchanged"]) == (0, 2)
    assert await switch_count() == 2


async def test_json_import_with_port_locations(admin):
    await make_credential()
    content = json.dumps({"switches": [{
        "name": "SW-J1", "management_ip": "10.1.1.1", "model": "OS6860E-P24",
        "aos_version": "8.9.221.R03", "role": "access", "credential": "switch-ro",
        "uplink_ports": ["1/1/49", "1/1/50"],
        "port_locations": {"1/1/5": "Building A - Floor 2 - Office 204"}}]})
    preview = (await validate(admin, content, "json", "sw.json")).json()
    assert preview["valid"] == 1, preview
    job = await run_to_end(admin, preview["id"])
    assert job["imported"] == 1
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch).where(Switch.name == "SW-J1"))).scalar_one()
        assert sw.uplink_ports == ["1/1/49", "1/1/50"]
        assert sw.port_locations == {"1/1/5": "Building A - Floor 2 - Office 204"}


async def test_semicolon_delimited_csv(admin):
    await make_credential()
    content = GOOD.replace(",", ";")
    assert (await validate(admin, content)).json()["valid"] == 2


# ------------------------------------------------------------------------ validation ---
BAD_ROWS = [
    ("R-1,,999.1.1.1,OS6360,8.10R1,Main,access,22,true,switch-ro", "not a valid IPv4/IPv6"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,access,70000,true,switch-ro", "outside 1-65535"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,access,ssh,true,switch-ro", "not a number"),
    ("R-1,,10.0.0.1,OS-6360,8.10R1,Main,access,22,true,switch-ro", "not an OmniSwitch model"),
    (",,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro", "name is required"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,router,22,true,switch-ro", "role 'router'"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,access,22,maybe,switch-ro", "must be true or false"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,=cmd|' /C calc'!A0,access,22,true,switch-ro",
     "formula injection"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,@SUM(1),access,22,true,switch-ro", "formula injection"),
    ("sw1;reload,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro", "name may contain"),
    ("R-1,bad_host!,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro", "not a valid DNS"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main $(reboot),access,22,true,switch-ro",
     "not allowed"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,no-such-credential", "does not exist"),
    ("R-1,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro,EXTRA", "Malformed row"),
    ("R-1,,0.0.0.0,OS6360,8.10R1,Main,access,22,true,switch-ro", "cannot be a switch address"),
    ("R-1,,10.0.0.1,OS6360,8.10R1;reload,Main,access,22,true,switch-ro", "not an AOS version"),
]


@pytest.mark.parametrize("line,expected", [
    ("R-1,,10.0.0.1,OS1234,8.10R1,Main,access,22,true,switch-ro", "No command profile covers"),
    ("R-1,,10.0.0.1,OS6450,8.10R1,Main,access,22,true,switch-ro", "No command profile covers"),
    ("R-1,,10.0.0.1,OS6900,7.3.4.R02,Main,access,22,true,switch-ro", "No command profile"),
])
async def test_expected_metadata_is_checked_but_never_trusted(admin, line, expected):
    """Unknown / unsupported expected metadata is a warning (discovery decides), not an error."""
    await make_credential()
    job = (await validate(admin, HEADER + line + "\n")).json()
    assert job["valid"] == 1 and any(expected in w for w in row(job, 2)["warnings"]), job
    # No model / version at all is fine: discovery identifies the switch.
    job = (await validate(admin, "name,management_ip,credential_reference\n"
                                 "SW-A,10.0.0.9,switch-ro\n")).json()
    assert job["valid"] == 1 and not any("profile" in w for w in row(job, 2)["warnings"])


@pytest.mark.parametrize("line,expected", BAD_ROWS)
async def test_invalid_rows_are_reported_not_imported(admin, line, expected):
    await make_credential()
    job = (await validate(admin, HEADER + line + "\n")).json()
    assert job["invalid"] == 1 and job["valid"] == 0, job
    assert any(expected in e for e in row(job, 2)["errors"]), row(job, 2)["errors"]
    resp = await admin.post(f"/api/switches/import/{job['id']}/confirm",
                            json={"skip_invalid": True})
    assert resp.status_code == 422  # no valid rows: nothing to import
    assert await switch_count() == 0


async def test_control_characters_in_json_are_rejected(admin):
    await make_credential()
    content = json.dumps([{"name": "SW-1", "management_ip": "10.0.0.1", "model": "OS6360",
                           "aos_version": "8.10R1", "site": "Main\nINJECTED LINE"}])
    job = (await validate(admin, content, "json")).json()
    assert job["invalid"] == 1
    assert any("control characters" in e for e in job["rows"][0]["errors"])


async def test_duplicates_within_the_file(admin):
    await make_credential()
    content = (HEADER
               + "SW-1,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro\n"
               + "SW-1,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro\n"   # identical
               + "sw-1,,10.0.0.2,OS6360,8.10R1,Main,access,22,true,switch-ro\n"   # same name
               + "SW-3,,10.0.0.1,OS6360,8.10R1,Main,access,22,true,switch-ro\n"   # same IP
               + "SW-4,sw4,10.0.0.4,OS6360,8.10R1,Main,access,22,true,switch-ro\n"
               + "SW-5,SW4,10.0.0.5,OS6360,8.10R1,Main,access,22,true,switch-ro\n")  # hostname
    job = (await validate(admin, content)).json()
    assert (job["valid"], job["duplicates"], job["invalid"]) == (2, 1, 3), job
    assert row(job, 3)["status"] == "duplicate"
    assert "Duplicate name" in row(job, 4)["errors"][0]
    assert "Duplicate management address" in row(job, 5)["errors"][0]
    assert "Duplicate hostname" in row(job, 7)["errors"][0]


@pytest.mark.parametrize("content,expected", [
    ("name,management_ip,model,aos_version,password\nSW,10.0.0.1,OS6360,8.10R1,x\n",
     "secret-like column"),
    ("name,management_ip,model,aos_version,ssh_private_key\nSW,10.0.0.1,OS6360,8.10R1,x\n",
     "Unexpected column"),
    ("name,management_ip,model,aos_version,enable_password\nSW,10.0.0.1,OS6360,8.10R1,x\n",
     "secret-like column"),
    ("name,management_ip,model,aos_version,command\nSW,10.0.0.1,OS6360,8.10R1,reload\n",
     "Unexpected column"),
    ("name,model\nSW,OS6360\n", "Missing required column"),
    ("name,management_ip,model,expected_model\nSW,10.0.0.1,OS6360,OS6360\n",
     "mean the same thing"),
    ("name,management_ip,credential,credential_reference\nSW,10.0.0.1,a,a\n",
     "mean the same thing"),
    ("name,name,management_ip,model,aos_version\n", "more than once"),
    ("", "no header row"),
])
async def test_file_level_rejections(admin, content, expected):
    resp = await validate(admin, content or " ")
    job = resp.json()
    assert job["status"] == "failed" and expected in job["file_errors"][0], job
    assert await switch_count() == 0


async def test_json_with_secret_field_is_rejected(admin):
    content = json.dumps([{"name": "SW", "management_ip": "10.0.0.1", "model": "OS6360",
                           "aos_version": "8.10R1", "password": "hunter2"}])
    job = (await validate(admin, content, "json")).json()
    assert job["status"] == "failed" and "secret-like" in job["file_errors"][0]
    async with session_factory()() as db:
        stored = (await db.get(ImportJob, job["id"]))
        assert "hunter2" not in json.dumps(stored.rows) + stored.error
        audits = (await db.execute(select(AuditLog))).scalars().all()
        assert all("hunter2" not in json.dumps(a.details) + a.message for a in audits)


async def test_invalid_json_and_deep_nesting(admin):
    assert (await validate(admin, "{not json", "json")).json()["status"] == "failed"
    deep = "[" * 100000 + "]" * 100000
    job = (await validate(admin, deep, "json")).json()
    assert job["status"] == "failed"


async def test_size_limits(admin):
    # Pydantic bound on the request body (5 MB) ...
    resp = await validate(admin, "x" * 5_000_001)
    assert resp.status_code == 422
    # ... and the row limit of the importer.
    lines = [f"S{i},,10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256},OS6360,8.10R1,,access,22,"
             "true," for i in range(bulk.MAX_ROWS + 1)]
    job = (await validate(admin, HEADER + "\n".join(lines))).json()
    assert job["status"] == "failed" and "more than" in job["file_errors"][0]


async def test_request_body_limits_apply_before_authentication(make_client, admin):
    anonymous = await make_client()
    big = {"format": "csv", "content": "x" * 13_000_000}
    resp = await anonymous.post("/api/switches/import/validate", json=big)
    assert resp.status_code == 413 and resp.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    resp = await anonymous.post("/api/auth/login", json={"username": "a" * 2_000_000,
                                                         "password": "x"})
    assert resp.status_code == 413
    # A normal-sized import request is not affected.
    assert (await admin.post("/api/switches/import/validate",
                             json={"format": "csv", "content": GOOD})).status_code == 200


# --------------------------------------------------------------- confirmation rules ---
async def test_invalid_rows_must_be_acknowledged(admin):
    await make_credential()
    content = GOOD + "BAD,,not-an-ip,OS6360,8.10R1,Main,access,22,true,switch-ro\n"
    job = (await validate(admin, content)).json()
    # Atomic (default): all rows or none — a file with an invalid row is never imported.
    for body in ({}, {"skip_invalid": True}):
        resp = await admin.post(f"/api/switches/import/{job['id']}/confirm", json=body)
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "INVALID_ROWS_ATOMIC"
    # Per-row mode is an explicit choice, and skipping must still be acknowledged.
    resp = await admin.post(f"/api/switches/import/{job['id']}/confirm",
                            json={"mode": "per_row"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "INVALID_ROWS_NOT_ACKNOWLEDGED"
    assert await switch_count() == 0
    done = await run_to_end(admin, job["id"], skip_invalid=True, mode="per_row")
    assert (done["imported"], done["skipped"]) == (2, 1)
    assert row(done, 4)["result"] == "skipped"


async def test_confirm_only_by_uploader_once_and_one_import_at_a_time(admin, make_client):
    from app.core.security import hash_password
    from app.models import User

    await make_credential()
    async with session_factory()() as db:
        db.add(User(username="admin2", full_name="Admin 2", role="admin",
                    password_hash=hash_password("Second-Admin-Passw0rd!")))
        await db.commit()
    other = await make_client()
    await other.login("admin2", "Second-Admin-Passw0rd!")
    job = (await validate(admin, GOOD)).json()
    assert (await other.post(f"/api/switches/import/{job['id']}/confirm",
                             json={})).status_code == 409
    # Simulate a running import: a second confirmation must wait.
    async with session_factory()() as db:
        db.add(ImportJob(created_by="x", status="running", file_format="csv"))
        await db.commit()
    resp = await admin.post(f"/api/switches/import/{job['id']}/confirm", json={})
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "IMPORT_RUNNING"


async def test_expired_preview_cannot_be_confirmed(admin):
    from datetime import timedelta

    from app.core.timeutil import utcnow

    await make_credential()
    job = (await validate(admin, GOOD)).json()
    async with session_factory()() as db:
        stored = await db.get(ImportJob, job["id"])
        stored.expires_at = utcnow() - timedelta(seconds=1)
        await db.commit()
    resp = await admin.post(f"/api/switches/import/{job['id']}/confirm", json={})
    assert resp.status_code == 409 and "expired" in resp.json()["error"]["message"]
    assert await switch_count() == 0


async def test_cancel_before_start(admin):
    await make_credential()
    job = (await validate(admin, GOOD)).json()
    assert (await admin.post(f"/api/switches/import/{job['id']}/cancel")).json()["status"] == \
        "cancelled"
    assert (await admin.post(f"/api/switches/import/{job['id']}/confirm",
                             json={})).status_code == 409


# ------------------------------------------------------------------ existing switches ---
async def test_existing_switches_are_never_silently_overwritten(admin):
    cred = await make_credential()
    async with session_factory()() as db:
        db.add(Switch(name="R-BY-NET-SW-1", host="172.17.2.10", hostname="sw01",
                      expected_model="OS6360", expected_aos_version="8.10R1", model="OS6360",
                      aos_version="8.10.94.R01", discovery_status="discovered",
                      site="Old site", role="access", credential_id=cred,
                      host_key="ssh-ed25519 AAAA", host_key_fingerprint="fp"))
        await db.commit()
    job = (await validate(admin, GOOD)).json()
    assert job["existing_changed"] == 1 and row(job, 2)["diff"] == ["site"]
    done = await run_to_end(admin, job["id"])  # default: skip existing
    assert row(done, 2)["result"] == "skipped" and done["imported"] == 1
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch).where(Switch.name == "R-BY-NET-SW-1"))).scalar_one()
        assert sw.site == "Old site"

    # Explicit update: applied, and a changed SSH endpoint clears the trusted host key.
    moved = GOOD.replace("172.17.2.10", "172.17.2.99")
    job = (await validate(admin, moved)).json()
    done = await run_to_end(admin, job["id"], on_existing="update")
    assert row(done, 2)["result"] == "updated" and "host key cleared" in row(done, 2)["message"]
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch).where(Switch.name == "R-BY-NET-SW-1"))).scalar_one()
        assert (sw.site, sw.host, sw.host_key, sw.host_key_fingerprint) == \
            ("Main", "172.17.2.99", "", "")
        # Another address may be another device: rediscovery before any state change.
        assert sw.discovery_status == "not_discovered"


async def test_address_owned_by_another_switch_is_an_error(admin):
    await make_credential()
    async with session_factory()() as db:
        db.add(Switch(name="EXISTING", host="172.17.2.10", model="OS6360", aos_version="8.10R1"))
        await db.commit()
    job = (await validate(admin, GOOD)).json()
    assert "already belongs to switch 'EXISTING'" in row(job, 2)["errors"][0]


async def test_row_taken_concurrently_after_preview_rolls_back_atomic_import(admin):
    await make_credential()
    job = (await validate(admin, GOOD)).json()
    # Between preview and confirmation someone adds a switch with the same address.
    resp = await admin.post("/api/switches", json={"name": "RACE", "host": "172.17.2.11",
                                                    "expected_model": "OS6450"})
    assert resp.status_code == 201
    done = await run_to_end(admin, job["id"])
    assert done["status"] == "failed" and "rolled back" in done["error"], done
    assert done["imported"] == 0
    assert row(done, 2)["result"] == "rolled_back"
    assert await switch_count() == 1  # RACE only: the atomic import left nothing behind


async def test_row_taken_concurrently_after_preview_fails_alone_per_row(admin):
    await make_credential()
    job = (await validate(admin, GOOD)).json()
    resp = await admin.post("/api/switches", json={"name": "RACE", "host": "172.17.2.11"})
    assert resp.status_code == 201
    done = await run_to_end(admin, job["id"], mode="per_row")
    assert row(done, 2)["result"] == "imported"
    assert row(done, 3)["result"] == "failed" and "RACE" in row(done, 3)["message"]
    assert (done["imported"], done["failed"]) == (1, 1)
    assert await switch_count() == 2  # RACE + SW-1; no partial/corrupt rows


async def test_export_then_import_is_unchanged_round_trip(admin):
    cred = await make_credential()
    async with session_factory()() as db:
        db.add(Switch(name="SW-RT", host="10.4.4.4", hostname="sw-rt", credential_id=cred,
                      expected_model="OS6860", model="OS6860E-P24",
                      aos_version="8.9.221.R03", vendor="ALE", discovery_status="discovered",
                      host_key="ssh-ed25519 AAAAC3Nza", host_key_fingerprint="SHA256:" + "A" * 43,
                      site="Main", role="access", environment="lab",
                      uplink_ports=["1/1/49"], port_locations={"1/1/5": "Office 204"}))
        await db.commit()
    for fmt in ("csv", "json"):
        exported = (await admin.get("/api/switches/export", params={"format": fmt})).text
        job = (await validate(admin, exported, fmt, f"switches.{fmt}")).json()
        assert job["valid"] == 1 and job["existing_unchanged"] == 1, job
        assert row(job, 2 if fmt == "csv" else 1)["diff"] == []


async def test_fingerprint_that_contradicts_the_trusted_key_is_an_error(admin):
    cred = await make_credential()
    async with session_factory()() as db:
        db.add(Switch(name="SW-FP", host="10.5.5.5", credential_id=cred,
                      host_key="ssh-ed25519 AAAA", host_key_fingerprint="SHA256:" + "B" * 43))
        await db.commit()
    content = ("name,management_ip,credential_reference,ssh_host_key_fingerprint\n"
               f"SW-FP,10.5.5.5,switch-ro,SHA256:{'C' * 43}\n")
    job = (await validate(admin, content)).json()
    assert job["invalid"] == 1 and "differs from the host key already trusted" in \
        row(job, 2)["errors"][0]
    bad = (await validate(admin, "name,management_ip,ssh_host_key_fingerprint\n"
                                 "SW-Q,10.5.5.6,MD5:aa:bb\n")).json()
    assert bad["invalid"] == 1 and "OpenSSH SHA256" in row(bad, 2)["errors"][0]


async def test_import_with_fingerprint_starts_discovery(admin):
    """A fingerprint supplied out of band lets discovery run right after the import. Here the
    address is unreachable: the switch ends DISCOVERY_FAILED, nothing is trusted."""
    await make_credential()
    content = ("name,management_ip,ssh_port,credential_reference,ssh_host_key_fingerprint\n"
               f"SW-D,127.0.0.1,1,switch-ro,SHA256:{'D' * 43}\n")
    job = await run_to_end(admin, (await validate(admin, content)).json()["id"])
    assert job["imported"] == 1 and job["discovery_job_id"], job
    for _ in range(200):
        discovery = (await admin.get(f"/api/discovery/jobs/{job['discovery_job_id']}")).json()
        if discovery["status"] not in ("queued", "running"):
            break
        await asyncio.sleep(0.05)
    assert discovery["status"] == "completed" and discovery["failed"] == 1, discovery
    async with session_factory()() as db:
        sw = (await db.execute(select(Switch).where(Switch.name == "SW-D"))).scalar_one()
        assert sw.discovery_status == "discovery_failed" and sw.host_key == ""
        assert sw.discovery_category == "DEVICE_UNREACHABLE"


async def test_database_constraints_back_the_validation(admin):
    """Even if validation were bypassed, the database refuses duplicates and bad values."""
    from sqlalchemy.exc import IntegrityError

    async with session_factory()() as db:
        db.add(Switch(name="A", host="10.9.9.9", model="OS6360", aos_version="8.10R1"))
        db.add(Switch(name="HOSTNAMED", host="sw-a.example", model="OS6360",
                      aos_version="8.10R1"))
        await db.commit()
    # Duplicates differing only in upper/lower case are duplicates too (name "a", host
    # "SW-A.EXAMPLE").
    for bad in (dict(name="B", host="10.9.9.9"), dict(name="a", host="10.9.9.3"),
                dict(name="H", host="SW-A.EXAMPLE"), dict(name="C", host="10.9.9.8", ssh_port=0),
                dict(name="D", host="10.9.9.7", role="router"),
                dict(name="E", host="10.9.9.6", transport="telnet")):
        async with session_factory()() as db:
            db.add(Switch(model="OS6360", aos_version="8.10R1", **bad))
            with pytest.raises(IntegrityError):
                await db.commit()
    async with session_factory()() as db:
        db.add(Switch(name="F", host="10.9.9.5", hostname="dup"))
        db.add(Switch(name="G", host="10.9.9.4", hostname="dup"))
        with pytest.raises(IntegrityError):
            await db.commit()


async def test_manual_create_reports_duplicate_address(admin):
    body = {"name": "A", "host": "10.0.0.1", "expected_model": "OS6360"}
    assert (await admin.post("/api/switches", json=body)).status_code == 201
    resp = await admin.post("/api/switches", json={**body, "name": "B"})
    assert resp.status_code == 409 and "already used by switch 'A'" in resp.json()["error"][
        "message"]


# ---------------------------------------------------------------------------- export ---
async def test_export_never_contains_secrets_and_is_formula_safe(admin):
    cred = await make_credential()
    async with session_factory()() as db:
        db.add(Switch(name="SW-X", host="10.0.0.1", model="OS6360", aos_version="8.10R1",
                      description="=HYPERLINK(\"http://evil\")", credential_id=cred,
                      host_key="ssh-ed25519 AAAAC3NzaSECRETISH", host_key_fingerprint="SHA256:x",
                      port_locations={"1/1/5": "Office 204"}))
        await db.commit()
    resp = await admin.get("/api/switches/export", params={"format": "csv"})
    assert resp.status_code == 200
    assert resp.headers["content-disposition"].startswith('attachment; filename="switches-')
    text = resp.text
    for secret in ("Not-A-Real-Passw0rd", "AAAAC3Nza", "ssh-ed25519", "password_encrypted"):
        assert secret not in text
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["description"].startswith("'=")  # neutralised formula
    assert rows[0]["credential_reference"] == "switch-ro"  # reference by name only
    assert rows[0]["ssh_host_key_fingerprint"] == "SHA256:x"  # public fingerprint only

    data = (await admin.get("/api/switches/export", params={"format": "json"})).json()
    assert data["count"] == 1 and data["switches"][0]["port_locations"] == {"1/1/5": "Office 204"}
    dumped = json.dumps(data)
    for secret in ("Not-A-Real-Passw0rd", "AAAAC3Nza", "ssh-ed25519", "password"):
        assert secret not in dumped
    audit = [a async for a in _audit("SWITCH_EXPORT")]
    assert len(audit) == 2


async def _audit(action: str):
    async with session_factory()() as db:
        for a in (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars():
            yield a


@pytest.mark.parametrize("fmt", ["csv", "json"])
async def test_export_reimport_round_trip_is_unchanged(admin, fmt):
    await make_credential()
    job = (await validate(admin, GOOD)).json()
    await run_to_end(admin, job["id"])
    exported = (await admin.get("/api/switches/export", params={"format": fmt})).text
    again = (await validate(admin, exported, fmt)).json()
    assert again["valid"] == 2 and again["existing_unchanged"] == 2, again


async def test_export_rejects_bad_format(admin):
    resp = await admin.get("/api/switches/export", params={"format": "../../etc/passwd"})
    assert resp.status_code == 422


async def test_error_report_is_formula_safe(admin):
    await make_credential()
    job = (await validate(admin, HEADER + "=1+1,,x,OS6360,8.10R1,,access,22,true,switch-ro\n")
           ).json()
    report = (await admin.get(f"/api/switches/import/{job['id']}/report")).text
    rows = list(csv.DictReader(io.StringIO(report)))
    assert rows[0]["name"].startswith("'=") and rows[0]["status"] == "invalid"


# ------------------------------------------------------------------------------ RBAC ---
@pytest.mark.parametrize("who", ["reader", "operator", "macop"])
async def test_only_administrators_can_import_or_export(make_client, who):
    api = await make_client(who)
    checks = [
        await api.get("/api/switches/export"),
        await api.get("/api/switches/import"),
        await api.get("/api/switches/import/template"),
        await api.post("/api/switches/import/validate",
                       json={"format": "csv", "content": GOOD}),
        await api.post("/api/switches/import/00000000-0000-0000-0000-000000000000/confirm",
                       json={}),
    ]
    assert [r.status_code for r in checks] == [403] * 5


async def test_template_downloads(admin):
    csv_t = (await admin.get("/api/switches/import/template")).text
    assert csv_t.startswith("name,hostname,management_ip") and "password" not in csv_t
    json_t = (await admin.get("/api/switches/import/template", params={"format": "json"})).json()
    assert json_t["switches"][0]["port_locations"]


# ------------------------------------------------------------------- concurrency ---
async def test_import_while_search_and_export_run(admin, reader, lab):
    await make_credential()
    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"])
    search = (await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})).json()
    job = (await validate(admin, GOOD)).json()
    confirm = admin.post(f"/api/switches/import/{job['id']}/confirm", json={})
    export = admin.get("/api/switches/export", params={"format": "json"})
    confirmed, exported = await asyncio.gather(confirm, export)
    assert confirmed.status_code == 200 and exported.status_code == 200
    for _ in range(600):
        s = (await reader.get(f"/api/mac/search/{search['id']}")).json()
        j = (await admin.get(f"/api/switches/import/{job['id']}")).json()
        if s["status"] == "completed" and j["status"] == "completed":
            break
        await asyncio.sleep(0.05)
    assert s["status"] == "completed" and j["status"] == "completed"
    assert j["imported"] == 2 and await switch_count() == 4


async def test_bulk_import_of_1000_switches(admin):
    await make_credential()
    lines = [f"BULK-{i:04d},bulk{i:04d},10.50.{i // 250}.{i % 250 + 1},OS6360,8.10R1,Main,"
             "access,22,true,switch-ro" for i in range(1000)]
    job = (await validate(admin, HEADER + "\n".join(lines) + "\n")).json()
    assert job["valid"] == 1000
    done = await run_to_end(admin, job["id"])
    assert done["status"] == "completed" and done["imported"] == 1000
    assert await switch_count() == 1000
    export = (await admin.get("/api/switches/export", params={"format": "csv"})).text
    assert export.count("\n") == 1001
