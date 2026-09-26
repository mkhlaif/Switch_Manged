"""Regression tests for the findings of AUDIT_REPORT.md (hardening pass)."""

import csv
import io
import logging
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, update

from app.core.config import Settings
from app.core.logging import RedactingFilter
from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import UserSession
from app.simulator.scenarios import MAC_ACCESS
from tests.conftest import seed_lab_switches, set_mode, wait_for_search

ROOT = Path(__file__).resolve().parents[2]

# §10 of the requirements: every one of these must be rejected before any SSH command.
INJECTIONS = [
    "00:11:22:33:44:55;reload",
    "00:11:22:33:44:55 && reload",
    "00:11:22:33:44:55 | reload",
    "00:11:22:33:44:55\nreload",
    "$(reload)",
    "`reload`",
    "00:11:22:33:44:55; configure terminal",
    "00:11:22:33:44:55'; DROP TABLE users; --",
]


def sent(lab):
    return [c for sw in lab.values() for c in sw.command_log]


# ------------------------------------------------------------------------ S1 proxy headers ---
def test_nginx_overwrites_x_forwarded_for():
    conf = (ROOT / "frontend/nginx/app-locations.conf").read_text(encoding="utf-8")
    assert "$proxy_add_x_forwarded_for" not in conf
    directives = [line.strip() for line in conf.splitlines()
                  if line.strip().startswith("proxy_set_header X-Forwarded-For")]
    assert directives and all(d.endswith("$remote_addr;") for d in directives)


# --------------------------------------------------------------------- S2 CSV injection ---
async def test_csv_exports_neutralise_formulas(admin, make_client):
    attacker = await make_client()
    evil = '=HYPERLINK("http://evil","x")'
    assert (await attacker.post("/api/auth/login", json={"username": evil, "password": "x"})
            ).status_code == 401
    body = (await admin.get("/api/audit/export")).text
    cells = [c for row in csv.reader(io.StringIO(body)) for c in row]
    assert "'" + evil.lower() in cells or "'" + evil in cells
    assert evil not in cells and evil.lower() not in cells


def test_csv_cell_rules():
    from app.core.csv_safe import csv_cell

    for value in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx"):
        assert csv_cell(value) == "'" + value
    assert csv_cell("SW-ACCESS-01") == "SW-ACCESS-01" and csv_cell(5) == 5


# ------------------------------------------------------------ S3 own role / own account ---
async def test_admin_cannot_change_own_role_or_disable_self(admin):
    me = (await admin.get("/api/auth/me")).json()["user"]
    r = await admin.patch(f"/api/users/{me['id']}", json={"role": "operator"})
    assert r.status_code == 422 and "own role" in r.json()["error"]["message"]
    r = await admin.patch(f"/api/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 422
    # Unchanged role and other fields are still editable.
    assert (await admin.patch(f"/api/users/{me['id']}", json={"full_name": "Chief"})).status_code == 200
    assert (await admin.patch(f"/api/users/{me['id']}", json={"role": "admin"})).status_code == 200
    # Changing another user's role works.
    users = {u["username"]: u for u in (await admin.get("/api/users")).json()}
    assert (await admin.patch(f"/api/users/{users['reader']['id']}", json={"role": "operator"})
            ).status_code == 200


# ------------------------------------------------------------------- S4 idle timeout ---
async def test_idle_session_is_ended(reader):
    assert (await reader.get("/api/auth/me")).status_code == 200
    async with session_factory()() as db:
        await db.execute(update(UserSession).values(last_seen_at=utcnow() - timedelta(hours=3)))
        await db.commit()
    r = await reader.get("/api/auth/me")
    assert r.status_code == 401 and "inactivity" in r.json()["error"]["message"]
    async with session_factory()() as db:
        assert (await db.execute(select(UserSession))).scalars().all() == []  # session deleted


# ------------------------------------------------------------------ S5 log injection ---
def test_log_lines_cannot_be_forged():
    record = logging.LogRecord("t", logging.WARNING, __file__, 1,
                               "LOGIN_FAILED user=%s", ("bob\n2026-01-01 AUDIT forged",), None)
    RedactingFilter().filter(record)
    assert "\n" not in record.getMessage() and "\\n" in record.getMessage()


# --------------------------------------------------------------- S6 password lengths ---
async def test_password_length_is_bounded(admin):
    r = await admin.post("/api/auth/change-password",
                         json={"current_password": "x", "new_password": "A1!" + "a" * 300})
    assert r.status_code == 422


# -------------------------------------------------------------- F1 default kill switch ---
def test_fresh_install_defaults_block_state_changes(monkeypatch):
    monkeypatch.delenv("NETWORK_COMMAND_EXECUTION", raising=False)
    monkeypatch.delenv("READ_ONLY_MODE", raising=False)
    s = Settings(_env_file=None)
    assert s.network_command_execution == "DISABLED"
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "${NETWORK_COMMAND_EXECUTION:-DISABLED}" in compose
    assert "${READ_ONLY_MODE:-true}" in compose
    # Web ports are published on localhost only unless the administrator opts in to LAN access.
    assert '"${BIND_ADDRESS:-127.0.0.1}:${HTTP_PORT:-8080}:8080"' in compose
    assert '"${BIND_ADDRESS:-127.0.0.1}:${HTTPS_PORT:-8443}:8443"' in compose
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "NETWORK_COMMAND_EXECUTION=DISABLED" in example and "READ_ONLY_MODE=true" in example


# ------------------------------------------------------------------------- B1 health ---
async def test_health_reports_components_without_secrets(make_client):
    anon = await make_client()
    for path in ("/health", "/api/health"):
        r = await anon.get(path)
        data = r.json()
        assert r.status_code == 200 and data["status"] == "healthy"
        assert data["database"] == "ok" and data["safety_firewall"] == "ok"
        text = r.text.lower()
        assert "sqlite" not in text and "postgres" not in text and "password" not in text


async def test_health_returns_503_when_database_is_down(make_client, monkeypatch):
    from app import main

    def broken():
        raise RuntimeError("db down")

    monkeypatch.setattr(main, "session_factory", broken)
    r = await (await make_client()).get("/health")
    assert r.status_code == 503 and r.json()["status"] == "unhealthy"
    assert r.json()["database"] == "unavailable"


# -------------------------------------------------------------- T4 injection matrix ---
@pytest.mark.parametrize("value", INJECTIONS)
async def test_mac_injection_rejected_everywhere(reader, macop, lab, value):
    await seed_lab_switches(["SIM-SW-01"])
    r = await reader.post("/api/mac/search", json={"mac": value})
    assert r.status_code == 422 and r.json()["error"]["code"] == "COMMAND_BLOCKED"
    r = await reader.post("/api/operations", json={"operation": "SEARCH_MAC", "mac": value})
    assert r.status_code == 422
    r = await macop.post("/api/simple/search", json={"mac": value})
    assert r.json()["state"] == "invalid"
    assert sent(lab) == []


@pytest.mark.parametrize("value", ["1/1/26;reload", "1/1/26 && reload", "1/1/26 | reload",
                                   "1/1/26\nreload", "$(reload)", "`reload`"])
async def test_port_injection_rejected(operator, lab, value):
    ids = await seed_lab_switches(["SIM-SW-01"])
    r = await operator.post("/api/operations", json={
        "operation": "GET_PORT_STATUS", "switch_id": ids["SIM-SW-01"], "port": value})
    assert r.status_code == 422
    r = await operator.post("/api/ports/restart/prepare", json={
        "switch_id": ids["SIM-SW-01"], "port": value, "mac": MAC_ACCESS})
    assert r.status_code == 422
    assert sent(lab) == []


@pytest.mark.parametrize("value", ["1;reload", "1 OR 1=1", "$(reload)", "../../etc/passwd"])
async def test_switch_id_and_path_injection_rejected(reader, lab, value):
    await seed_lab_switches(["SIM-SW-01"])
    r = await reader.post("/api/operations", json={
        "operation": "GET_PORT_VLAN", "switch_id": value, "port": "1/1/26"})
    assert r.status_code == 422
    r = await reader.get(f"/api/mac/search/{value}")
    assert r.status_code in (404, 422)
    assert sent(lab) == []


@pytest.mark.parametrize("value", ["admin'--", "admin\nreload", "$(reload)", "a" * 65])
async def test_username_injection_is_harmless(make_client, admin, value):
    anon = await make_client()
    r = await anon.post("/api/auth/login", json={"username": value, "password": "whatever"})
    assert r.status_code in (401, 422)
    r = await admin.post("/api/users", json={"username": value, "password": "Str0ng-Passw0rd!!"})
    assert r.status_code == 422


# --------------------------------------------------------- B2 MAC operator message ---
async def test_mac_operator_sees_required_message_when_device_does_not_return(
        macop, admin, lab):
    from tests.conftest import approve

    await seed_lab_switches(["SIM-SW-01", "SIM-SW-02"], roles={"SIM-SW-01": "access"})
    await approve("AOS8", "INTERFACE_ADMIN_STATE", "8.9")
    await admin.put("/api/settings", json={"values": {
        "dry_run_mode": False, "port_bounce_hold_seconds": 1, "post_restart_verify_seconds": 10}})
    await set_mode("MAINTENANCE")
    lab["SIM-SW-01"].behavior.relearn_delay = 600
    import asyncio

    st = (await macop.post("/api/simple/search", json={"mac": MAC_ACCESS})).json()
    for _ in range(200):
        res = (await macop.get(f"/api/simple/search/{st['search_id']}")).json()
        if res["state"] != "searching":
            break
        await asyncio.sleep(0.05)
    started = (await macop.post("/api/simple/restart", json={"search_id": st["search_id"]})).json()
    assert started["state"] == "running"
    for _ in range(600):
        fin = (await macop.get(f"/api/simple/restart/{started['request_id']}")).json()
        if fin["state"] != "running":
            break
        await asyncio.sleep(0.1)
    assert fin == {"state": "success_pending",
                   "message": "The device could not be verified after restart. Please contact IT support."}


async def test_search_still_works_after_hardening(reader, lab):
    await seed_lab_switches(["SIM-SW-01"])
    sid = (await reader.post("/api/mac/search", json={"mac": MAC_ACCESS})).json()["id"]
    assert (await wait_for_search(reader, sid))["found_count"] == 1


@pytest.mark.parametrize("raw", ["Pw-Example-1234!\n", "Pw-Example-1234!\r\n",
                                 "\ufeffPw-Example-1234!\r\n", "Pw-Example-1234!"])
def test_cli_password_stdin_strips_windows_line_endings_and_bom(raw):
    import io

    from app.cli import read_stdin_password

    assert read_stdin_password(io.StringIO(raw)) == "Pw-Example-1234!"
