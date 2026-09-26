"""Database schema audit: migrations == models, N-1 → N upgrade with existing data, downgrade,
pre-upgrade integrity checks, constraints and indexes. (PostgreSQL is covered by the Docker
migration check in docs/DATABASE.md; these tests run on SQLite in every CI run.)"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect

BACKEND = Path(__file__).resolve().parents[1]


def alembic(db: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{db.as_posix()}"}
    return subprocess.run([sys.executable, "-m", "alembic", *args], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=180)


def insert_legacy_rows(db: Path) -> None:
    """Rows created by version 0003 (before hostname/site/port_locations existed)."""
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO switches (id, name, host, ssh_port, model, aos_version, location, "
        "description, enabled, profile_key, transport, host_key, host_key_fingerprint, "
        "legacy_ssh_algorithms, uplink_ports, status, last_error, created_at, updated_at, role) "
        "VALUES (1, 'SW1', '10.0.0.1', 22, 'OS6360', '8.10R1', 'Bldg A', '', 1, '', 'ssh', "
        "'ssh-ed25519 AAAA', 'SHA256:x', 0, '[\"1/1/49\"]', 'online', '', '2026-01-01', "
        "'2026-01-01', 'access')")
    con.execute(
        "INSERT INTO mac_searches (id, mac, requested_by, status, total_switches, checked, "
        "found_count, failed_count, timeout_count, options, summary, mode, created_at) VALUES "
        "('s1', '001122334455', 'x', 'completed', 1, 1, 1, 0, 0, '{}', '{}', 'STANDARD', "
        "'2026-01-01')")
    con.execute(
        "INSERT INTO mac_search_results (search_id, switch_id, switch_name, switch_host, "
        "location, model, aos_version, profile_key, status, error_message, port, interface_raw, "
        "is_linkagg, mac_type, operation, port_details, vlans, tagged_vlans, lldp, "
        "classification, classification_confidence, classification_reasons, commands_executed, "
        "warnings, created_at) VALUES ('s1', 1, 'SW1', '', '', '', '', '', 'found', '', "
        "'1/1/5', '', 0, '', '', '{}', '[]', '[]', '[]', 'ACCESS', 'High', '[]', '[]', '[]', "
        "'2026-01-01')")
    con.commit()
    con.close()


def test_models_and_migrations_are_identical(tmp_path):
    db = tmp_path / "check.db"
    assert alembic(db, "upgrade", "head").returncode == 0
    result = alembic(db, "check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No new upgrade operations detected" in result.stdout + result.stderr


def test_upgrade_from_previous_version_keeps_data_and_references(tmp_path):
    db = tmp_path / "upgrade.db"
    assert alembic(db, "upgrade", "0003").returncode == 0
    insert_legacy_rows(db)
    result = alembic(db, "upgrade", "head")
    assert result.returncode == 0, result.stderr
    con = sqlite3.connect(db)
    sw = con.execute("SELECT name, host, host_key, uplink_ports, role, hostname, site, "
                     "port_locations FROM switches").fetchone()
    assert sw == ("SW1", "10.0.0.1", "ssh-ed25519 AAAA", '["1/1/49"]', "access", "", "", "{}")
    # Rebuilding the switches table must not fire ON DELETE SET NULL on referencing rows.
    assert con.execute("SELECT switch_id FROM mac_search_results").fetchone() == (1,)
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    con.close()

    # N → N-1 → N
    assert alembic(db, "downgrade", "0003").returncode == 0
    con = sqlite3.connect(db)
    assert con.execute("SELECT switch_id FROM mac_search_results").fetchone() == (1,)
    assert "hostname" not in {r[1] for r in con.execute("PRAGMA table_info(switches)")}
    con.close()
    assert alembic(db, "upgrade", "head").returncode == 0


def test_upgrade_stops_on_duplicate_management_addresses(tmp_path):
    db = tmp_path / "dups.db"
    assert alembic(db, "upgrade", "0003").returncode == 0
    insert_legacy_rows(db)
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO switches (name, host, ssh_port, model, aos_version, location, description, "
        "enabled, profile_key, transport, host_key, host_key_fingerprint, legacy_ssh_algorithms, "
        "uplink_ports, status, last_error, created_at, updated_at, role) VALUES ('SW1-copy', "
        "'10.0.0.1', 22, '', '', '', '', 1, '', 'ssh', '', '', 0, '[]', 'unknown', '', "
        "'2026-01-01', '2026-01-01', 'unknown')")
    con.commit()
    con.close()
    result = alembic(db, "upgrade", "head")
    assert result.returncode != 0
    assert "share the management address 10.0.0.1:22" in result.stderr
    con = sqlite3.connect(db)
    assert con.execute("SELECT version_num FROM alembic_version").fetchone() == ("0003",)
    assert con.execute("SELECT COUNT(*) FROM switches").fetchone() == (2,)  # nothing changed
    con.close()


def test_expected_constraints_and_indexes_exist(tmp_path):
    db = tmp_path / "schema.db"
    assert alembic(db, "upgrade", "head").returncode == 0
    insp = inspect(create_engine(f"sqlite:///{db.as_posix()}"))
    # Expression indexes cannot be reflected by SQLAlchemy/Alembic on SQLite (alembic check only
    # warns), so their exact definitions are asserted from sqlite_master.
    con = sqlite3.connect(db)
    sql = {n: s for n, s in con.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='switches'")}
    con.close()
    assert sql["uq_switches_host_port"] == \
        "CREATE UNIQUE INDEX uq_switches_host_port ON switches (lower(host), ssh_port)"
    assert sql["uq_switches_name_lower"] == \
        "CREATE UNIQUE INDEX uq_switches_name_lower ON switches (lower(name))"
    assert sql["uq_switches_hostname"].endswith("(hostname) WHERE hostname <> ''")
    assert sql["ix_switches_name"] == "CREATE UNIQUE INDEX ix_switches_name ON switches (name)"
    checks = {c["name"] for c in insp.get_check_constraints("switches")}
    assert {"ck_switches_ssh_port_range", "ck_switches_role_valid",
            "ck_switches_transport_valid"} <= checks
    assert {"ck_import_jobs_status_valid", "ck_import_jobs_format_valid",
            "ck_import_jobs_on_existing_valid"} <= {
        c["name"] for c in insp.get_check_constraints("import_jobs")}
    fks = insp.get_foreign_keys("import_jobs")
    assert fks and fks[0]["referred_table"] == "users" and \
        fks[0]["options"].get("ondelete") == "SET NULL"
    # Lookups used by searches, audit and imports are indexed.
    assert "ix_mac_searches_mac" in {i["name"] for i in insp.get_indexes("mac_searches")}
    assert {"ix_audit_logs_ts", "ix_audit_logs_action"} <= {
        i["name"] for i in insp.get_indexes("audit_logs")}
    assert "ix_import_jobs_status" in {i["name"] for i in insp.get_indexes("import_jobs")}
