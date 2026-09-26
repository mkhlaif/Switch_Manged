# Final Project Report — Alcatel Network Operations & Safety Platform

Date: 2026-09-26 · Repository: https://github.com/mkhlaif/Switch_Manged (branch `main`)

Every number in this report comes from a run on 2026-09-26 (Windows 11 + Docker Desktop 4.x /
Engine 28.5, WSL2 Ubuntu 24.04.3, PostgreSQL 16, Python 3.11, Node 22). Nothing was tested on
real Alcatel-Lucent hardware; every "switch" is the project's simulator (in-process, or over real
SSH in the `sim-ssh` container). The first audit and its fixes are in
[AUDIT_REPORT.md](AUDIT_REPORT.md) (sections 1–21); this iteration's audit is section 22.

# Executive Summary

**Status: APPLICATION PRODUCTION READY FOR LAB VALIDATION** — not "full network production
ready", because the AOS commands have not yet been executed on real OmniSwitch hardware.

This iteration delivered:

- **MAC_OPERATOR direct restart** — search a MAC, see only the device's location, restart its
  endpoint port with a simple confirmation and **no administrator approval**; in exchange the
  server now requires independent evidence that the port is a single endpoint port and
  re-validates it immediately before and after the change.
- **Bulk switch import** (CSV / JSON; validation, preview, explicit confirmation, background
  batches, idempotent, up to 5000 switches) and **export** (CSV / JSON, never secrets).
- **A new full audit** with 16 findings (3 HIGH, 7 MEDIUM, 6 LOW) — all fixed and covered by tests
  or recorded runs ([AUDIT_REPORT.md § 22](AUDIT_REPORT.md)). The most important: SQLite
  migrations could null foreign keys, the documented rollback restore produced a mixed database,
  and two security tests had silently stopped checking anything after a FastAPI upgrade.

Results: 565 backend + 27 frontend automated tests pass (0 failed, 0 skipped); clean installation
on Windows 36/36 end-to-end checks; Linux (Ubuntu 24.04) 23/23; upgrade from the published version
and rollback verified on PostgreSQL; frontend audit 112 page/viewport/theme combinations without a
problem.

# Architecture

nginx (unprivileged, `edge` network) → FastAPI backend (one process, read-only filesystem, `edge`
+ internal `data` network) → PostgreSQL 16 (`data` only). The backend reaches the switches over
SSH (asyncssh, host-key pinning) and, optionally, NetBox / Zabbix read-only. Every network
operation passes authorization → operation policy → Command Safety Firewall → AOS command profile
→ validator → SSH executor. New in this iteration: `import_jobs` + background import worker, the
MAC_OPERATOR endpoint evidence gate in the restart policy, request-size middleware, container /
network hardening. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

# MAC_OPERATOR

What the role can do — nothing else:

| Capability | Detail |
|---|---|
| Search a MAC address | any common format; the answer is *Device Found* + **location**, *Not Found*, *Multiple locations*, or a generic message |
| See the device location | administrator's label for the port (e.g. *Building A - Floor 2 - Office 204*), else switch site + location, else *Location not recorded* |
| Restart the device directly | simple confirmation, **no administrator approval** |

Never sent to the role (the API response itself is role-aware, verified by tests and in the
browser): switch name, IP, VLAN, model, AOS version, port, LLDP, MAC table, commands, technical
errors. Allowed response keys: `state, message, location, can_restart, search_id, request_id`.

Mandatory automatic checks before a MAC_OPERATOR restart (all implemented and tested; details in
[docs/SECURITY.md § 4](docs/SECURITY.md#4-mac_operator-direct-endpoint-restart)): authenticated
user, role, own search ≤ 10 min, exactly one High-confidence ACCESS location on a switch with role
`access`, every switch answered, fresh read of MAC / switch / port / VLAN / port state / LLDP / MAC
count on the switch, admin-disabled ports refused, endpoint evidence gate (single untagged VLAN,
no tagged VLANs, MAC in that VLAN, ≤ 3 MACs, link up, < 10 Gbit/s, no uplink / trunk / management
/ stack / LAG description, all evidence readable), NetBox evidence when configured (fail closed if
unreachable), unchanged switch / port / VLAN since the search, AOS profile + lab-verified
strategy, Command Safety Firewall safety test and sealed authorization, operation lock, circuit
breaker / SAFE MODE, kill switch, MAINTENANCE mode, `NETWORK_COMMAND_EXECUTION=ENABLED`, dry run
off, a second fresh re-check + gate immediately before *down*. After *up*: port up, MAC relearned
on the same port and VLAN, VLANs and classification unchanged — otherwise *"The device could not
be verified after restart. Please contact IT support."*; never retried automatically. Before /
after state, fingerprints and verification are in the audit log and the port action.

Blocked for the role (tested): TRUNK, LIKELY_TRUNK, declared uplinks, core / distribution /
unknown-role switches, UNKNOWN classification, LIKELY_ACCESS, link aggregates, management / stack
/ LAG descriptions, NetBox tagged / LAG / mgmt-only / disabled interfaces, admin-disabled ports,
ports with tagged VLANs or more than 3 MACs, 10G links.

API security (tested): IDOR (another user's search or restart id → generic error), parameter
tampering and field injection (`switch_id`, `port`, `vlan`, `role`, `command`, `confirmations`,
`profile` → 400/422), role manipulation (user / switch / settings / credential / breaker /
import / export / topology / NetBox endpoints → 403, audited as RBAC_VIOLATION HIGH), hidden
endpoint enumeration (the route test covers all 81 endpoints), two MAC operators restarting the
same port concurrently (exactly one restart).

# Bulk Switch Import

- Formats: CSV (comma or semicolon, UTF-8, BOM accepted) and JSON (list or `{"switches": [...]}`,
  plus `port_locations`). Limits: 5 MB, 5000 rows.
- Workflow: upload → server validation → preview (Total, Valid, Invalid, Duplicates, Warnings,
  New, Existing changed, Unchanged, per-row errors, downloadable error report) → explicit
  confirmation (skip or update existing; invalid rows must be acknowledged) → background job
  (per-row transaction, progress every 100 rows, cancel, 15-min timeout, interrupted-job
  detection) → per-row result (imported, updated, unchanged, skipped, failed).
- Validation (55 tests): names, hostnames, IPs, ports, models, AOS versions (must match a
  supported profile), roles, booleans, duplicates within the file and against the inventory,
  malformed rows, duplicate rows, CSV formula injection, control characters, command /
  shell metacharacters, oversized files, deep JSON, unexpected columns, secret-like columns
  (`password`, `token`, `key`, … → file rejected; credentials only by name).
- Safety: nothing written before confirmation; one import at a time; existing switches never
  silently overwritten; a row taken concurrently fails alone (UNIQUE constraint); re-import is
  idempotent; audit entries for validate / start / cancel / result.
- Measured (PostgreSQL): 1000 rows in 9.1 s, 5000 rows in 55.7 s; validation of 5000 rows 0.64 s.
- Guide: [docs/SWITCH_IMPORT_EXPORT.md](docs/SWITCH_IMPORT_EXPORT.md).

# Bulk Switch Export

CSV and JSON (Excel not added — the stack has no spreadsheet library and CSV opens in Excel):
name, hostname, management_ip, ssh_port, model, aos_version, site, location, description, role,
enabled, credential (name only), uplink_ports, status, created_at, updated_at (+ port_locations in
JSON). Never exported: passwords, encrypted passwords, host keys, private keys, tokens, TLS keys
(tested with a stored host key and credential). CSV formula / newline / delimiter safe
(`csv_cell` + full quoting), server-generated file name, admin-only, 10 per minute, 20 000
switches max, audited. Export → re-import round trip reports every switch *unchanged* (tested for
CSV and JSON).

# Security Audit

16 findings, all fixed ([AUDIT_REPORT.md § 22](AUDIT_REPORT.md)). HIGH: SQLite migrations nulling
foreign keys (A2-1); rollback restore producing a mixed database (A2-2); vacuous route-security
tests after the FastAPI upgrade (A2-3). MEDIUM: MAC_OPERATOR evidence gaps (A2-4), bounce of
admin-disabled ports (A2-5), unbounded request bodies / missing proxy limits (A2-6), restore
scripts leaving the app stopped (A2-7), unusable admin from PowerShell pipes (A2-8), audit write
failures on long values (A2-9), container privileges and network exposure (A2-10).

Automated security coverage (all passing): SQL injection and command injection payloads in MAC,
port, switch id, path, username and import fields; XSS (React escaping, no `innerHTML` /
`dangerouslySetInnerHTML`); CSRF (double-submit, SameSite=strict, stolen cookie without token
cannot change anything); SSRF (no user-supplied URL is fetched — NetBox/Zabbix URLs from the
environment only, switch hosts admin-only); IDOR; RBAC bypass (every endpoint); authentication
bypass; path traversal (export format and file names server-controlled); file upload abuse
(size, depth, types, secrets); CSV injection; parameter tampering; arbitrary CLI (request guard,
strict schemas, firewall seal); secret leakage (API, audit, logs, exports, backups).

Static review (repository scan): no `eval(`, `exec(`, `os.system`, `shell=True`, `pickle`,
`yaml.load`, `innerHTML`, `dangerouslySetInnerHTML` or f-string SQL anywhere; `subprocess` only in
tests (running Alembic); raw SQL only as constants in migrations, the health check and the audit
triggers; `localStorage` only for the light/dark theme; outside the tests (synthetic fixture
passwords) the only credential-like literal is the documented public password of the lab
simulator. No real secret in the repository or its history (checked before the push).

# Database Audit

Details: [docs/DATABASE.md](docs/DATABASE.md). Models == migrations (`alembic check`) on SQLite
and on PostgreSQL. Migrations tested from an empty database, N-1 → N with data (SQLite test and
the published version → new version on PostgreSQL), N → N-1, N → N-1 → N, and the pre-upgrade
check that refuses duplicate inventory entries without changing anything. New constraints:
case-insensitive UNIQUE name and (host, SSH port), UNIQUE hostname when set, CHECK SSH port /
role / transport / import status. Reliability: bounded pool, connect / statement /
idle-in-transaction timeouts, per-request sessions, lock expiry and startup cleanup, interrupted
jobs detected, UNIQUE races answered with 409 / per-row failure. Indexes added only where
measured: 1 M search results — topology 76 → 4.7 ms, dashboard 123 → 0.15 ms, switch delete
180 → 57 ms; duplicate lookups at 8 000 switches no longer full scans. Size: 226 bytes per search
result row incl. indexes.

# Backend Audit

- 81 endpoints enumerated from the application (including nested routers): 3 public (`/health`,
  `/api/health`, login), 4 session-only (me, logout, change password, the operation gateway which
  checks the permission per operation), 74 session + permission. All request bodies use strict
  schemas; 21 bodies checked for command-like fields.
- Rate limits added: NetBox reconciliation, exports (audit / history / switches), import
  validation, switch detect, host-key fetch, lab verification run (existing: login, password
  change, searches, port queries, restarts, switch test). Every list is paginated with a maximum;
  exports are capped.
- Request bodies limited to 1 MB (12 MB for the import) before authentication; nginx the same.
- Errors: structured, no stack traces, reference ids; OpenAPI disabled in production.
- Transactions: per request; imports per row; restarts use DB-backed locks with expiry.

# Frontend Audit

- 112 combinations — 12 admin pages + import dialog + 4 settings tabs + login + MAC-operator idle
  and result screens, at desktop / tablet / mobile, light and dark — on the production build
  behind nginx, with 7003 switches in the inventory: no horizontal overflow, no unlabelled form
  control, no page error, no 5xx response, no sensitive data in `localStorage` / `sessionStorage`
  or URLs, session cookie `HttpOnly` + `Secure` + `SameSite=Strict`, no technical text and no
  technical navigation for the MAC operator.
- Import dialog driven with a real file (desktop and mobile): correct preview counts, confirm
  disabled until invalid rows are acknowledged.
- The backend stays authoritative: the MAC-operator screen and the admin-only buttons are
  convenience only (tests call the API directly).
- 27 frontend tests (login, technical search, restart confirmation, role navigation,
  MAC-operator screen incl. location, import dialog, admin-only controls).
- Observation: the switches list renders every row (7003 rows in 4.7 s, filter 0.44 s; about
  0.7 s at 1000 switches) — see Known Limitations.

# SSH Infrastructure

Connection lifecycle through one manager with a global semaphore (`MAX_CONCURRENT_SSH`, default
5; the performance test never exceeded it), connect / login / command timeouts plus an overall
connect deadline, maximum session duration and 60 commands per session, keep-alives, bounded
close. Host-key pinning (unknown or changed keys refused; lab-only override never on by default).
Prompt learning, pager answering, `ERROR:` detection, silent-login nudge; unexpected output is
discarded and counted by the circuit breaker. Retries: connection-level only, 0–5 (default 1)
with back-off; authentication and host-key failures never retried; a state-changing command is
never re-sent (ambiguous timeouts read the admin state first). No password or key in any log or
`repr`. Failure modes tested: timeout, silent command, malformed output, authentication failure,
connection refused, host-key mismatch, session drop mid-restart.

# Command Safety Firewall

Unchanged allowlist — no command was added or modified. Every execution path was searched
(`asyncssh`, `run`, `exec`, `send`, `write`, `create_process`, `subprocess`, `shell`): the only
place that writes to a switch CLI is `InteractiveCli.run()` via the transports'
`run_approved()`, which verifies the firewall's HMAC seal; a test fails if anything else calls
it. The HTTP layer has no command field (request guard + strict schemas, now verified on every
route). 105 firewall tests pass.

# AOS Compatibility

| Profile | Models | AOS | Status |
|---|---|---|---|
| `AOS8` | OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 | 8.x (guide 8.10R1) | documentation-verified; lab verification required per model family / version |
| `AOS6` | OS6250, OS6350, OS6450 | 6.6, 6.7 (guide 6.7.1) | documentation-verified; lab verification required |
| `AOS7` (OS10K, OS6900 7.x) | — | — | disabled |
| anything else | — | — | blocked ("Command profile unavailable") |

Every command has operation, template, models, AOS version, expected prompt, parser, expected
output, risk and verification source ([docs/ALCATEL_COMMAND_PROFILES.md](docs/ALCATEL_COMMAND_PROFILES.md)).
The importer refuses model / version pairs without a profile.

# Docker Infrastructure

Verified on the running containers: backend uid 10001, read-only root filesystem, all
capabilities dropped; nginx `nginx-unprivileged` — every process runs as `nginx` (uid 101), all
capabilities dropped; PostgreSQL processes run as `postgres`; `no-new-privileges` everywhere;
memory limits (1 GB / 1 GB / 256 MB, configurable) and PID limits; `edge` and internal `data`
networks — the web container cannot even resolve the database; only the web ports are published,
on `127.0.0.1` by default. Health checks with startup ordering, `restart: unless-stopped`, named
volume for the database. Base images pinned by version tag (`python:3.11-slim`,
`node:22-bookworm-slim`, `nginxinc/nginx-unprivileged:1.27-alpine`, `postgres:16-alpine`); no
secret in any image (all from `.env`). Redis is not used (by design; documented).

nginx / HTTPS: TLS 1.2/1.3, HTTP → HTTPS redirect preserving a non-standard port, HSTS on HTTPS,
CSP, `X-Frame-Options: DENY` / `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, body limits,
`limit_req` for login and API, proxy timeouts, `X-Forwarded-For` overwritten with the peer address.
Verified over HTTPS on Ubuntu 24.04.

# Authentication & RBAC

argon2 passwords (12+ characters, 3 classes, max 256); HttpOnly + SameSite=strict (+ Secure)
session cookie with CSRF token; lockout after 5 failures; login rate limits (backend per user /
IP, nginx per IP); 8 h lifetime, 60 min idle timeout; logout, password change, role change,
disabling and forced logout end sessions (tested, 8 session tests). Four roles with a fixed
permission matrix (import / export are admin-only permissions); nobody changes their own role;
the last administrator is protected. RBAC is enforced on every route (81 checked).

# Audit Logging

Append-only (database triggers). Every entry: time, user, role, source IP, operation, target,
switch, port, MAC, VLAN, profile, command fingerprint, risk, approval, result, error, before /
after state. New events: `SWITCH_IMPORT_VALIDATE`, `SWITCH_IMPORT_START`, `SWITCH_IMPORT`,
`SWITCH_IMPORT_CANCEL`, `SWITCH_EXPORT`, `SIMPLE_RESTART_BLOCKED` with the precise reason. Fields
bounded to their column size, oversized JSON truncated with a marker, CR/LF escaped in log lines,
secret-named keys scrubbed; verified: no password of any kind in the audit log after the
end-to-end run.

# Circuit Breaker

Trips to SAFE MODE on repeated SSH / authentication failures of healthy switches, validation
failures and unexpected CLI output (tests); SAFE MODE blocks state-changing operations for every
role including MAC operators (tested), reads continue; only administrators reset it (with a
reason). The kill switch (STOP ALL NETWORK OPERATIONS, and `NETWORK_COMMAND_EXECUTION` ≠ `ENABLED`)
blocks restarts — verified end to end for the MAC operator.

# Backup & Restore

`backup.sh` / `backup.ps1` (pg_dump inside the container; Linux file mode 600) and `restore.sh` /
`restore.ps1`, which now restore into a fresh database, swap it in only on success, keep the
previous database, and always restart the application. Verified on Windows and Ubuntu: backup →
change → restore returns the exact backed-up state; a corrupted file is refused with the database
unchanged and the application running; a pre-upgrade backup restored over an upgraded database
gives exactly the old schema and data. Backup contents checked: no plaintext switch password,
user password, `POSTGRES_PASSWORD` or `CREDENTIAL_ENCRYPTION_KEY` — only argon2 hashes and Fernet
ciphertext. Configuration recovery = `.env` (keep `CREDENTIAL_ENCRYPTION_KEY` separately).
[docs/BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md), [docs/UPGRADE.md](docs/UPGRADE.md).

Update / rollback (PostgreSQL, published version 8d73c07 → this version): backup → new code →
`docker compose up -d --build` → migration 0003 → 0004, `alembic check` clean, data and history
kept; rollback A (restore the pre-upgrade backup with the new scripts, old code) → exact
pre-upgrade state; rollback B (`alembic downgrade 0003`, old code) → old version runs with all
data. The previously documented rollback order failed (old code refuses the newer schema) — the
procedure was corrected.

# Performance

MAC search (simulated switches, 50 ms per command, 5 parallel sessions):

| Switches | Search time | Peak RSS | Peak parallel SSH sessions | SQL per switch |
|---|---|---|---|---|
| 100 | 2.74 s | 82.5 MB | 5 | 5.1 |
| 500 | 14.39 s | 92.4 MB | 5 | 5.0 |
| 1000 | 27.09 s | 100.9 MB | 5 | 5.0 |

CPU time is close to wall time because the simulated switches run in the same process; the
published version measured the same (1.8–2.1 s CPU per 100 switches vs. 1.5–2.3 s now). Real
switches add SSH handshake time (≈ ceil(N / 5) × per-switch time).

PostgreSQL (Docker): import 1000 switches 9.1 s, 5000 switches 55.7 s; validation 5000 rows
0.64 s; with ~1000 switches: list 83 ms, CSV export 144 ms, JSON export 70 ms, audit page 20 ms,
dashboard 60 ms; backend memory ≈ 96 MB; database connections ≤ 8 (pool bounded). Parallel
searches: bounded by the same SSH semaphore and per-user rate limits; an import running while a
search and an export run completes correctly (test).

# Failure Testing

| Scenario | Result (test / run) |
|---|---|
| database unavailable | `/health` 503; DB error during search / restart → generic message, nothing executed |
| switch unreachable, SSH timeout, authentication failure, malformed output, silent prompt | per-switch status, never a restart offer; circuit breaker counts |
| MAC not found / on several switches | *Not Found* / *Multiple locations*, no restart |
| port disappears / MAC moves / VLAN changes after the search | restart blocked, nothing sent |
| switch disappears during the restart | CRITICAL result with manual instructions; *down* sent once, never repeated |
| restart timeout (ambiguous *down*) | admin state read first; restore only if needed |
| backend / frontend container stopped | restore scripts always restart them; health checks report it |
| corrupted backup file | refused, database unchanged |
| migration on inconsistent data | refused with the list of problems, nothing changed |
| Redis unavailable | not applicable (Redis is not used) |
| disk full | not tested (not practical on this machine) |

# Clean Installation

From a copy of the working tree without any local state (no `.env`, database or dependencies),
with the documented Windows commands: `init-env.ps1` → `docker compose up -d --build` →
migrations 0001 → 0004 → admin via CLI → login → credential → **CSV import of 3 SSH switches** +
idempotent re-import + password-column rejection → host-key enrolment → read-only lab
verification → technical MAC search over real SSH → port location label → MAC_OPERATOR creation
and search (location only) → restart blocked by the read-only defaults → export CSV/JSON without
secrets → backup → restore → opt-in (`READ_ONLY_MODE=false`, `NETWORK_COMMAND_EXECUTION=ENABLED`)
→ restart blocked in NORMAL → MAINTENANCE → **MAC_OPERATOR direct restart, verified** → change
report and audit → kill switch blocks → no password in the audit log. **36/36 checks passed**;
`alembic check` on PostgreSQL clean.

# Windows Deployment

Windows 11, Docker Desktop (Engine 28.5, Compose 2.40), Windows PowerShell 5.1: the installation
commands of [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md) were run as written (init, build,
start, admin creation — scripted variant, health, backup, restore). Not run on Windows: the
firewall rule and the self-signed HTTPS certificate step (HTTPS was verified on Linux). Two
Windows-specific defects were found and fixed: CR in passwords piped to the CLI, and restore
aborting when output is redirected.

# Linux Deployment

Ubuntu 24.04.3 (WSL2) with Docker Engine via Docker Desktop integration, as a normal user in the
`docker` group: the README / [docs/LINUX_SETUP.md](docs/LINUX_SETUP.md) commands on a
clone-equivalent tree — **23/23 checks**: `.env` and backups created with mode 600, safe defaults,
build and start, admin, health, login, import, export, backup, `restore.sh --yes` (marker gone,
data intact, previous database kept), HTTPS with the unprivileged nginx after the documented
`chown 101:101` of the key, redirect with port, HSTS, CSP, nginx not root, teardown. Not tested:
the `ufw` firewall step (needs `sudo`), and a bare-metal server.

# Test Results

| Suite | Result |
|---|---|
| Backend (pytest; unit, integration over real SSH to the lab server, security, RBAC, firewall, restart safety, import/export, database migrations, sessions, failure modes, architecture) | **565 passed, 0 failed, 0 skipped** (10 min) |
| Frontend (vitest) + type check + production build | **27 passed**, 0 failed; typecheck and build OK |
| Integration (in the backend count) | real SSH to the simulator: 10 transport tests; end-to-end restart flows |
| Security (in the backend count) | firewall 105, hardening 38, API security 32, MAC_OPERATOR 110, sessions 8, import/export security cases |
| Database | 4 migration / schema tests (SQLite) + PostgreSQL upgrade, downgrade, rollback and `alembic check` runs |
| Infrastructure | container users, capabilities, networks, health checks, HTTPS headers verified on running stacks |
| E2E | Windows clean install 36/36; Linux 23/23; upgrade + 2 rollback paths; UI audit 112/112 |
| Performance | search 100/500/1000 switches; import 1000/5000; queries at 1 M result rows |
| CI (GitHub Actions) | runs backend, frontend and Docker build on every push (result reported with the push) |

New tests in this iteration: 143 (422 → 565 backend) and 4 frontend (23 → 27). Two existing
security tests were repaired because they had become vacuous (A2-3).

# Known Limitations

1. **No real Alcatel hardware was tested.** All commands are verified against the official ALE CLI
   reference guides and exercised on the simulator only.
2. **Lab verification is required** per model family and AOS version before any production use
   (the application enforces it for real switches).
3. **The switch model and AOS version must match a verified command profile**; everything else is
   blocked (and refused by the importer).
4. **NetBox integration is read-only** (GET only); it is used as additional evidence, never
   updated. Tested against mocked HTTP responses only.
5. **Zabbix integration is read-only** (availability and current problems only; no metrics).
   Tested against mocked HTTP responses only.
6. **No MFA / SSO / LDAP.**
7. One backend process by design (rate limits and live progress are in memory).
8. The switches list is not paginated (fine at 1000 switches; ~4.7 s to render 7000).
9. No automatic purge of search history (226 bytes per switch per search; plan database size).
10. Sessions are not bound to the client IP; the audit log's immutability relies on database
    triggers (the database owner could drop them).
11. Excel (.xlsx) export not implemented (CSV opens in Excel).
12. Not tested: host firewall (`ufw` / Windows Firewall rules), disk-full behaviour, a bare-metal
    Linux server, many users behind one NAT address against the nginx per-IP rate limit.

# Production Readiness

| Gate | Status |
|---|---|
| Tests pass | ✔ 565 + 27, 0 failed |
| Security tests pass | ✔ |
| Database migrations pass | ✔ SQLite + PostgreSQL, upgrade / downgrade / rollback |
| Clean installation passes | ✔ 36/36 |
| Docker passes | ✔ hardened stack healthy |
| Windows documentation verified | ✔ |
| Linux deployment verified | ✔ Ubuntu 24.04 (WSL2); firewall step not run |
| MAC_OPERATOR verified | ✔ |
| Import verified | ✔ |
| Export verified | ✔ |
| RBAC verified | ✔ 81 endpoints |
| Command firewall verified | ✔ no bypass path |
| No secret leakage | ✔ API, logs, audit, exports, backups, repository |
| No critical/high unresolved security issues | ✔ (3 HIGH found and fixed) |
| No database corruption | ✔ |
| No known bypass of safety controls | ✔ |
| Real Alcatel hardware validation | ✘ not performed |

**Verdict: APPLICATION PRODUCTION READY FOR LAB VALIDATION.** Next steps before production use:
lab verification of each model family / AOS version on real switches
([docs/DEPLOYMENT.md § 5](docs/DEPLOYMENT.md#5-production-enablement)), a first controlled restart
of one endpoint port, then MAC-operator restarts in maintenance windows.
