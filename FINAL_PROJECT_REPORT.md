# Final Project Report — Alcatel Network Operations & Safety Platform

Date: 2026-09-27 · Repository: https://github.com/mkhlaif/Switch_Manged · This release: branch
`feature/automatic-discovery` (not yet merged or pushed; see *Deployment Instructions*).

Every number in this report comes from a recorded run. Runs of **this release** (2026-09-26/27):
automated tests, the Docker clean installation with PostgreSQL over real SSH, the Linux deployment
test, the PostgreSQL upgrade / downgrade test, migration tests on SQLite, performance and UI checks.
Results carried over from the **previous release** (2026-09-26, commit `5f83ed2`) are marked
*(previous release)*. Environment: Windows 11 + Docker Desktop (Engine 28.5), WSL2 Ubuntu 24.04,
PostgreSQL 16, Python 3.11, Node 22.

**Nothing was tested on real Alcatel-Lucent hardware.** Every "switch" is the project's simulator,
in-process or behind a real SSH server (`sim-ssh` container). Audit findings:
[AUDIT_REPORT.md](AUDIT_REPORT.md) — § 1–21 first audit, § 22 second, § 23 this release.

# Executive Summary

**Status: READY FOR LAB VALIDATION** — not production-ready for a live network: no command,
discovery answer or restart has been executed on a real OmniSwitch, and no capability is
LAB_VERIFIED or PRODUCTION_VERIFIED by this project.

This release makes the platform identify every switch itself:

- **Automatic discovery.** A switch is added with IP / hostname + credential reference (+ ideally
  the SSH host-key fingerprint). The platform reads vendor, model and AOS version from the device
  (`show system`, Discovery Profile Registry, vendor = ALE description **and** enterprise OID),
  selects the command profile, and refuses every state change on a device it has not identified
  exactly. Typed model / version became *expected metadata*; a difference, or a device that
  changed since it was discovered, is an **identity mismatch** that blocks restarts until an
  administrator reviews it. The identity is read again before every restart, in the prepare and
  in the execution session.
- **Command profile states** per model family and AOS version: DRAFT, LAB_VERIFIED,
  PRODUCTION_VERIFIED, BLOCKED, DEPRECATED. Production switches need PRODUCTION_VERIFIED, which the
  server grants only with recorded evidence from a real SSH switch; simulator runs are never
  evidence.
- **Structural port classes** (UPLINK, LAG, MANAGEMENT, STACK — never restartable; CORE,
  DISTRIBUTION — like trunks) and Low-confidence evidence reported as UNKNOWN.
- **Import / export redesign**: model / version optional, `credential_reference`,
  `ssh_host_key_fingerprint`, `environment`; **all-or-nothing import by default**; discovery after
  the import; exports round-trip unchanged.
- **Safe error categories, action outcomes and extended audit** (site, profile version, category,
  outcome); two new circuit-breaker triggers (identity mismatches, failed verifications).
- **Audit**: 15 findings (4 HIGH, 6 MEDIUM, 5 LOW), all fixed with tests
  ([AUDIT_REPORT.md § 23](AUDIT_REPORT.md)); three of them were found by this release's own
  end-to-end and full-suite runs.

Results: **611 backend** and **30 frontend** automated tests pass (0 failed, 0 skipped); clean
installation on PostgreSQL over real SSH **48/48**; Linux deployment **24/24**; PostgreSQL upgrade
from the published version with data, downgrade with the old code and re-upgrade **17/17**;
rendered UI check 9/9.

# Architecture

nginx (unprivileged, `edge` network) → FastAPI backend (one process, read-only filesystem, `edge`
+ internal `data` network) → PostgreSQL 16 (`data` only). The backend reaches switches over SSH
(asyncssh, host-key pinning) and, optionally, NetBox / Zabbix read-only. Every network operation
passes authorization → operation policy → Command Safety Firewall → AOS command profile →
validator → SSH executor; the only code that can write to a switch CLI verifies the firewall's HMAC
seal.

New in this release: `services/discovery` (Discovery Profile Registry, identity evaluation,
background jobs), `/api/discovery/*`, profile states in `command_verifications`,
`core/error_categories.py`, migration 0005, the discovery gate in `port_control` and in the
firewall's restart authorization. Flows: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

# Implemented Features

| Area | Features |
|---|---|
| Discovery | registry (AOS 8 / AOS 6, sources, patterns, fixtures), vendor + model + version from the device, expected metadata comparison, mismatch review, discovery jobs (bounded, cancellable, 30 min timeout), discovery on create / key trust / address change / import / first search, re-identification before every restart |
| MAC search | FAST / STANDARD / DEEP, any MAC format, bounded SSH concurrency, path and topology from LLDP evidence, alerts, safe error category per switch |
| Port inspection | state, speed, VLANs, LLDP, MAC count, counters, classification with evidence (11 classes) |
| Port restart | link bounce / PoE cycle; re-check, typed confirmation, locks, sealed authorization, identity + state re-verification, post-restart verification, outcome, change report |
| MAC_OPERATOR | location-only search, direct restart of a verified endpoint port without approval, every technical check mandatory |
| Command profiles | allowlisted AOS 8 / AOS 6 commands with sources; profile states and evidence levels; read-only verification run; custom profiles linted |
| Safety | operation modes, kill switch, SAFE MODE circuit breaker (6 triggers), dry run, network state vocabulary |
| Inventory | CRUD with expected metadata / fingerprint / environment, bulk import (atomic or per row), export without secrets |
| Integrations | NetBox and Zabbix read-only |
| Audit | append-only, structured, command fingerprints, SSH session records |

# Automatic Discovery

Flow, statuses and operations: [docs/DISCOVERY.md](docs/DISCOVERY.md).

| Rule | Enforcement | Test / run |
|---|---|---|
| Vendor = ALE only if description **and** OID 1.3.6.1.4.1.6486 agree | parser `detect_vendor` | unit tests; other-vendor answer → DISCOVERY_FAILED, only `show system` sent (API test) |
| Version only in the documented AOS format | `normalize_discovered_version` | 8 malformed / injected formats rejected |
| Exactly one registry entry (family + version of one generation) | `match_profile` | AOS 6 platform reporting 8.x → no entry |
| Expected metadata compared (family / major.minor) | `apply_discovery` | mismatch tests; clean install: expected OS6450 vs OS6900 → MISMATCH |
| Previously discovered identity compared, also after an address change | `apply_discovery` | tests incl. address change to another device |
| Host key trusted only if it equals the supplied fingerprint | `_trust_expected_host_key` | wrong fingerprint → HOST_KEY_UNTRUSTED, nothing stored (clean install) |
| Unidentified device → no state change | port_control + firewall `authorize_restart` | DISCOVERY_REQUIRED / DEVICE_NOT_DISCOVERED tests |
| Identity re-read before a restart (prepare and execution sessions) | port_control | upgrade between confirmation and execution → aborted, only `show system` sent; SSH session records of the clean-install restart show `system_info` first in both sessions |
| Mismatch → alert, circuit breaker, admin review with reason | discovery service, API | tests; clean install acceptance |

Measured: discovery of 10 / 50 / 100 / 500 switches in 0.43 / 1.86 / 3.03 / 14.95 s (see
*Performance*). Clean installation over real SSH: 4 imported switches without model / version →
1 discovered (OS6860E-P24 / 8.9.221.R03 → AOS8), 1 mismatch, 1 HOST_KEY_UNTRUSTED, 1 waiting for its
host key → trusted by the administrator → discovered (OS6450-P24 / 6.7.2.191.R08 → AOS6).

Not collected: serial number / chassis inventory (no verified command). Not supported: AOS 7
(no registry entry, no documented output — such switches end DISCOVERY_FAILED).

# Command Profile System

Details: [docs/ALCATEL_COMMAND_PROFILES.md](docs/ALCATEL_COMMAND_PROFILES.md).

- **Sources**: only the official ALE CLI Reference Guides (AOS 8.10R1 [A8], AOS 6.7.1 [A6]); page
  references per command. No command was added or changed in this release; nothing comes from AI
  output, blogs or guesses.
- **Evidence levels**: SIMULATED, FIXTURE_TESTED, LAB_VERIFIED, PRODUCTION_VERIFIED. Every built-in
  read command is FIXTURE_TESTED (documented output fixtures) and SIMULATED; restart commands are
  SIMULATED only (they print nothing).
- **Profile states** per capability (READ, each restart strategy) × model family × major.minor:
  no record = DRAFT; LAB_VERIFIED (reads, lab switches); PRODUCTION_VERIFIED (production restarts;
  promotion requires recorded evidence from a real SSH switch — a passed verification run for READ,
  a live restart with a successful post-restart verification for a strategy); BLOCKED (wins over
  everything); DEPRECATED (revoked, kept). Audited transitions with a mandatory reason.
- Legacy records: `*` (all models) counts as LAB_VERIFIED at most, `8` (one component) does not
  count; new records need an exact family and major.minor.
- Exact match or block: no fallback to another profile; the profile is chosen from the discovered
  identity only.

| Command family | Source | Evidence here |
|---|---|---|
| Discovery `show system` | [A8] p.61-56, [A6] p.2-31 | FIXTURE_TESTED, SIMULATED, SSH simulator |
| MAC lookup / MACs on port | [A8] p.4-41, [A6] p.20-10 | FIXTURE_TESTED, SIMULATED, SSH simulator |
| VLAN membership | [A8] p.5-13, [A6] p.25-15 | FIXTURE_TESTED, SIMULATED, SSH simulator |
| Port status / admin state | [A8] p.1-59, 1-63, [A6] p.23-49, 23-79 | FIXTURE_TESTED, SIMULATED, SSH simulator |
| LLDP | [A8] p.18-63, [A6] p.13-47 | FIXTURE_TESTED, SIMULATED, SSH simulator |
| Link bounce | [A8] p.1-3, [A6] p.23-15 | SIMULATED, SSH simulator |
| PoE cycle | [A8] p.2-4, [A6] p.4-2 / 4-4 | SIMULATED |

# MAC Operator

Unchanged capabilities: search a MAC and see only the device's location; restart the endpoint
port directly with a simple confirmation, **no administrator approval**, every technical check
mandatory ([docs/SECURITY.md § 4](docs/SECURITY.md#4-mac_operator-direct-endpoint-restart)).

New in this release:

- the switch must be **discovered** (identity re-read twice before the change); structural classes
  and Low-confidence evidence are never offered;
- **no restart offer** while any switch could not be checked (uncertain location) — seen in the
  clean-install run with an unreachable switch in the inventory;
- **no technical text in any error**: `/api/simple` validation errors (extra fields, oversized
  values), unknown paths and application errors return generic sentences without field names,
  validation details or error categories (tested; clean install);
- discovery, registry and inventory APIs return 403 for the role.

Allowed response keys remain `state, message, location, can_restart, search_id, request_id`.
Verified in the clean installation: location-only answer, restart blocked by the safe defaults,
then — after opting in and a MAINTENANCE window — a direct restart on a lab switch, verified
(*Device restarted successfully.*).

# Safety Architecture

| Property | How |
|---|---|
| UNKNOWN DEVICE / UNKNOWN AOS = no state change | discovery status gate in port_control and in the firewall's restart authorization |
| UNKNOWN COMMAND PROFILE = no execution | profile selection refuses undiscovered switches; no profile → nothing sent |
| UNKNOWN PORT TYPE = no restart | UNKNOWN (incl. Low-confidence LIKELY_*) blocked for every role |
| Trunks / uplinks / core / distribution | UPLINK, LAG, MANAGEMENT, STACK hard-blocked; TRUNK / LIKELY_TRUNK / CORE / DISTRIBUTION only admin + EMERGENCY + two phrases |
| PROFILE NOT VERIFIED = no production execution | `authorize_restart` requires PRODUCTION_VERIFIED on production switches (LAB_VERIFIED on lab switches / simulator); clean install: production switch → dry run only |
| SAFETY CHECK FAILURE = block | policy, endpoint gate, safety test, pre-restart re-verification, identity check |
| VERIFICATION FAILURE = no blind retry | down never re-sent; ambiguous results read state first; outcome VERIFICATION_FAILED / UNKNOWN; circuit breaker counts |
| Global state | NORMAL / READ_ONLY / SAFE_MODE / EMERGENCY_STOP / MAINTENANCE (+ EMERGENCY_OVERRIDE) exposed as `network_state` |
| Locks | DB-backed switch + port locks (UNIQUE), expiry and startup cleanup |
| Firewall | allowlist unchanged; HMAC-sealed requests; no `/execute-command`; request guard on every route |

Outcomes of a port action: SUCCESS, VERIFICATION_FAILED, FAILED, UNKNOWN, BLOCKED — with a safe error
category and the content hash of the profile used (`profile_version`).

# RBAC

Four roles (admin, operator, readonly, mac_operator) with a fixed permission matrix. New endpoints:
discovery run / jobs / cancel / accept (admin: MANAGE_INVENTORY), jobs list (VIEW_INVENTORY),
registry (VIEW_SAFETY), profile state changes (MANAGE_PROFILES). The route test enumerates every
endpoint (including the new ones) and asserts authentication and permission; MAC_OPERATOR gets 403
on all of them (tested and in the clean installation).

# SSH Security

Unchanged mechanisms (host-key pinning, bounded sessions and commands, timeouts, no blind
retries, no secrets in logs). New: discovery never trusts an unknown key — only an enrolled key or
exactly the fingerprint supplied out of band (wrong fingerprint → HIGH alert, nothing stored); an
address or port change clears the trusted key and the identity. Discovery jobs use the global SSH
semaphore (peak 5 sessions at 500 switches).

# Import/Export

Details: [docs/SWITCH_IMPORT_EXPORT.md](docs/SWITCH_IMPORT_EXPORT.md). Required columns: `name`,
`management_ip`. Optional: `credential_reference`, `ssh_host_key_fingerprint`, `ssh_port`,
`expected_model` / `model`, `expected_aos_version` / `aos_version`, `environment`, hostname, site,
location, description, role, enabled, uplink ports, (JSON) port locations. Validation pipeline:
format, size, header (secret-like / unknown / alias conflicts), per-row fields, duplicates in the
file and against the inventory, fingerprint vs trusted key, coverage warnings, CSV injection,
control characters. **Atomic by default** (one transaction; any failure / cancel / timeout rolls
back), per-row as explicit choice; idempotent; discovery job afterwards. Export: no passwords or
keys, fingerprint and discovered identity included, formula-safe, round trip unchanged (tested,
clean install).

# NetBox

Read-only (GET only), from the environment configuration. Compared with the inventory / live data:
management IP, model (discovered), role, **site (new)**, interface VLANs / mode / enabled. Used as
fail-closed evidence for MAC_OPERATOR restarts; never updated. Tested against mocked HTTP
responses only.

# Zabbix

Read-only: host availability and current problems on the switch page. Tested against mocked HTTP
responses only. Unchanged in this release.

# Audit Logging

Append-only (database triggers, preserved by migration 0005 on SQLite and PostgreSQL). New fields:
**site, profile_version, error_category, outcome** (also returned by the audit API). New events:
`DEVICE_DISCOVERY` (identity, registry entry, commands, source), `DISCOVERY_JOB_START`,
`DISCOVERY_JOB`, `DISCOVERY_JOB_CANCEL`, `DISCOVERY_ACCEPT`, `PROFILE_STATE_CHANGE`, and
`HOSTKEY_TRUST` for keys trusted from a supplied fingerprint. No secrets: verified after the
clean-installation run (no password of any kind in the audit log).

# Circuit Breaker

Trips to SAFE MODE (persisted; admin reset with reason) on, within the window: SSH failures and
authentication failures of healthy switches, HIGH/CRITICAL validation failures, unexpected CLI
output, and — new — **identity mismatches** (default 3) and **failed post-restart verifications**
(default 3; a MAC that is merely not relearned does not count). Thresholds configurable. Tests for
both new triggers.

# Testing

| Suite | Result (this release) |
|---|---|
| Backend (pytest: unit, integration over real SSH, security, RBAC, firewall, discovery, restart safety, import/export, migrations, sessions, failure modes, architecture) | **611 passed, 0 failed, 0 skipped** |
| Frontend (vitest) + type check + production build | **30 passed**, 0 failed; type check and build OK |
| Clean installation (Docker, PostgreSQL, nginx, sim-ssh over real SSH; import without model / version) | **48/48** (setup 34 + live 14) |
| Linux deployment (Ubuntu 24.04 WSL2; init, build, import, backup / restore, HTTPS, teardown) | **24/24** |
| PostgreSQL upgrade published `main` (0004) → this release (0005) with data, downgrade, re-upgrade | **17/17**: typed models moved to expected metadata, users / search results / verification records kept (`*` record kept as LAB), `alembic check` clean, audit triggers present and firing, discovery afterwards without mismatch, `alembic downgrade 0004` restores the model column and the old code runs, re-upgrade works |
| SQLite migration 0004 → 0005 → 0004 → 0005 with data; models == migrations | ✔ (test + development database) |
| Live smoke on the development stack (discovery job, search, categories, registry, network state) | 15/15 functional checks |
| Rendered UI (switches, form, identity card, failed discovery, settings, import dialog) | 9/9 |
| Performance (discovery, first search, search at 10 / 50 / 100 / 500) | all PASS (peak 5 sessions) |

New tests in this release: 46 backend (565 → 611) and 3 frontend (27 → 30); tests changed where the
behaviour changed on purpose (typed model / version, `*` records, TRUNK → UPLINK / LAG, per-row →
atomic import, DELETE → DEPRECATED).

*(previous release)*: Windows clean installation 36/36, UI audit 112 combinations, backup /
restore on Windows and Ubuntu, PostgreSQL upgrade 0003 → 0004 and both rollback paths.

# Security Audit

[AUDIT_REPORT.md § 23](AUDIT_REPORT.md): A3-1 typed identity selected commands (HIGH), A3-2 no
re-verification before a change (HIGH), A3-3 `*` / one-component verification records and no
lab/production distinction (HIGH), A3-4 no BLOCKED state and destructive revoke (HIGH), A3-5 port
classes (MEDIUM), A3-6 partial imports by default (MEDIUM), A3-7 imports trusted typed identity /
no fingerprint (MEDIUM), A3-8 `/api/simple` validation details (MEDIUM), A3-9 no error categories /
outcomes (MEDIUM), A3-10 breaker ignored mismatches and verification failures (MEDIUM), A3-11 –
A3-15 LOW (three found by this release's own runs). All fixed and tested.

Unchanged coverage (all passing): injection payloads in every parameter, XSS, CSRF, SSRF, IDOR,
RBAC bypass on every route, path traversal, upload abuse, CSV injection, arbitrary CLI, secret
leakage (API, audit, logs, exports, backups). Repository secret scan before each commit: no real
secret; control-character scan clean.

# Performance

In-process simulator, 50 ms per CLI command, 5 parallel SSH sessions, this release:

| Switches | Discovery job | First search (discovers each switch) | Search (discovered) | Peak RSS | Peak sessions |
|---|---|---|---|---|---|
| 10 | 0.43 s | 0.42 s | 0.38 s | 81 MB | 5 |
| 50 | 1.86 s | 1.33 s | 1.06 s | 83 MB | 5 |
| 100 | 3.03 s | 2.21 s | 1.21 s | 85 MB | 5 |
| 500 | 14.95 s | 10.46 s | 5.78 s | 92 MB | 5 |

The theoretical floor is N × commands × 50 ms / 5 (500 switches: 5 s per command per switch), so
the platform adds little overhead; SQL ≈ 5–8 statements per switch. Real switches add SSH
handshake time (≈ ceil(N / 5) × per-switch time). The first search after an upgrade costs one extra
`show system` per switch. *(previous release, PostgreSQL)*: import 1000 rows 9.1 s / 5000 rows
55.7 s (per-row mode); queries at 1 M result rows 0.15–57 ms.

# Known Limitations

1. **No real Alcatel hardware was tested**; no capability is LAB_VERIFIED or PRODUCTION_VERIFIED.
2. Serial number / chassis information not collected (no verified command).
3. AOS 7 (OS10K, OS6900 on 7.x) not supported: discovery fails closed.
4. Expected AOS version compared on major.minor only (release names are not mapped to builds).
5. NetBox and Zabbix read-only, tested against mocked responses only.
6. No MFA / SSO / LDAP; one backend process by design; sessions not bound to the client IP.
7. Switch list not paginated (≈ 0.7 s at 1000 switches, 4.7 s at 7000 — previous release).
8. No automatic purge of search history.
9. Not tested: host firewall rules, disk-full behaviour, bare-metal Linux, many users behind one NAT
   address against the nginx per-IP rate limit.

# Hardware Verification Status

| Item | Level reached by this project |
|---|---|
| Discovery (`show system`) | FIXTURE_TESTED + SIMULATED (in-process and over SSH) |
| Read commands (AOS 8, AOS 6) | FIXTURE_TESTED + SIMULATED (in-process and over SSH) |
| Restart strategies | SIMULATED (in-process and over SSH) |
| LAB_VERIFIED on real hardware | **none** |
| PRODUCTION_VERIFIED | **none** (the clean-installation run demonstrated the promotion mechanism with the SSH simulator and then set the record to BLOCKED; that database was discarded) |

# Production Readiness

| Gate | Status |
|---|---|
| Tests pass | ✔ 611 + 30, 0 failed, 0 skipped |
| Security review | ✔ 15 findings fixed; no known unresolved HIGH / CRITICAL |
| Database migrations | ✔ SQLite; PostgreSQL clean install, upgrade with data, downgrade, re-upgrade (17/17) |
| Clean installation | ✔ 48/48 |
| Linux deployment | ✔ 24/24 |
| Discovery, profile states, MAC_OPERATOR, import / export, RBAC, firewall | ✔ tested |
| No secret leakage | ✔ API, logs, audit, exports, repository |
| Real Alcatel hardware validation | ✘ not performed |

**Verdict: READY FOR LAB VALIDATION.** Before production use: discover real lab switches, run the
read-only verification per model family / AOS version, validate each restart strategy on a lab
switch (LAB_VERIFIED, `environment = lab`), then promote with the recorded evidence
(PRODUCTION_VERIFIED) and start with one controlled endpoint restart in a maintenance window.

# Deployment Instructions

New installation: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md),
[docs/LINUX_SETUP.md](docs/LINUX_SETUP.md). This release is on the branch
`feature/automatic-discovery`; it is deployed like any version after it is merged:

```bash
./scripts/backup.sh                 # Windows: .\scripts\backup.ps1
git pull                            # the version containing migration 0005
docker compose up -d --build        # migration 0004 → 0005 runs at backend start
```

Then (see [docs/UPGRADE.md](docs/UPGRADE.md) § migration 0005): *Switches → Discover all*; review
every *Identity mismatch*; mark lab switches `environment = lab`; note that restarts on production
switches now require PRODUCTION_VERIFIED records.

# Rollback Instructions

[docs/UPGRADE.md § Rollback](docs/UPGRADE.md#rollback): **A** — restore the pre-upgrade backup with
the new scripts and run the old code (exact pre-upgrade state); **B** — `docker compose exec
backend alembic downgrade 0004`, then the old code: the model / version columns get the expected
(typed) values back, discovery data is dropped. Both leave the audit log append-only.

# Remaining Risks

| Risk | Mitigation in place | Still needed |
|---|---|---|
| Real OmniSwitch output differs from the documented examples (discovery or reads) | strict parsing; unexpected output discarded, alerted, counted by the circuit breaker; DISCOVERY_FAILED instead of guessing | lab validation on each model family / AOS version |
| A restart strategy behaves differently on real hardware | profile states; production needs recorded evidence; post-restart verification; never blind retry | supervised lab tests before any promotion |
| Wrong expected metadata or mismatches after upgrades flood the operators | mismatch blocks only state changes; reads continue; admin review | procedure for AOS upgrade windows (accept identity afterwards) |
| An administrator promotes a capability using evidence from a lab SSH simulator | evidence recorded and shown with the record; audit with reason | organisational rule: promote only with evidence from real switches |
| One backend process | health checks, restart policy, interrupted-job detection | none by design |
