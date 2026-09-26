# Audit report — Switch_Manged (Alcatel Network Operations & Safety Platform)

**Scope:** the complete working copy (backend, frontend, database migrations, Docker, docs,
configuration) and the target GitHub repository, audited **before** the hardening pass.
**Date:** 2026-09-26. **Method:** code review, configuration review, targeted verification of
library behaviour, the existing automated test suite (386 backend + 16 frontend tests, all
passing before this audit), and earlier live runs against the simulator and a Docker/PostgreSQL
deployment.

Severity scale: **CRITICAL** (network or security compromise likely) · **HIGH** (exploitable
weakness or safety gap) · **MEDIUM** (weakness with mitigations, or a missing required feature) ·
**LOW** (hardening, hygiene) · **INFO** (observation, design decision).

Status of each finding after the hardening pass is tracked in
[FINAL_PROJECT_REPORT.md](FINAL_PROJECT_REPORT.md).

---

## 1. Current architecture

```
Browser ──HTTPS──► nginx (SPA + /api reverse proxy) ──► FastAPI (1 process) ──► PostgreSQL
                                                          │
                                                          ├─ RBAC (permission per route)
                                                          ├─ Operation policy
                                                          ├─ COMMAND SAFETY FIREWALL
                                                          │    validators · allowlist · AOS profile
                                                          │    applicability · lab verification ·
                                                          │    risk · seal · fingerprint · budgets ·
                                                          │    output contracts
                                                          └─ SSH manager (asyncssh) ──SSH/22──► OmniSwitches
```

No Redis: jobs, the SSH concurrency limit, rate limits and live progress run inside one backend
process; locks are rows in the database. The design is documented in the README.

## 2. Backend architecture

Python 3.11, FastAPI, SQLAlchemy 2 (async), Alembic, Pydantic v2, asyncssh, argon2, Fernet.
Layers: `api/routes` → `services` (MAC search, port query, port control, inventory, alcatel
adapter, classification, integrations) → `security` (firewall, policy, state/modes, circuit
breaker, restart policy, recorder) → `services/ssh` (manager, asyncssh transport, CLI state
machine). An in-process and an SSH-served **simulator** reproduce AOS 6/8 output for tests and lab
mode.

## 3. Frontend architecture

React 19 + TypeScript + Tailwind 4 + Vite 8. Two separate experiences selected from the
server-provided `interface` field: the full technical UI (permission-filtered navigation, safety
indicator) and `simple/SimpleApp` for MAC_OPERATOR. The API client uses same-origin cookies and a
CSRF header; no tokens in web storage (only the theme preference is in `localStorage`). No
`dangerouslySetInnerHTML`, `innerHTML` or `eval` anywhere.

## 4. Database architecture

PostgreSQL in production (SQLite for development/tests). Three Alembic migrations. Tables:
users, user_sessions, credentials (Fernet-encrypted passwords), switches, command_profiles,
command_verifications, mac_searches (+ results, sightings), port_actions, port_snapshots,
operation_locks, audit_logs (append-only triggers), alerts, safety_events, ssh_sessions,
system_settings. Foreign keys use `SET NULL` for history rows (searches/actions survive switch or
user deletion), `CASCADE` for sessions and search results, `RESTRICT` for credentials in use.
All queries go through the ORM (parameterized); the only raw SQL is `SELECT 1` and SQLite
PRAGMAs.

## 5. Authentication

argon2 password hashes; strength policy (12+ chars, 3 classes); HttpOnly SameSite=strict session
cookie (token stored hashed) + double-submit CSRF token; 8-hour absolute session lifetime;
account lockout after 5 failures (15 min); per-IP and per-IP+username login rate limits; timing
equalisation for unknown users; password change invalidates other sessions.

## 6. Authorization

Permission-based RBAC (`core/permissions.py`), enforced by `require(Permission…)` on every
route (a static test checks that every route is authenticated). Roles: READ_ONLY, MAC_OPERATOR,
OPERATOR, ADMIN. The firewall additionally checks the role per operation.

## 7. SSH implementation

asyncssh interactive shell; host-key pinning (no connection without an enrolled key); prompt
learning, pager answers, `ERROR:` detection, per-command and connect timeouts; retries only for
connection-level failures (never authentication/host key); global concurrency semaphore
(`MAX_CONCURRENT_SSH`, default 5); per-session limits (60 commands, `SSH_MAX_SESSION_SECONDS`);
transports accept only firewall-sealed requests.

## 8. Alcatel commands currently used

Complete inventory (generated from `services/alcatel/profiles.py` and `security/policy.py`). Every
command is **documentation-verified only** — none has been executed on real hardware by this
project.

| Operation | Key | AOS 8 (OS6360, OS6465, OS6560, OS6570M, OS6860(N), OS6865, OS6900, OS9900) | AOS 6 (OS6250, OS6350, OS6450; 6.6/6.7) | R/W | Level |
|---|---|---|---|---|---|
| discovery | `system_info` | `show system` | `show system` | read | doc_example |
| SEARCH_MAC | `mac_lookup` | `show mac-learning mac-address {mac}` | `show mac-address-table {mac}` | read | doc_syntax |
| GET_PORT_MACS | `mac_on_port` | `show mac-learning port {port}` | `show mac-address-table {port}` | read | doc_syntax (AOS 6 form has no literal example) |
| GET_PORT_VLAN | `vlan_port` | `show vlan members port {port}` | `show vlan port {port}` | read | doc_example |
| GET_PORT_VLAN | `vlan_linkagg` | `show vlan members linkagg {agg}` | `show vlan port {agg}` | read | doc_syntax |
| GET_PORT_STATUS | `port_detail` | `show interfaces port {port}` | `show interfaces {port}` | read | doc_example |
| GET_PORT_STATUS | `port_admin` | `show interfaces port {port} alias` | `show interfaces {port} port` | read | doc_example |
| GET_LLDP | `lldp_port` | `show lldp port {port} remote-system` | `show lldp {port} remote-system` | read | doc_syntax |
| RESTART_PORT (link) | strategy | `interfaces port {port} admin-state disable` / `enable` | `interfaces {port} admin down` / `up` | **write** | doc_syntax / doc_example |
| RESTART_PORT (PoE) | strategy | `lanpower port {port} admin-state disable` / `enable` (not OS6570M/OS6900) | `lanpower stop {port}` / `start {port}` | **write** | doc_example |

AOS 7 (OS10K, OS6900 on 7.x): all commands `unverified`, profile disabled.

**Model mapping verified against the guides:** OS6350 and OS6450 run **AOS 6** (`slot/port`
numbering); OS6360 and OS6465 run **AOS 8** (`chassis/slot/port`). The commands are *not*
interchangeable between the two generations and the code never mixes them (profile applicability
is checked per model family and version).

## 9. Command safety mechanisms

Verified present and covered by tests: operation allowlist; command-key allowlist; exact
template allowlist; strict validators (MAC, port per AOS generation, link aggregate, switch id);
injection characters rejected as HIGH security events; risk classification (dangerous verbs →
CRITICAL); HMAC seal checked by the firewall *and* the transport; SHA-256 fingerprint; command
budgets per operation, per restart authorization and per session; output contracts; fail-closed
on any internal error, unreadable safety state or failed policy self-check; request-body guard
rejecting command-like fields; no raw-text execution API exists (static tests).

## 10. MAC search implementation

MAC normalised from `aa:bb…`, `aa-bb…`, `aabb.ccdd.eeff`, `aabbccddeeff`; invalid values rejected
before any connection. Enabled switches searched with bounded parallelism; FAST (lookup only),
STANDARD (lookup + port details), DEEP (≤5 selected switches). Only the port where the MAC was
learned is inspected. Multiple locations are never collapsed; MAC moves are detected; nothing is
deleted or modified.

## 11. Port restart implementation

Prepare (re-check, plan snapshot, policy, safety test) → confirm (`RESTART PORT <port>`) → mode /
kill switch / SAFE MODE / dry-run / lab verification / rate limits / switch+port locks → sealed
authorization → pre-restart re-verification against the plan (abort on any change) → down → hold
→ up → post-verification (port, MAC, VLAN, LLDP, classification) → change report → structured
audit. The down command is never re-sent; after an ambiguous timeout the admin state is read
before any restore.

## 12. User management

Admin can create, edit (name, role, active flag, password), delete, force-logout users; list shows
active sessions and last login. Last active admin cannot be demoted, disabled or deleted.

## 13. MAC_OPERATOR role

Separate minimal permission set (`simple_search`, `simple_restart`); only `/api/simple/*`;
responses carry no technical data; restart only for exactly one ACCESS location with High/Medium
confidence and every switch reachable; generic user messages; every other API returns 403 and is
audited as `RBAC_VIOLATION` (HIGH).

---

## 14. Security weaknesses

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| S1 | **HIGH** | **Client IP spoofing.** nginx forwards `X-Forwarded-For $proxy_add_x_forwarded_for` (keeps the client-supplied value) and uvicorn runs with `--forwarded-allow-ips='*'`, which makes it take the **leftmost** (client-controlled) entry. Any client can therefore choose its source IP: this bypasses the per-IP login rate limits (enables password spraying across accounts) and **falsifies the source IP in the audit log**. | `frontend/nginx/app-locations.conf`, `backend/Dockerfile`; uvicorn 0.54 `get_trusted_client_address` returns `hosts[0]` when trusting `*` |
| S2 | MEDIUM | **CSV formula injection** in the audit and search-history exports. Cells are written unescaped; the username of a failed login is attacker-controlled (unauthenticated) and stored in the audit log, so `=HYPERLINK(…)` could execute when an administrator opens the export in a spreadsheet. | `api/routes/audit.py`, `api/routes/history.py` |
| S3 | MEDIUM | **Administrators can change their own role or disable their own account** (only the last-admin guard exists). Requirement: users must never change their own role. | `api/routes/users.py` `update_user` |
| S4 | MEDIUM | **No idle session timeout** — only an 8-hour absolute lifetime. An unattended browser stays authorised for hours. | `api/deps.py` |
| S5 | LOW | **Log injection**: the login username (≤64 chars, free text) may contain CR/LF and is written to text-format logs, allowing forged log lines. | `api/routes/auth.py`, `core/logging.py` |
| S6 | LOW | Password fields on user update / change-password have **no maximum length** (argon2 cost on very large inputs). | `schemas/common.py` |
| S7 | LOW | `X-Forwarded-Proto` is taken from the client in `http.conf`. No security decision depends on it today (cookies use `COOKIE_SECURE`, HSTS uses `$scheme`), but it is misleading. | `frontend/nginx/http.conf` |
| S8 | INFO | Administrators can point a switch entry at any host:port (SSH connection / host-key fetch). This is an admin-only capability, host keys must still be trusted; acceptable. | `api/routes/switches.py` |
| S9 | INFO | Technical users can open any MAC search by id (shared operational data, intended). MAC_OPERATOR searches and restarts are strictly owner-bound. | `api/routes/mac.py`, `api/routes/simple.py` |
| S10 | INFO | The append-only audit triggers can be dropped by the database owner role, which the application currently uses. | `db/audit_guard.py`, compose |

No CRITICAL issue was found. Checked and **not** vulnerable: SQL injection (ORM only), command
injection (validators + allowlist + seal; tested), XSS (React escaping, no HTML sinks), CSRF
(double-submit, SameSite=strict), path traversal (no file APIs), file upload (none), unsafe
deserialization (JSON only), privilege escalation via API (permission checks per route; tested),
secrets in the repository (none; see §20).

## 15. Bugs

| ID | Severity | Bug |
|---|---|---|
| B1 | LOW | `/api/health` raises an unhandled 500 when the database is down and does not report the database state separately; `/health` (without `/api`) is not routed. |
| B2 | LOW | When the MAC does not return after a MAC_OPERATOR restart, the message is "…has not reconnected yet…" instead of the required "The device could not be verified after restart. Please contact IT support." |
| B3 | INFO | Working-tree files had mixed CRLF/LF line endings (introduced by edit tooling on Windows); harmless in Python but risky for shell scripts. Fixed by `.gitattributes` before the first commit. |

## 16. Missing features

| ID | Severity | Missing |
|---|---|---|
| F1 | MEDIUM | Fresh installs default to `NETWORK_COMMAND_EXECUTION=ENABLED` (compose, `.env.example`, code default). Requirement: `DISABLED` until an administrator enables it. Mitigated today by `READ_ONLY_MODE=true` and NORMAL mode. |
| F2 | MEDIUM | Admin UI has no **Topology** view and no **Roles** (permission matrix) view. |
| F3 | MEDIUM | Zabbix integration shows only host availability and current problems; traffic, errors, drops, uptime, CPU, memory and temperature are not read (item keys are template-specific and must not be guessed). |
| F4 | LOW | No backup/restore scripts; update and rollback procedure not documented. |
| F5 | LOW | Frontend container has no health check. |
| F6 | INFO | No self-service password reset and no forced password change after an admin reset (admin-managed accounts). |
| F7 | MEDIUM | The AOS 8 profile accepts **any 8.x** release, while only the 8.10R1 guide was reviewed. Mitigated by mandatory per-model-family/version lab verification — but an administrator can switch that requirement off. |

## 17. Missing tests

| ID | Severity | Missing |
|---|---|---|
| T1 | MEDIUM | No performance test at 10 / 50 / 100 switches (search time, CPU, RAM, SSH sessions, DB load). |
| T2 | MEDIUM | Frontend tests cover only the MAC_OPERATOR screen and navigation hints; no tests for login, technical MAC search, restart confirmation or admin screens. |
| T3 | LOW | No automated UI layout check (desktop/tablet/mobile, dark/light). |
| T4 | LOW | The complete injection matrix of the requirements (`;`, `&&`, `|`, newline, `$( )`, backticks) is tested for MAC and port but not for every API parameter (switch id, username, search id). |
| T5 | INFO | No test for proxy-header handling (S1) or CSV export escaping (S2). |

## 18. Deployment problems

| ID | Severity | Problem |
|---|---|---|
| D1 | MEDIUM | See F1 (kill switch not engaged by default). |
| D2 | LOW | Behind an external TLS load balancer, nginx would need `set_real_ip_from` to keep correct client IPs once S1 is fixed; not documented. |
| D3 | LOW | No documented LAN access / firewall rules for the published port. |
| D4 | INFO | The web port is published on all interfaces (intended for LAN use); the backend and PostgreSQL are not published. |

## 19. Documentation problems

| ID | Severity | Problem |
|---|---|---|
| DOC1 | MEDIUM | No step-by-step **fresh-machine** installation for Windows and Linux (required software, exact commands, first login, first switch). |
| DOC2 | LOW | No user, admin or MAC_OPERATOR guides; no troubleshooting, backup/restore or upgrade documents; no architecture document. |
| DOC3 | LOW | No per-command table with operation, model, version, R/W, expected output, parser and status in one place. |

## 20. GitHub problems

| ID | Severity | Problem |
|---|---|---|
| G1 | MEDIUM | The working copy was **not under version control**. (Initialised during this audit; baseline committed in 5 logical commits after verifying that no secret, database, `.env`, key or build artefact is included.) |
| G2 | MEDIUM | The target repository `mkhlaif/Switch_Manged` is **public** and **empty**. Everything pushed — including the security architecture — becomes publicly visible. No secret is in the tree, but the owner should confirm that public visibility is intended. |
| G3 | LOW | No CI workflow; no commit identity configured on this machine (a repo-local identity using the owner's GitHub noreply address was set to avoid publishing a personal e-mail). |
| G4 | LOW | Internal-looking example names/addresses (`R-BY-NET-SW-…`, an RFC 1918 address) appeared in code and tests. Replaced with neutral examples **before** the first commit, so they are not in the history. |
| G5 | INFO | No LICENSE file. Choosing a license is the owner's decision; none was added. |

Secrets review: working tree scanned for passwords, tokens, keys, PEM blocks, Fernet keys and
connection strings. The only sensitive files (`backend/.env` with a development key,
`backend/data/dev.db`) are git-ignored and were confirmed absent from the index. The repository
had no history before this audit, so there is no historical exposure.

## 21. Recommended fixes (priority order)

1. S1 — overwrite `X-Forwarded-For` with `$remote_addr` in nginx (document `set_real_ip_from` for
   load balancers) and add a regression check.
2. F1 — default `NETWORK_COMMAND_EXECUTION=DISABLED` for fresh installs.
3. S2 — neutralise spreadsheet formulas in CSV exports.
4. S3 — forbid changing one's own role or active flag.
5. S4 — idle session timeout (configurable).
6. S5/S6 — escape CR/LF in log lines; bound password lengths.
7. B1/B2 — health endpoint with database state and 503; exact MAC_OPERATOR message.
8. F2 — read-only Topology and Roles views.
9. F4/F5 — backup/restore scripts, frontend health check, upgrade/rollback procedure.
10. T1–T5 — performance test, frontend tests, UI layout check, full injection matrix, tests for
    the fixes above.
11. DOC1–DOC3 — README rewrite and the full `docs/` set.
12. G3 — CI workflow (tests + build).
13. Keep F3 (Zabbix metrics) and F7 (AOS 8 versions) as documented limitations until lab
    evidence exists; do not guess item keys or command variants.
