# Alcatel Network Operations & Safety Platform

A web platform for **Alcatel-Lucent Enterprise OmniSwitch (AOS)** networks. It finds which switch,
port and VLAN a MAC address is on, explains whether that port is an access port or a trunk, traces
the network path, and can restart ("bounce") an access port under strict safety controls. It
offers two separate experiences: a full technical interface for network staff, and a one-screen
tool for non-technical staff (MAC operators).

- **Read first, analyze second, change last.** Searches are read-only by construction. Only an
  explicitly confirmed port restart can send a port-changing command.
- **Command Safety Firewall.** Every command passes one mandatory firewall: allowlist, strict
  validators, exact model/version profile, lab verification, sealing, fingerprinting and output
  validation. Anything else is blocked and audited. See
  [docs/SECURITY_FIREWALL.md](docs/SECURITY_FIREWALL.md).
- **Verified AOS syntax.** Every command comes from the official ALE CLI Reference Guides and
  records its source, who verified it and when. Production use additionally needs an
  administrator's lab verification per model family and AOS version. See
  [docs/AOS_COMMAND_VERIFICATION.md](docs/AOS_COMMAND_VERIFICATION.md).
- **Fail closed.** Unknown model or version, unverified command, unexpected CLI output, uncertain
  port classification, unreadable safety state: nothing is sent.

Other documents: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (deployment guide) and
[docs/SECURITY.md](docs/SECURITY.md) (security documentation).

---

## Contents

1. [Command verification: corrections](#1-command-verification-corrections)
2. [Architecture](#2-architecture)
3. [Safety model](#3-safety-model)
4. [Features](#4-features)
5. [Installation (Docker Compose)](#5-installation-docker-compose)
6. [Development mode (no Docker)](#6-development-mode-no-docker)
7. [Lab / simulation mode](#7-lab--simulation-mode)
8. [Configuration reference](#8-configuration-reference)
9. [Roles and permissions](#9-roles-and-permissions)
10. [API](#10-api)
11. [Testing](#11-testing)
12. [Troubleshooting](#12-troubleshooting)
13. [Known limitations](#13-known-limitations)

---

## 1. Command verification: corrections

The commands were checked against *OmniSwitch AOS Release 8 CLI Reference Guide 8.10R1* and
*AOS 6250/6350/6450 CLI Reference Guide 6.7.1*. Several examples in the original specification are
**not valid** as written:

| Supplied example | Status | Used instead |
|---|---|---|
| `interfaces 1/1/26 admin down/up` | Invalid on every AOS release | AOS 6: `interfaces 1/26 admin down/up` · AOS 8: `interfaces port 1/1/26 admin-state disable/enable` |
| `lanpower stop/start 1/1/26` | AOS 6 only, which uses 2-part ports | AOS 6: `lanpower stop/start 1/26` |
| `lanpower port 1/1/26 admin-state …` | AOS 8 only (not OS6570M/OS6900) | as supplied, AOS 8 |
| `show vlan members port` | AOS 8 only | AOS 6: `show vlan port 1/26` |
| `show mac-address-table` | AOS 6 only | AOS 8: `show mac-learning mac-address <mac>` |
| "OS6450 running AOS 8.10, port 1/1/26" | Not possible | OS6450 runs AOS 6.x with `slot/port` numbering |
| OS6350 as an AOS 8 platform; OS6360/OS6465 as AOS 6 platforms | Incorrect | OS6350 → AOS 6; OS6360 and OS6465 → AOS 8 |

A **link bounce** (`interfaces …`) and a **PoE power cycle** (`lanpower …`) are different
operations and are offered as separate methods.

## 2. Architecture

```
Browser (React + TypeScript + Tailwind)          MAC_OPERATOR: simplified screen only
   │  HTTPS, same origin (session cookie + CSRF token)
nginx ── static SPA ── /api reverse proxy (SSE-aware)
   │
FastAPI (single process)
   ├── API routes ──────── authentication · permission-based RBAC · rate limits · audit
   ├── Simple API ──────── /api/simple: search + restart request, no technical data
   ├── MAC search ──────── FAST / STANDARD / DEEP, bounded parallelism, SSE progress, path
   ├── Port control ────── plan snapshot → confirm → locks → pre-check → bounce → verify → report
   ├── Classification ──── evidence-based ACCESS / LIKELY_* / TRUNK / UNKNOWN + topology
   ├── Alerts · safety events · circuit breaker · operation modes · kill switch
   ├── NetBox / Zabbix ─── read-only clients (GET / *.get allowlists)
   ├── Alcatel adapter ─── operations only (never command text) + parsers
   ├── COMMAND SAFETY FIREWALL ─ policy · allowlist · validators · profile applicability ·
   │                             lab verification · risk · seal · fingerprint · budgets ·
   │                             session limits · output contracts
   └── SSH manager ─────── asyncssh, host-key pinning, global concurrency limit; transports
        │                   accept sealed commands only
        ▼
   OmniSwitches (SSH interactive CLI)        PostgreSQL (SQLAlchemy 2 + Alembic)
```

```
backend/app/
  api/routes/        REST endpoints (incl. simple, safety, alerts, integrations)
  core/              config, permissions, security, logging
  security/          firewall, policy, state (modes), circuit breaker, restart policy, recorder
  services/          ssh, alcatel (profiles, registry, adapter, verification), mac_search (+ path),
                     port_control, classification, integrations (netbox, zabbix), audit
  models/ schemas/ parsers/alcatel/ simulator/ workers/
frontend/src/        pages, components, simple/ (MAC_OPERATOR app), API client
docs/                command verification, firewall, security, deployment
```

### Why no Redis

The specification suggests Redis. It is deliberately **not** used. Search jobs, the global SSH
concurrency limit, rate limits and live progress live in **one** backend process, and
switch/port locks live in the database (a unique constraint, taken atomically). That makes
`MAX_CONCURRENT_SSH` a real global limit and keeps locking correct across crashes (stale locks are
cleared at start). The backend therefore runs with **exactly one worker** (enforced in the
Dockerfile). Horizontal scaling would need a shared queue and broker; it is not required for
hundreds of switches. A Redis container that nothing uses would only add attack surface.

### SSH library choice

OmniSwitches are driven through an **interactive shell**, as an operator would use it. `asyncssh`
gives native async I/O, explicit host-key pinning, per-switch legacy-algorithm control for old
AOS 6, and a server API used by the lab simulator. The CLI state machine learns the prompt,
strips echo and ANSI escapes, answers pagers, detects `ERROR:` lines and enforces timeouts.

## 3. Safety model

**Everything state-changing requires all of the following** (enforced server-side):

1. A permitted role and permission (see [section 9](#9-roles-and-permissions)).
2. A command profile that applies to the switch's **exact model family and AOS version**, with an
   administrator's **lab verification** of the restart strategy for that family and version.
3. A fresh read-only re-check and a **plan snapshot**; a port classification that the policy
   allows (UNKNOWN, uplinks and link aggregates never; trunks and core/distribution switches only
   for administrators in EMERGENCY mode).
4. Operation mode **MAINTENANCE** (EMERGENCY for administrators), no kill switch, no SAFE MODE,
   `READ_ONLY_MODE=false`, dry-run off.
5. The exact typed confirmation `RESTART PORT <port>` (plus `I UNDERSTAND THIS IS A TRUNK` for an
   emergency trunk override). MAC operators confirm with a simple dialog, and only ever reach
   confidently classified ACCESS ports.
6. Rate limits, a free **switch lock and port lock**, and a sealed, expiring firewall
   authorization.
7. Immediately before the change, a **pre-restart re-verification** against the plan snapshot:
   *"Network state changed since confirmation. Operation cancelled for safety."* on any
   difference.

After the change: post-restart verification (port UP, MAC relearned, VLANs, LLDP,
classification), a before/after **change report**, and an audit entry with the command
fingerprints. The down command is never re-sent; after an ambiguous timeout the port's admin
state is read before any restore is attempted.

| Operation mode | Effect |
|---|---|
| **NORMAL** (default) | read-only operations; restarts can be prepared and simulated only |
| **MAINTENANCE** | authorized state-changing operations |
| **READ_ONLY** | no state changes (forced by `READ_ONLY_MODE=true`) |
| **EMERGENCY** | administrator-approved emergency operations only |

Independently: the **kill switch** "STOP ALL NETWORK OPERATIONS" (operators may engage it, only
administrators release it) and **SAFE MODE**, tripped by the circuit breaker (repeated SSH or
authentication failures on healthy switches, validation failures, unexpected CLI output) and
reset only by an administrator. An always-visible indicator shows **NETWORK SAFETY: ACTIVE / READ
ONLY / SAFE MODE / STOPPED / EMERGENCY**.

## 4. Features

- **MAC search** in any common format, across all enabled switches, with live progress.
  - **FAST**: MAC lookup only. **STANDARD**: plus port status, VLANs, LLDP and MAC count.
    **DEEP**: plus the MAC distribution of the port; never run against the whole network
    (1–5 explicitly selected switches).
  - Multiple locations are never collapsed; the possible causes are listed. MAC moves are shown.
  - **Network path** from the evidence already collected (edge port, LLDP neighbors, topology
    roles), for example `Device → SW-ACCESS-01 1/1/24 → SW-DIST-01 1/1/1`. No extra commands.
- **Port details page**: description, admin/oper state, speed, duplex, VLANs, MACs, LLDP, error,
  drop and traffic counters, classification and evidence. *Refresh* and *Trace MAC* are
  read-only; *Restart port* is visually separated.
- **Classification with evidence**: tagged/untagged VLANs, protocol VLANs, LLDP capabilities, an
  LLDP neighbor that is a managed switch in the inventory, MAC count, speed, description,
  declared uplinks, and the switch's topology role. Never "trunk" from VLAN count alone.
- **Alerts**: multiple locations, MAC move, undeclared trunk-like port, NetBox mismatch, SSH
  failure, circuit breaker, blocked dangerous operation, failed restart, MAC not relearned,
  unexpected CLI output. Deduplicated; informational only.
- **NetBox** (read-only): device and interface comparison, reconciliation with mismatch alerts.
- **Zabbix** (read-only): host state and current problems on the switch page.
- **Audit** (append-only): role, IP, operation, switch, port, MAC, VLAN, profile, fingerprint,
  risk, approval, result, error, before/after state. **SSH session records** per command.
- **Search history**, port action history with change reports, CSV exports.
- **MAC operator screen**: enter a MAC, see the switch name, press *Restart Device*, confirm. No
  technical terms, no technical errors.

## 5. Installation (Docker Compose)

Summary (full guide: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)):

```bash
cp .env.example .env
# Edit .env: POSTGRES_PASSWORD, CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_')
docker compose up -d --build
docker compose exec backend python -m app.cli create-user --role admin youradmin
```

Open `http://<server>:8080`, or `https://<server>:8443` with `NGINX_SITE=https.conf` and
certificates in `./certs/`. Migrations run automatically on start. Back up the `pgdata` volume
**and** `CREDENTIAL_ENCRYPTION_KEY`.

The first deployment starts safe: `READ_ONLY_MODE=true`, operation mode NORMAL, dry-run on, and
no lab verification records.

## 6. Development mode (no Docker)

Requires Python 3.11+ and Node 20.19+/22.12+.

```bash
cd backend
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cat > .env <<EOF
ENVIRONMENT=development
DATABASE_URL=sqlite+aiosqlite:///./data/dev.db
CREDENTIAL_ENCRYPTION_KEY=$(python -m app.cli generate-key)
COOKIE_SECURE=false
EOF
alembic upgrade head
python -m app.cli create-user --role admin admin
uvicorn app.main:app --reload --port 8000            # API docs: http://127.0.0.1:8000/api/docs

cd ../frontend && npm install && npm run dev         # http://127.0.0.1:5173 (proxies /api)
```

## 7. Lab / simulation mode

With `ENABLE_SIMULATOR=true`, `python -m app.cli seed-lab` adds simulated switches that use the
exact output formats of the ALE guides, with stateful ports (a bounce really takes the port down
and MACs relearn).

| Switch | Model / AOS | Role | Scenario |
|---|---|---|---|
| SIM-SW-01 | OS6860E-P24 · 8.9 | access | PC, phone+PC, AP, 10G uplink |
| SIM-SW-02 | OS6900-X20 · 8.10 | distribution | trunk to SW-01, link aggregate to SW-03 |
| SIM-SW-03 | OS6450-P24 · 6.7 | access | AOS 6, pagination on, version auto-detected |
| SIM-SW-04 | | | SSH authentication failure |
| SIM-SW-05 | | | command hangs (timeout) |
| SIM-SW-06 | | | command rejected (`ERROR: Invalid entry`) |
| SIM-SW-07 | OS10K · AOS 7 | core | no verified profile |

Try `00:11:22:33:44:55` (edge on SW-01, seen through the uplinks of SW-02 and SW-03),
`aa:bb:cc:00:12:34` (AOS 6 phone + PC), `00:aa:00:00:00:77` (behind an AP: LIKELY TRUNK),
`00:de:ad:be:ef:01` (not found). The simulator transport is exempt from the READ lab-verification
requirement; restart strategies still need a verification record.

`docker compose --profile lab up -d` also starts `sim-ssh`, which serves the same switches over
genuine SSH (ports 2201–2207, user `lab` / `lab-password`) to exercise host keys, authentication,
prompts and pagination.

## 8. Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | sqlite (dev) | `postgresql+asyncpg://…` in production |
| `CREDENTIAL_ENCRYPTION_KEY` | — (required) | Fernet key for switch credentials |
| `COOKIE_SECURE` / `SESSION_TTL_MINUTES` | `true` / `480` | web sessions |
| `NETWORK_COMMAND_EXECUTION` | `ENABLED` | anything else forces the kill switch |
| `READ_ONLY_MODE` | `true` | forces operation mode READ_ONLY |
| `MAX_CONCURRENT_SSH` | `5` | global SSH session limit (alias `MAX_CONCURRENT_SWITCH_CONNECTIONS`) |
| `SSH_TIMEOUT` / `SSH_LOGIN_TIMEOUT` / `COMMAND_TIMEOUT` | `10` / `20` / `15` s | SSH timeouts (aliases `SSH_CONNECT_TIMEOUT`, `SSH_COMMAND_TIMEOUT`) |
| `SSH_MAX_SESSION_SECONDS` | `300` | maximum duration of one SSH session |
| `SSH_CONNECT_RETRIES` | `1` | connection-level retries only (never auth / host key) |
| `SSH_SWITCH_BUDGET_SECONDS` | `120` | max time per switch per search |
| `SSH_ALLOW_UNKNOWN_HOST_KEYS` | `false` | **lab only** |
| `CIRCUIT_BREAKER_THRESHOLD` | `5` | SSH failures on healthy switches before SAFE MODE |
| `DEFAULT_DRY_RUN` | `true` | initial dry-run setting |
| `NETBOX_URL` / `NETBOX_TOKEN` / `NETBOX_VERIFY_TLS` | empty / empty / `true` | read-only NetBox integration |
| `ZABBIX_URL` / `ZABBIX_TOKEN` / `ZABBIX_VERIFY_TLS` | empty / empty / `true` | read-only Zabbix integration (6.4+ API token) |
| `INTEGRATION_TIMEOUT` | `10` | HTTP timeout for integrations |
| `ENABLE_SIMULATOR` | `false` | lab mode |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | empty | bootstrap admin when no users exist |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | `json` for log shippers |

Runtime settings (administrators, audited): **Safety Controls** (mode, kill switch, SAFE MODE
reset, circuit-breaker thresholds, rate limits, lab-verification requirement) and **Settings**
(dry-run, operator-restartable classes, hold time, verification timeout, plan validity, search
options, command profiles and lab verification, users, credentials).

## 9. Roles and permissions

| | MAC operator | Read only | Operator | Admin |
|---|:-:|:-:|:-:|:-:|
| Simplified search + restart of a confident ACCESS port | ✔ | | | |
| Technical search, port details, path, alerts, history, inventory view | | ✔ | ✔ | ✔ |
| Test SSH, restart ACCESS / LIKELY ACCESS ports, acknowledge alerts | | | ✔ | ✔ |
| Engage the kill switch | | | ✔ | ✔ |
| Audit logs and SSH session records | | | | ✔ |
| Operation modes, kill-switch release, SAFE MODE reset, EMERGENCY trunk override | | | | ✔ |
| Inventory, credentials, users (incl. force logout), profiles, lab verification | | | | ✔ |

Details: [docs/SECURITY.md](docs/SECURITY.md#rbac).

## 10. API

All endpoints are under `/api`; interactive docs at `/api/docs` outside production.

```
POST /api/auth/login · POST /api/auth/logout · GET /api/auth/me (incl. permissions) · POST /api/auth/change-password
POST /api/simple/search · GET /api/simple/search/{id} · POST /api/simple/restart · GET /api/simple/restart/{id}
POST /api/mac/search {mac, mode, switch_ids} · GET /api/mac/search/{id} · …/results · …/events (SSE) · …/path
GET  /api/switches/{id}/ports/{port}?mac=      live read-only port view
POST /api/operations {"operation": "GET_PORT_VLAN", "switch_id": 27, "port": "1/1/26"}
POST /api/ports/restart/prepare · POST /api/ports/restart · GET /api/ports/actions · …/{id} · …/{id}/report
GET  /api/safety · POST /api/safety/mode · POST /api/safety/kill-switch · POST /api/safety/breaker/reset
GET  /api/safety/events · GET /api/safety/locks · GET /api/ssh-sessions
GET  /api/alerts · GET /api/alerts/summary · POST /api/alerts/{id}/ack
GET  /api/integrations/status · …/netbox/switches/{id} · …/netbox/reconcile · …/netbox/results/{id} · …/zabbix/switches/{id}
GET  /api/profiles · POST/DELETE /api/profiles/verifications · POST /api/profiles/verifications/run
GET/POST /api/switches · GET/PATCH/DELETE /api/switches/{id} · …/test · …/detect · …/host-key/*
GET  /api/search-history · GET /api/audit · GET/PUT /api/settings · GET /api/dashboard · GET /api/health
GET/POST /api/users · PATCH/DELETE /api/users/{id} · POST /api/users/{id}/logout · /api/credentials
```

State-changing requests need the `X-CSRF-Token` header. Errors have the form
`{"error": {"code", "title", "message", "action"}}`; raw exceptions are never returned.

## 11. Testing

```bash
cd backend && pytest                 # 386 tests, no real switch needed
cd frontend && npm test              # 16 tests (vitest + Testing Library)
cd frontend && npm run build         # type-check + production build
```

Backend coverage includes parsers (against the ALE guide examples), classification, profiles and
applicability, the SSH CLI driver and the real asyncssh client against the lab SSH server, the
Command Safety Firewall and penetration tests (injection, arbitrary and dangerous commands, forged
or unsealed requests, parameter tampering, unknown profiles, output validation, session limits),
RBAC including every MAC_OPERATOR restriction, operation modes, kill switch, circuit breaker,
locks, pre/post restart verification, ambiguous timeouts, change reports, alerts, path discovery,
search modes, NetBox/Zabbix clients (mocked HTTP), user management, lab verification runs,
append-only audit and migrations. Static architecture tests prove that there is no bypass path
and that every API route is authenticated.

Frontend tests cover the MAC_OPERATOR screen (no technical data, simple confirmation, generic
errors), interface separation, permission-filtered navigation, the safety indicator and the
restart-eligibility hints.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Command profile unavailable for this switch model/version` | Model or AOS version unknown/unsupported, or no lab verification for that model family and version. Run *Detect*, then the read-only verification (*Settings → Command profiles*). |
| `PORT RESTART BLOCKED … require MAINTENANCE mode` | Operation mode is NORMAL. An administrator switches to MAINTENANCE in *Safety Controls*. |
| `SAFE MODE is active` | The circuit breaker tripped; the reason is shown in *Safety Controls*. Fix the cause, then reset. |
| `Network state changed since confirmation` | The port changed between confirmation and execution. Nothing was sent; re-check and prepare again. |
| `UNEXPECTED CLI OUTPUT` | The switch answered in an undocumented format. The result was discarded. Check the profile against that AOS version. |
| `SSH HOST KEY NOT TRUSTED` | Enroll the host key on the switch page; if it changed, find out why first. |
| `SSH AUTHENTICATION FAILED` | Check the credential. Not retried, to avoid lockouts. |
| `SWITCH LOCKED` / `PORT LOCKED` | Another state-changing operation runs on that switch/port (*Safety Controls → locks*). |
| Live progress not updating behind a proxy | The proxy must not buffer `/api/mac/search/*/events`. The UI falls back to polling. |

## 13. Known limitations

- **Not validated on real switches.** All commands are verified against the ALE documentation and
  exercised against a simulator that reproduces the documented output. Each model family / AOS
  version must be lab-verified before production use (the platform enforces this).
- Syntax verified against **AOS 8.10R1** and **AOS 6.7.1 (OS6250/6350/6450)** guides only. Early
  AOS 8 releases (8.1–8.3) may differ; **AOS 7** is unverified and disabled.
- The AOS 6 per-port MAC listing (`show mac-address-table <slot/port>`) has no literal example in
  the guide; validate it in the lab.
- Port bounce on link aggregates is not supported (hard block).
- Path discovery relies on LLDP; without LLDP between switches the path is reported as partial.
- NetBox and Zabbix clients are tested against mocked HTTP responses only.
- Single backend process by design (see "Why no Redis"). No MFA/SSO.
