# Architecture

## 1. Components

```
                    ┌──────────────────────── Docker Compose ────────────────────────┐
Browser ──HTTPS────►│ frontend (nginx, uid 101)                    network: edge     │
 (technical UI or   │   • serves the React single-page app                           │
  MAC operator UI)  │   • proxies /api and /health to the backend                    │
                    │   • security headers, CSP, HSTS, body limits, rate limits      │
                    │           │                                                     │
                    │           ▼                                                     │
                    │ backend (FastAPI, exactly 1 process, uid 10001, read-only fs)  │
                    │   api/routes ─ auth · RBAC · rate limits · body limits · audit │
                    │   services  ─ MAC search · port query · port control ·         │
                    │               inventory · bulk import/export · classification ·│
                    │               path/topology · NetBox/Zabbix (read-only)         │
                    │   security  ─ operation policy · COMMAND SAFETY FIREWALL ·     │
                    │               restart policy + endpoint gate · modes ·          │
                    │               kill switch · circuit breaker · recorder          │
                    │   services/ssh ─ SSH manager (concurrency limit) · asyncssh    │──TCP/22──► OmniSwitches
                    │           │                                   network: data     │
                    │           ▼                                   (internal)        │
                    │ postgres (PostgreSQL 16, volume pgdata)                        │
                    └─────────────────────────────────────────────────────────────────┘
```

| Service | Image / build | Published | Notes |
|---|---|---|---|
| `frontend` | `frontend/Dockerfile` (Node build → `nginx-unprivileged`) | `BIND_ADDRESS:HTTP_PORT` (8080), `BIND_ADDRESS:HTTPS_PORT` (8443) | network `edge`; health check `/nginx-health`; capabilities dropped |
| `backend` | `backend/Dockerfile` (Python 3.11, user 10001) | not published | networks `edge` + `data`; runs `alembic upgrade head`, then uvicorn with **1 worker**; health check `/api/health`; read-only root filesystem, capabilities dropped |
| `postgres` | `postgres:16-alpine` | not published | network `data` (internal, no route outside); data in the `pgdata` volume |
| `sim-ssh` | backend image | lab profile only | simulated switches over real SSH for testing |

All services: `no-new-privileges`, memory and PID limits, `restart: unless-stopped`, health
checks; the backend waits for a healthy database and nginx for a healthy backend.

## 2. Backend layers

| Layer | Path | Responsibility |
|---|---|---|
| API | `backend/app/api/routes/` | HTTP endpoints; every route requires a permission (`require(...)`) |
| Permissions | `backend/app/core/permissions.py` | fixed role → permission matrix |
| Services | `backend/app/services/` | MAC search jobs, port queries, restart workflow, inventory, bulk import/export, classification, integrations |
| Adapter | `backend/app/services/alcatel/adapter.py` | turns *operations* into firewall requests; never sees command text |
| Profiles | `backend/app/services/alcatel/profiles.py` | AOS 6 / AOS 8 command profiles, supported models and versions |
| Firewall | `backend/app/security/firewall.py`, `policy.py` | the only place that generates, validates, seals and sends commands |
| Restart policy | `backend/app/security/restart_policy.py` | per-role restart rules and the MAC_OPERATOR endpoint evidence gate |
| Safety state | `backend/app/security/state.py`, `circuit_breaker.py` | operation modes, kill switch, SAFE MODE |
| SSH | `backend/app/services/ssh/` | connection manager (global semaphore), asyncssh transport, CLI state machine |
| Parsers | `backend/app/parsers/alcatel/` | structured data from switch output (treated as untrusted) |
| Workers | `backend/app/workers/tasks.py` | in-process background tasks (searches, restarts, imports), drained on shutdown |
| Simulator | `backend/app/simulator/` | simulated AOS 6/8 switches for tests and lab mode |

## 3. Request flow: MAC search

1. The browser posts `{"mac": "...", "mode": "STANDARD"}` to `/api/mac/search`
   (MAC operators: `/api/simple/search`, always with LLDP and MAC-count evidence).
2. The MAC is validated and normalised (`00:11:22:33:44:55`, `00-11-…`, `0011.2233.4455`,
   `001122334455`); invalid or malicious values are rejected and audited before any connection.
3. A background job opens at most `MAX_CONCURRENT_SSH` sessions at a time. For each switch:
   if it was never identified, the registry's discovery command runs first in the same session
   (other vendor / unreadable identity → DISCOVERY_FAILED, nothing else is sent) and the identity
   is stored; then profile applicability (discovered model family + AOS version) and the profile
   state are checked, and the firewall runs the MAC-filtered lookup.
4. Only on switches where the MAC is found, only that port is inspected (VLANs, status, LLDP, MAC
   count) and classified.
5. Results, progress (Server-Sent Events), alerts and the network path are stored and shown. The
   MAC-operator view reduces the result to state + location + "restart possible".

## 4. Request flow: port restart

```
prepare (switch must be DISCOVERED; identity re-read first (show system) — changed → MISMATCH,
         stop; read-only re-check, plan snapshot, admin-state check, restart policy,
         MAC_OPERATOR: endpoint evidence gate + NetBox evidence, dry-run safety test)
  → confirm ("RESTART PORT <port>"; simple dialog for MAC operators, no approval step)
  → mode / kill switch / SAFE MODE / dry run / rate limits
  → switch lock + port lock → sealed restart authorization (DISCOVERED; strategy LAB_VERIFIED on
    lab switches, PRODUCTION_VERIFIED on production switches)
  → identity re-read in the execution session, then pre-restart re-verification (abort on any
    change; gate re-run for MAC operators)
  → down → hold → up  (down never re-sent; ambiguous timeouts read the port state first)
  → post-restart verification (port up, MAC on same port + VLAN, VLANs/classification unchanged)
  → outcome SUCCESS / VERIFICATION_FAILED / FAILED / UNKNOWN / BLOCKED + safe error category
  → change report → audit (site, profile version, outcome, category)
```

## 4a. Request flow: automatic discovery

```
switch created / host key trusted / imported / address changed / "Discover all" / first search
  → discovery job (bounded SSH concurrency, cancel, 30 min timeout)
  → trusted host key (enrolled, or exactly the supplied fingerprint)
  → firewall session → show system (registry) → vendor + model + version, strict formats
  → one registry entry → compare expected metadata + previous identity
  → DISCOVERED / MISMATCH (alert, circuit breaker) / DISCOVERY_FAILED (safe category) → audit
```

## 5. Request flow: bulk import

```
POST /api/switches/import/validate (file as text, ≤ 5 MB / 5000 rows)
  → parse (CSV / JSON), reject secret-like and unknown columns
  → validate every row, compare with the file and the inventory → import_jobs row (preview)
POST /api/switches/import/{id}/confirm (skip | update existing; mode atomic | per_row)
  → background task: per row re-check; atomic: one transaction, rolled back on any failure /
    cancel / timeout; per_row: own transaction per row, invalid rows acknowledged and skipped
  → per-row result, audit SWITCH_IMPORT → discovery job for the imported switches
```

## 6. Data model

Main tables: `users`, `user_sessions`, `credentials` (Fernet-encrypted), `switches`,
`command_profiles`, `command_verifications`, `mac_searches`, `mac_search_results`,
`mac_sightings`, `port_actions`, `port_snapshots`, `operation_locks`, `audit_logs`
(append-only triggers), `alerts`, `safety_events`, `ssh_sessions`, `system_settings`,
`import_jobs`, `discovery_jobs`. Constraints, indexes and migrations: [DATABASE.md](DATABASE.md).

## 7. Design decisions

- **Operations, not commands.** The API has no field that can carry CLI text; request bodies with
  command-like keys are rejected before routing.
- **One backend process, no Redis.** Search jobs, imports, the SSH concurrency limit, rate limits
  and live progress live in one process; locks are database rows. This keeps the SSH limit a
  real global limit. Horizontal scaling would need a shared queue/broker and is not required for
  1000 switches (measured: a search over 1000 simulated switches with 5 parallel sessions takes
  about 27 s at ~100 MB RSS — see [FINAL_PROJECT_REPORT.md](../FINAL_PROJECT_REPORT.md)).
- **No human approval for MAC operators, but more automatic evidence.** Instead of an
  administrator approving each restart, the server requires independent evidence (VLANs, LLDP,
  MAC count, port state and description, switch role, optional NetBox) and re-checks it
  immediately before the change.
- **Interactive SSH shell** (asyncssh) as an operator would use it: prompt learning, pager
  handling, `ERROR:` detection, host-key pinning.
- **Fail closed** everywhere: unknown model/version, unverified command, unexpected output,
  unreadable safety state, uncertain classification, missing evidence, unreachable NetBox (when
  configured).
