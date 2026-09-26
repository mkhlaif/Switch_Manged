# Architecture

## 1. Components

```
                    ┌──────────────────────── Docker Compose ────────────────────────┐
Browser ──HTTPS────►│ frontend (nginx)                                               │
 (technical UI or   │   • serves the React single-page app                           │
  MAC operator UI)  │   • proxies /api and /health to the backend                    │
                    │   • security headers, CSP, HSTS                                 │
                    │           │                                                     │
                    │           ▼                                                     │
                    │ backend (FastAPI, exactly 1 process)                           │
                    │   api/routes ─ auth · RBAC · rate limits · audit               │
                    │   services  ─ MAC search · port query · port control ·         │
                    │               inventory · classification · path/topology ·     │
                    │               NetBox/Zabbix (read-only)                         │
                    │   security  ─ operation policy · COMMAND SAFETY FIREWALL ·     │
                    │               modes · kill switch · circuit breaker · recorder  │
                    │   services/ssh ─ SSH manager (concurrency limit) · asyncssh    │──TCP/22──► OmniSwitches
                    │           │                                                     │
                    │           ▼                                                     │
                    │ postgres (PostgreSQL 16, volume pgdata)                        │
                    └─────────────────────────────────────────────────────────────────┘
```

| Service | Image / build | Published | Notes |
|---|---|---|---|
| `frontend` | `frontend/Dockerfile` (Node build → nginx) | `BIND_ADDRESS:HTTP_PORT` (8080), `BIND_ADDRESS:HTTPS_PORT` (8443) | health check `/nginx-health` |
| `backend` | `backend/Dockerfile` (Python 3.11) | not published | runs `alembic upgrade head`, then uvicorn with **1 worker**; health check `/api/health` |
| `postgres` | `postgres:16-alpine` | not published | data in the `pgdata` volume |
| `sim-ssh` | backend image | lab profile only | simulated switches over real SSH for testing |

## 2. Backend layers

| Layer | Path | Responsibility |
|---|---|---|
| API | `backend/app/api/routes/` | HTTP endpoints; every route requires a permission (`require(...)`) |
| Permissions | `backend/app/core/permissions.py` | fixed role → permission matrix |
| Services | `backend/app/services/` | MAC search jobs, port queries, restart workflow, inventory, classification, integrations |
| Adapter | `backend/app/services/alcatel/adapter.py` | turns *operations* into firewall requests; never sees command text |
| Profiles | `backend/app/services/alcatel/profiles.py` | AOS 6 / AOS 8 command profiles, supported models and versions |
| Firewall | `backend/app/security/firewall.py`, `policy.py` | the only place that generates, validates, seals and sends commands |
| Safety state | `backend/app/security/state.py`, `circuit_breaker.py` | operation modes, kill switch, SAFE MODE |
| SSH | `backend/app/services/ssh/` | connection manager (global semaphore), asyncssh transport, CLI state machine |
| Parsers | `backend/app/parsers/alcatel/` | structured data from switch output (treated as untrusted) |
| Simulator | `backend/app/simulator/` | simulated AOS 6/8 switches for tests and lab mode |

## 3. Request flow: MAC search

1. The browser posts `{"mac": "...", "mode": "STANDARD"}` to `/api/mac/search`.
2. The MAC is validated and normalised (`00:11:22:33:44:55`, `00-11-…`, `0011.2233.4455`,
   `001122334455`); invalid or malicious values are rejected and audited before any connection.
3. A background job opens at most `MAX_CONCURRENT_SSH` sessions at a time. For each switch:
   profile applicability (model family + AOS version) and lab verification are checked, then the
   firewall runs the MAC-filtered lookup.
4. Only on switches where the MAC is found, only that port is inspected (VLANs, status, LLDP, MAC
   count) and classified.
5. Results, progress (Server-Sent Events), alerts and the network path are stored and shown.

## 4. Request flow: port restart

```
prepare (read-only re-check, plan snapshot, policy, dry-run safety test)
  → confirm ("RESTART PORT <port>"; simple dialog for MAC operators)
  → mode / kill switch / SAFE MODE / dry run / lab verification / rate limits
  → switch lock + port lock → sealed restart authorization
  → pre-restart re-verification (abort on any change)
  → down → hold → up  (down never re-sent; ambiguous timeouts read the port state first)
  → post-restart verification → change report → audit
```

## 5. Data model

Main tables: `users`, `user_sessions`, `credentials` (Fernet-encrypted), `switches`,
`command_profiles`, `command_verifications`, `mac_searches`, `mac_search_results`,
`mac_sightings`, `port_actions`, `port_snapshots`, `operation_locks`, `audit_logs`
(append-only triggers), `alerts`, `safety_events`, `ssh_sessions`, `system_settings`.
Migrations: `backend/alembic/versions/` (applied automatically at start).

## 6. Design decisions

- **Operations, not commands.** The API has no field that can carry CLI text; request bodies with
  command-like keys are rejected before routing.
- **One backend process, no Redis.** Search jobs, the SSH concurrency limit, rate limits and live
  progress live in one process; locks are database rows. This keeps the SSH limit a real global
  limit. Horizontal scaling would need a shared queue/broker and is not required for hundreds of
  switches (measured: 100 switches with 5 parallel sessions, < 1 s CPU, ~80 MB RSS — see
  [FINAL_PROJECT_REPORT.md](../FINAL_PROJECT_REPORT.md#7-testing)).
- **Interactive SSH shell** (asyncssh) as an operator would use it: prompt learning, pager
  handling, `ERROR:` detection, host-key pinning.
- **Fail closed** everywhere: unknown model/version, unverified command, unexpected output,
  unreadable safety state, uncertain classification.
