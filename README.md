# Switch_Manged — Alcatel Network Operations & Safety Platform

> **WARNING: this application controls production network equipment.** It can take a switch port
> down. Install it read-only, validate it on a lab switch, and only then enable port restarts —
> in that order (see [Production enablement](#production-enablement)).

## What is the application?

An internal web application for **Alcatel-Lucent Enterprise OmniSwitch (AOS)** networks. It
finds which switch and port a device (MAC address) is connected to, shows the port's state and
whether it is an access port or an uplink, and lets authorised staff **restart an endpoint port**
under strict safety controls.

Two separate experiences:

- **Technical interface** for network staff: MAC search, port details, topology, alerts, audit,
  safety controls, administration.
- **Simple screen** for non-technical staff (role `MAC_OPERATOR`): enter a MAC address → see the
  switch name → press *Restart device* → confirm. Nothing technical is shown.

## Features

- MAC search across all switches (any common MAC format), with FAST / STANDARD / DEEP modes and
  bounded SSH concurrency.
- Port inspection: admin/operational state, speed, duplex, description, VLANs, MACs, LLDP,
  error/drop/traffic counters, **access/trunk classification with evidence**.
- Controlled port restart (link bounce or PoE power cycle): re-check, typed confirmation
  `RESTART PORT <port>`, pre-restart re-verification, locks, post-restart verification, change
  report.
- Simplified MAC_OPERATOR workflow (backend-enforced, not just hidden buttons).
- Network path (device → access switch → distribution → core) and a read-only topology view,
  built from LLDP evidence without extra commands.
- Alerts (multiple locations, MAC moves, undeclared trunks, SSH failures, circuit breaker, failed
  restarts, MAC not returning, …).
- Append-only audit log with fingerprints of every command; SSH session records.
- Read-only NetBox and Zabbix integrations.
- Safety controls: operation modes, kill switch, circuit breaker (SAFE MODE), dry run.

## Architecture

```
Browser ──HTTPS──► nginx (web UI + /api proxy) ──► FastAPI backend (1 process) ──► PostgreSQL
                                                     │
                                                     ├─ authentication · RBAC · audit
                                                     ├─ operation policy
                                                     ├─ COMMAND SAFETY FIREWALL
                                                     │    allowlist · validators · AOS profiles ·
                                                     │    lab verification · seal · fingerprint ·
                                                     │    budgets · output validation
                                                     └─ SSH (asyncssh, host-key pinning) ──TCP/22──► OmniSwitches
```

Backend: Python 3.11, FastAPI, SQLAlchemy, Alembic, asyncssh. Frontend: React, TypeScript,
Tailwind. Database: PostgreSQL. Deployment: Docker Compose. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

- **RBAC** enforced by the server on every request; four roles (below).
- **Command Safety Firewall:** the browser can only request named operations
  (`SEARCH_MAC`, `GET_PORT_STATUS`, …); the backend builds every command from an exact allowlist.
  There is no way to send CLI text. Everything else is blocked and audited.
- **AOS command profiles** per model family and AOS version; unknown combinations fail closed
  ("Command profile unavailable for this switch model/version").
- **Read-only by default:** `READ_ONLY_MODE=true` and `NETWORK_COMMAND_EXECUTION=DISABLED` on a
  fresh install.
- **Circuit breaker** (SAFE MODE) after repeated SSH/authentication failures, validation failures
  or unexpected switch output; **kill switch** "STOP ALL NETWORK OPERATIONS".
- **Audit logs** that the database refuses to modify or delete.
- SSH host-key pinning, encrypted switch credentials, argon2 passwords, CSRF protection, idle
  session timeout.

Details: [docs/SECURITY.md](docs/SECURITY.md) and
[docs/SECURITY_FIREWALL.md](docs/SECURITY_FIREWALL.md).

## Supported switches

Only these combinations are supported. Every command was verified against the official ALE CLI
Reference Guides — **not yet on real hardware**; each model family/AOS version must pass the
built-in lab verification before production use (the application enforces this).

| Profile | Models | AOS | Port format |
|---|---|---|---|
| `AOS8` | OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 | 8.x (guide 8.10R1) | `1/1/24` |
| `AOS6` | OS6250, OS6350, OS6450 | 6.6, 6.7 (guide 6.7.1) | `1/24` |

Unsupported (blocked): AOS 7 (OS10K), other AOS 6 models (OS6400/6850/6855/9000E), any other
vendor. Full command list: [docs/ALCATEL_COMMAND_PROFILES.md](docs/ALCATEL_COMMAND_PROFILES.md).

## Quick start (new computer)

Needs Git and Docker (Docker Desktop on Windows, Docker Engine on Linux). Exact per-OS steps:
[docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md) · [docs/LINUX_SETUP.md](docs/LINUX_SETUP.md).

1. Install Git and Docker.
2. Clone the repository: `git clone https://github.com/mkhlaif/Switch_Manged.git`
3. Enter the directory: `cd Switch_Manged`
4. Create `.env` with generated secrets:
   - Linux: `./scripts/init-env.sh`
   - Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1`
5. Review `.env`. For the first local test nothing else is required. For access from other PCs
   set `BIND_ADDRESS` and HTTPS (see [docs/NETWORK_SETUP.md](docs/NETWORK_SETUP.md)).
6. Start: `docker compose up -d --build`
7. Database migrations run automatically when the backend starts (`docker compose logs backend`
   shows "Running upgrade … -> 0003"; nothing to run by hand).
8. Create the first administrator:
   `docker compose exec backend python -m app.cli create-user --role admin admin`
9. Open `http://localhost:8080` and sign in. Health: `http://localhost:8080/health`.
10. Keep `READ_ONLY_MODE=true` and `NETWORK_COMMAND_EXECUTION=DISABLED` — the safety indicator shows
    **STOPPED / READ ONLY**.
11. Add switches, credentials and trusted host keys (*Switches*, *Settings → Credentials*).
12. Test SSH on each switch (*Test SSH connection*, *Detect model / AOS*).
13. Test a MAC search.
14. Run the lab verification for each model family/AOS version (*Settings → Command profiles*).
15. Only then enable restart operations — see [Production enablement](#production-enablement).

## Running on another computer

Everything needed is in the repository; nothing depends on the developer's machine. A fresh
installation starts **read-only** (`READ_ONLY_MODE=true`, `NETWORK_COMMAND_EXECUTION=DISABLED`).

### Linux (Ubuntu 22.04+, Docker Engine + Compose plugin installed — see [docs/LINUX_SETUP.md](docs/LINUX_SETUP.md))

```bash
git clone https://github.com/mkhlaif/Switch_Manged.git
cd Switch_Manged
./scripts/init-env.sh                     # creates .env with a generated DB password and encryption key
docker compose up -d --build              # PostgreSQL, backend (runs DB migrations), nginx
docker compose ps                         # wait until all services are "healthy"
docker compose exec backend python -m app.cli create-user --role admin admin
curl -fsS http://127.0.0.1:8080/health    # {"status":"healthy","database":"ok",...}
```

### Windows PowerShell (Git for Windows + Docker Desktop installed — see [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md))

```powershell
git clone https://github.com/mkhlaif/Switch_Manged.git
cd Switch_Manged
powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1
docker compose up -d --build
docker compose ps
docker compose exec backend python -m app.cli create-user --role admin admin
Invoke-RestMethod http://127.0.0.1:8080/health
```

### Then

- **Browser:** `http://localhost:8080` on the same machine.
- **`.env`:** created by the init script from `.env.example`; never commit it. Back up
  `CREDENTIAL_ENCRYPTION_KEY` securely.
- **Database:** PostgreSQL runs in Docker (volume `pgdata`); migrations run automatically at
  every backend start — no manual SQL.
- **HTTPS and LAN access:** put `tls.crt`/`tls.key` into `./certs`, set `NGINX_SITE=https.conf` and
  `BIND_ADDRESS=<server LAN IP>`, open the port in the firewall, `docker compose up -d`; users
  open `https://SERVER-IP:8443` ([docs/NETWORK_SETUP.md](docs/NETWORK_SETUP.md)).
- **Switches:** *Settings → Credentials* (SSH account, stored encrypted), *Switches → Add switch*,
  then on the switch page *Fetch host key* → compare the fingerprint with the switch → *Trust*,
  *Test SSH connection*, *Detect model / AOS* (TCP/22 from the server to the switches).
- **Enabling network execution — only after the lab verification**
  ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#5-production-enablement)): in `.env` set
  `READ_ONLY_MODE=false` and `NETWORK_COMMAND_EXECUTION=ENABLED`, `docker compose up -d`, then
  *Safety Controls → Maintenance* and *Settings → Port actions → dry run off*.
- **Backup / restore / upgrade:** `./scripts/backup.sh` (`.\scripts\backup.ps1`),
  `./scripts/restore.sh <file>` (`.\scripts\restore.ps1 -File <file>`), and
  [docs/UPGRADE.md](docs/UPGRADE.md) (backup → `git pull` → `docker compose up -d --build`).

## Installation

- Windows 10/11: [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md)
- Linux (Ubuntu 22.04+): [docs/LINUX_SETUP.md](docs/LINUX_SETUP.md)
- Deployment details, HTTPS and first-time configuration: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

## Configuration

All configuration is in `.env` (created from [.env.example](.env.example); never commit `.env`).

| Variable | Default | Meaning |
|---|---|---|
| `POSTGRES_PASSWORD` | generated | database password (required) |
| `CREDENTIAL_ENCRYPTION_KEY` | generated | encrypts switch passwords; **back it up** (required) |
| `READ_ONLY_MODE` | `true` | `true` blocks every state change |
| `NETWORK_COMMAND_EXECUTION` | `DISABLED` | only `ENABLED` allows state-changing commands |
| `BIND_ADDRESS` | `127.0.0.1` | interface for the web ports; LAN IP or `0.0.0.0` for LAN access |
| `HTTP_PORT` / `HTTPS_PORT` | `8080` / `8443` | published web ports |
| `NGINX_SITE` | `http.conf` | `https.conf` for built-in HTTPS (certificates in `./certs`) |
| `COOKIE_SECURE` | `true` | cookies only over HTTPS (browsers also accept `http://localhost`) |
| `SESSION_TTL_MINUTES` / `SESSION_IDLE_MINUTES` | `480` / `60` | session lifetime / inactivity timeout |
| `MAX_CONCURRENT_SSH` | `5` | simultaneous SSH sessions |
| `SSH_TIMEOUT` / `SSH_LOGIN_TIMEOUT` / `COMMAND_TIMEOUT` | `10` / `20` / `15` s | SSH timeouts |
| `SSH_MAX_SESSION_SECONDS` | `300` | maximum duration of one SSH session |
| `SSH_ALLOW_UNKNOWN_HOST_KEYS` | `false` | lab only — never enable in production |
| `CIRCUIT_BREAKER_THRESHOLD` | `5` | SSH failures before SAFE MODE |
| `DEFAULT_DRY_RUN` | `true` | restarts are simulated until disabled |
| `NETBOX_URL` / `NETBOX_TOKEN`, `ZABBIX_URL` / `ZABBIX_TOKEN` | empty | optional read-only integrations |
| `ENABLE_SIMULATOR` | `false` | lab mode with simulated switches — never in production |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | `json` for log collectors |

## Running

```bash
docker compose up -d --build      # start / apply changes
docker compose ps                 # status (all services should be "healthy")
docker compose logs -f backend    # logs
docker compose down               # stop (data is kept in the pgdata volume)
```

Backup/restore: [docs/BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md). Updates:
[docs/UPGRADE.md](docs/UPGRADE.md).

## Windows

Git for Windows + Docker Desktop (WSL 2). Step-by-step with firewall rules and troubleshooting:
[docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md).

## Linux

Ubuntu 22.04+ with Docker Engine and the Compose plugin. Step-by-step including firewall, logs,
updates and backups: [docs/LINUX_SETUP.md](docs/LINUX_SETUP.md).

## Network setup

- Other PCs open `https://SERVER-IP:8443` (or `http://SERVER-IP:8080`) after `BIND_ADDRESS` is
  set and the port is allowed in the host firewall. Do not expose it to the Internet.
- The server needs **TCP/22 (SSH)** to the switch management addresses.

Details: [docs/NETWORK_SETUP.md](docs/NETWORK_SETUP.md).

## Switch setup

Each switch needs SSH enabled and an account the application can use (read-only privileges are
enough until restarts are enabled). In the application: add the credential, add the switch
(name, management IP, credential, topology role, uplink ports), trust its SSH host key after
comparing the fingerprint, then *Test SSH connection* and *Detect model / AOS*. See
[docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md).

## User roles

| Role | Can |
|---|---|
| `READ_ONLY` (`readonly`) | technical search, port details, topology, alerts, history |
| `MAC_OPERATOR` (`mac_operator`) | only the simple screen: search a MAC, see the switch name, restart a confidently identified endpoint port |
| `OPERATOR` (`operator`) | read-only rights + restart access ports, acknowledge alerts, engage the kill switch |
| `ADMIN` (`admin`) | everything: users, switches, credentials, command profiles, safety controls, audit |

Nobody can change their own role. Full matrix: *Settings → Roles* and
[docs/SECURITY.md](docs/SECURITY.md#3-rbac).

## MAC_OPERATOR

Non-technical staff sign in and see one screen: enter the MAC address, press **SEARCH**, read the
switch name, press **RESTART DEVICE**, confirm, wait for "Device restarted successfully." The
server re-checks everything and refuses anything that is not a confidently identified endpoint
port ("This device cannot be restarted automatically. Please contact IT support.").
Guide: [docs/MAC_OPERATOR_GUIDE.md](docs/MAC_OPERATOR_GUIDE.md).

## Production enablement

Follow this order — never enable state changes right after installation:

```
Fresh install ─► READ ONLY ─► Add switches ─► Test SSH ─► Test MAC search ─► Verify AOS profiles
  ─► Run tests ─► Test with a LAB switch ─► Enable controlled restart ─► Test an endpoint port
  ─► Production
```

Exact steps: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#5-production-enablement).

## Troubleshooting

Common problems (login fails over plain HTTP, host key not trusted, "Command profile
unavailable", SAFE MODE, port conflicts): [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Security warnings

- This software changes the state of production switch ports. Misuse or misconfiguration can
  disconnect devices or network segments.
- Keep `READ_ONLY_MODE=true` and `NETWORK_COMMAND_EXECUTION=DISABLED` until the lab validation is
  complete. Restart only endpoint ports; trunks, uplinks, core/distribution switches and
  uncertain ports are blocked by design — do not work around it.
- Never commit `.env`, backups, certificates or credentials. Back up
  `CREDENTIAL_ENCRYPTION_KEY` securely.
- Run it on an internal management network only; never expose it to the Internet.
- Use a dedicated switch account with the least privileges needed.

## Documentation

| Document | Content |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, data flow, design decisions |
| [SECURITY](docs/SECURITY.md) · [SECURITY_FIREWALL](docs/SECURITY_FIREWALL.md) | security model, command firewall |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | installation, HTTPS, first-time configuration, production enablement |
| [WINDOWS_SETUP](docs/WINDOWS_SETUP.md) · [LINUX_SETUP](docs/LINUX_SETUP.md) | step-by-step installation |
| [NETWORK_SETUP](docs/NETWORK_SETUP.md) | LAN access, firewall, switch connectivity |
| [ALCATEL_COMMAND_PROFILES](docs/ALCATEL_COMMAND_PROFILES.md) · [AOS_COMMAND_VERIFICATION](docs/AOS_COMMAND_VERIFICATION.md) | every command, model, version and verification source |
| [USER_GUIDE](docs/USER_GUIDE.md) · [ADMIN_GUIDE](docs/ADMIN_GUIDE.md) · [MAC_OPERATOR_GUIDE](docs/MAC_OPERATOR_GUIDE.md) | guides per role |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) · [BACKUP_RESTORE](docs/BACKUP_RESTORE.md) · [UPGRADE](docs/UPGRADE.md) | operations |
| [AUDIT_REPORT](AUDIT_REPORT.md) · [FINAL_PROJECT_REPORT](FINAL_PROJECT_REPORT.md) | audit findings and project status |

## Testing

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest    # no real switch needed
cd frontend && npm ci && npm test && npm run build
python backend/scripts/perf_search.py --switches 10 50 100               # performance (simulated)
```

The backend tests use a simulated OmniSwitch lab (in-process and over real SSH) — MAC found,
missing, multiple locations, timeouts, authentication failure, unexpected output, access/trunk
ports, restart success/failure, MAC not returning. CI runs the same suites on every push
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Known limitations

- Commands are documentation-verified, not yet executed on real OmniSwitch hardware (the lab
  verification step exists for this).
- Zabbix: only host availability and current problems are shown; traffic/CPU/memory/temperature
  items are template-specific and not read.
- One backend process by design (no Redis); no MFA/SSO.
- See [FINAL_PROJECT_REPORT.md](FINAL_PROJECT_REPORT.md#10-known-limitations) for the complete
  list.
