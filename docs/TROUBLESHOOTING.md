# Troubleshooting

First look at: `docker compose ps` (all services `healthy`?), `/health`, and
`docker compose logs --tail 200 backend`.

## Installation and startup

| Symptom | Cause / fix |
|---|---|
| `required variable CREDENTIAL_ENCRYPTION_KEY is missing` | `.env` missing or incomplete — run `scripts/init-env.sh` / `init-env.ps1` |
| `port is already allocated` | another program uses 8080/8443 — change `HTTP_PORT`/`HTTPS_PORT` in `.env` |
| backend `unhealthy`, log shows `CREDENTIAL_ENCRYPTION_KEY` error | the key is not a valid Fernet key — regenerate only on a **new** installation |
| backend `unhealthy`, database authentication failed | `POSTGRES_PASSWORD` changed after the first start; the database keeps the original password — restore the old value |
| `/health` returns 503 `"database":"unavailable"` | PostgreSQL not running / not reachable: `docker compose logs postgres` |
| frontend `unhealthy` | `docker compose logs frontend` — typically `https.conf` without `certs/tls.crt` and `certs/tls.key` |

## Login and access

| Symptom | Cause / fix |
|---|---|
| Login succeeds but you are immediately signed out, only from other PCs | `COOKIE_SECURE=true` requires HTTPS (except `http://localhost`) — use `NGINX_SITE=https.conf` ([NETWORK_SETUP.md](NETWORK_SETUP.md)) |
| Other PCs cannot open the page | `BIND_ADDRESS` still `127.0.0.1`, or a firewall blocks the port |
| "Too many requests" at login | rate limit (10 attempts per 5 min per user and address) — wait |
| "The account is temporarily locked" | 5 failed passwords → 15 min lock; an admin can set a new password |
| "Your session ended after a period of inactivity" | `SESSION_IDLE_MINUTES` (default 60) |
| Redirect from HTTP goes to the wrong port | set `HTTPS_PORT` in `.env` to the published HTTPS port and `docker compose up -d` |

## Switches

| Symptom | Cause / fix |
|---|---|
| `SSH HOST KEY NOT TRUSTED` | enrol the host key on the switch page; if the key *changed*, find out why before trusting it |
| `SSH negotiation failed` (old AOS 6) | enable *Legacy SSH algorithms* for that switch |
| `SSH AUTHENTICATION FAILED` | wrong credential or account not allowed from the server; not retried to avoid lockouts |
| connection timeout | routing/firewall: the host needs TCP/22 to the management IP ([NETWORK_SETUP.md](NETWORK_SETUP.md)) |
| *Command profile unavailable for this switch model/version* | unsupported model/version, model/version unknown (use *Detect*), or no lab verification for that model family/version ([ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md)) |
| `UNEXPECTED CLI OUTPUT` | the switch answered in an undocumented format; the result was discarded. Run the read-only verification on that model/version and report the output format |
| `COMMAND FAILED … may not be compatible` | the switch rejected a command; nothing was changed |

## Restarts

| Symptom | Cause / fix |
|---|---|
| "State-changing operations require MAINTENANCE mode" | switch the mode in *Safety Controls* (admin) |
| "STOP ALL NETWORK OPERATIONS is active" | kill switch engaged in the UI or `NETWORK_COMMAND_EXECUTION` is not `ENABLED` in `.env` |
| "SAFE MODE is active" | circuit breaker — investigate the reason, then *Reset SAFE MODE* |
| "not lab-verified" / only dry run possible | record the strategy verification for that model family and AOS version |
| "Network state changed since confirmation" | the port changed between confirmation and execution; nothing was sent — prepare again |
| `PORT LOCKED` / `SWITCH LOCKED` | another restart is running on that port/switch (*Safety Controls → locks*) |
| "PORT RESTART BLOCKED … trunk/uplink" / UNKNOWN | by design; handle manually if really needed |
| "WARNING: MAC has not been relearned" | the port is up but the device did not come back within the verification time; check the device |
| action shows *interrupted* | the application stopped during a restart — check that port's state on the switch manually |

## MAC operators

They only see generic messages. The technical reason for every refusal is in *Audit Logs*
(actions `SIMPLE_RESTART_BLOCKED`, `PORT_RESTART`, `RBAC_VIOLATION`).
