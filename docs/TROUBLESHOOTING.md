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
| frontend restarting, `cannot load certificate key … Permission denied` (Linux) | nginx runs as uid 101: `sudo chown 101:101 certs/tls.key certs/tls.crt && sudo chmod 400 certs/tls.key` |
| backend restarting after an upgrade, log `Migration 0004 stopped: … share the management address` / `are named` | duplicate inventory entries; nothing was changed. Roll back ([UPGRADE.md](UPGRADE.md)), remove or correct the duplicates, upgrade again |
| backend restarting after `git checkout <older>`, log `Can't locate revision` | the database is newer than the code — follow the rollback procedure in [UPGRADE.md](UPGRADE.md) |
| HTTP 413 `REQUEST_TOO_LARGE` | request body over 1 MB (12 MB for the import upload) |
| HTTP 429 | rate limit (nginx per IP, or the backend per user) — wait a minute |

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

## Discovery

| Identity / category | Cause | What to do |
|---|---|---|
| *Not discovered* | never reached securely yet, or address / port / transport changed | trust the host key (switch page) or supply the fingerprint; *Run discovery*; a MAC search also discovers it |
| `HOST_KEY_UNTRUSTED` | no enrolled key and no fingerprint, or the switch presented another key than the supplied fingerprint (HIGH alert) | verify the fingerprint on the switch console; never trust a key you have not verified |
| `DEVICE_UNREACHABLE`, `TIMEOUT`, `AUTHENTICATION_FAILED` | network, SSH service or credential | as for *Test SSH connection* |
| `DISCOVERY_FAILED` | the answer did not identify an ALE OmniSwitch exactly (other vendor, AOS 7, unreadable model / version) | check the device; unsupported devices stay blocked by design |
| `PROFILE_NOT_FOUND` (identity *Discovered*) | identified, but no command profile covers that model / AOS version | nothing can be run on it; see [ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md) |
| *Identity mismatch* | the device differs from the expected metadata or from the identity discovered before (upgrade, replacement, wrong address) | check the switch; *Review and accept identity* with a reason, or fix the address / expected values |
| Search result `blocked` / `PROFILE_NOT_VERIFIED` | no READ record for that model family / AOS version (real switches) | run the read-only verification on a lab switch of that family / version |
| Restart plan says *needs PRODUCTION_VERIFIED* | production switch, strategy only LAB_VERIFIED | promote with evidence, or mark a lab switch `environment = lab` |

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

| "The port is administratively disabled; a restart would enable it" | an administrator shut the port down on purpose; restarting would be a configuration change — handle manually |

## Import and export

| Symptom | Cause / fix |
|---|---|
| file rejected: *secret-like column(s)* | remove password/key/token columns; reference the credential by name in `credential` |
| file rejected: *Unexpected column(s)* / *Missing required column(s)* | use the template (*Import → CSV template*); column names as in [SWITCH_IMPORT_EXPORT.md](SWITCH_IMPORT_EXPORT.md) |
| row *Unsupported model/AOS version* | the model/version pair has no supported command profile ([ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md)) |
| row *credential … does not exist* | create the credential first (*Settings → Credentials*) |
| *Confirm import* stays disabled | invalid/duplicate rows must be acknowledged with the checkbox, or fixed in the file |
| "Another switch import is running" | only one import at a time — wait for it (*Import* dialog shows progress) |
| "The preview expired" | previews are valid 30 minutes — upload again |
| rows *failed: Management address now belongs to …* | the inventory changed after the preview; the other rows were imported — fix and import the file again (already imported rows are *unchanged*) |
| import *interrupted* | the application stopped during the import; rows committed before are kept — import the same file again |

## Backup and restore

| Symptom | Cause / fix |
|---|---|
| "the backup could not be restored; the current database was NOT changed" | the file is damaged or not a `pg_dump` custom-format dump; nothing was changed, the application was started again |
| database `<name>_pre_restore_<timestamp>` exists | the database before the last restore, kept on purpose — drop it when you no longer need it ([BACKUP_RESTORE.md](BACKUP_RESTORE.md)) |
| `Run this from the installation directory.` | `cd` to the directory with `docker-compose.yml` first |

## MAC operators

They only see generic messages. The technical reason for every refusal is in *Audit Logs*
(actions `SIMPLE_RESTART_BLOCKED`, `PORT_RESTART_PREPARE`, `PORT_RESTART`, `RBAC_VIOLATION`).
Frequent reasons for *"This device cannot be restarted automatically"*: the switch role is not
`access`; the port has tagged VLANs, several MACs, an LLDP switch neighbour or an infrastructure
description; NetBox documents the interface as tagged / LAG / management (or NetBox is configured
but unreachable); the operation mode is not MAINTENANCE; the restart strategy is not LAB_VERIFIED (lab switch)
or PRODUCTION_VERIFIED (production switch); the switch identity is not *Discovered*; some
switches could not be checked during the search; dry run is on. See [ADMIN_GUIDE.md § MAC operators](ADMIN_GUIDE.md#mac-operators).

*"The device could not be verified after restart"*: the restart was done, but the MAC did not
come back on the same port and VLAN, or the VLANs / classification changed. The details are in
*Port Actions → verification*. The restart is never repeated automatically.
