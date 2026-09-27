# Security

This document describes how the platform protects the network it controls and itself. The
command path to the switches is described in detail in [SECURITY_FIREWALL.md](SECURITY_FIREWALL.md);
the verification of every AOS command in [AOS_COMMAND_VERIFICATION.md](AOS_COMMAND_VERIFICATION.md);
the database in [DATABASE.md](DATABASE.md).

Priority order for every design decision:

```
NETWORK SAFETY > FUNCTIONALITY > PERFORMANCE > UI
```

## 1. What the platform can do to a switch

Exactly two kinds of things, and nothing else:

1. **Read**: a small allowlist of `show` commands (MAC lookup, VLAN membership, port status,
   LLDP, MACs on a port, `show system`).
2. **Restart one port**: a link bounce (`interfaces … admin-state disable/enable` on AOS 8,
   `interfaces … admin down/up` on AOS 6) or a PoE power cycle (`lanpower …`). Only for a port
   that passed every check, after an explicit confirmation by the person who requested it.

Before either, the device must be **identified by automatic discovery** ([DISCOVERY.md](DISCOVERY.md)):
the model and AOS version come only from the device (`show system`, vendor = description AND
enterprise OID), never from what someone typed. Fail-closed properties enforced in code and tests:

| Condition | Consequence |
|---|---|
| Unknown device / AOS (not discovered, discovery failed, identity mismatch) | no state-changing operation (port_control and the firewall both refuse) |
| Unknown command profile | no execution (not even reads) |
| Unknown port type (UNKNOWN, incl. Low-confidence LIKELY_*) | no restart, for every role |
| UPLINK, LAG, MANAGEMENT, STACK | no restart, for every role |
| TRUNK / LIKELY_TRUNK / CORE / DISTRIBUTION | administrator in EMERGENCY mode with two phrases only |
| Profile not PRODUCTION_VERIFIED | no restart on a production switch (LAB_VERIFIED only on lab switches / simulator) |
| Device identity changed between discovery / confirmation and execution | restart aborted before the down command (identity re-read in the execution session) |
| Safety check / verification failure | blocked; never retried blindly; repeated failures trip the circuit breaker |

There is no configuration change, no VLAN change, no `write memory`, no reload and no free-text
CLI anywhere: not in the UI, not in the API, not in the code. Every network operation passes
*authorization → operation policy → Command Safety Firewall → AOS command profile → validator →
SSH executor*; the only code that can send text to a switch CLI is the transport's
`run_approved()`, which verifies the firewall's HMAC seal, and static tests
(`tests/test_architecture.py`) fail if any other caller or a raw-command path is introduced.

## 2. Authentication and sessions

- Passwords are hashed with **argon2**. Strength policy: 12+ characters and 3 of 4 character
  classes (maximum 256). Plaintext passwords are never stored or logged.
- Sessions: 256-bit random token in an **HttpOnly, SameSite=strict** cookie (`Secure` in
  production) plus a double-submit **CSRF token** on every state-changing request. Only the
  SHA-256 of the session token is stored. Nothing sensitive is kept in browser storage
  (`localStorage` holds only the light/dark theme) or in URLs.
- Lockout after 5 failed logins (15 minutes). Login attempts are rate limited per IP and per
  username in the backend, and per IP in nginx. Failed logins are audited.
- Sessions end after 8 hours (`SESSION_TTL_MINUTES`) or after 60 minutes without activity
  (`SESSION_IDLE_MINUTES`).
- A captured session cookie stops working on logout, password change (all other sessions end),
  role change, disabling the user, forced logout by an administrator, idle timeout or expiry; it
  cannot change anything without the per-session CSRF token (`tests/test_sessions_audit.py`).
  Sessions are not bound to an IP address (users behind NAT / roaming Wi-Fi) — use HTTPS.
- The client IP used for rate limits and the audit log cannot be forged: nginx overwrites
  `X-Forwarded-For` with the TCP peer address (see [NETWORK_SETUP.md](NETWORK_SETUP.md) for load
  balancers).
- Nobody can change their own role or disable their own account; the last active administrator
  cannot be demoted, disabled or deleted.

## 3. RBAC

Permissions are enforced **server-side on every route** (`require(Permission…)`). A test walks
all 81 API endpoints (including those of included routers) and fails if any route other than
`/health`, `/api/health` and the login is reachable without a session and a permission check.
The UI only mirrors the permissions.

| Capability | MAC_OPERATOR | READ_ONLY | OPERATOR | ADMIN |
|---|:-:|:-:|:-:|:-:|
| Search a MAC — answer = device **location only** | ✔ | | | |
| Restart the device's endpoint port directly (no approval; automatic safety checks) | ✔ | | | |
| Technical MAC search, port details, path, history, alerts, dashboard | | ✔ | ✔ | ✔ |
| View inventory, topology, safety state, settings, integrations | | ✔ | ✔ | ✔ |
| Test SSH, restart ACCESS / LIKELY ACCESS ports (typed confirmation), acknowledge alerts | | | ✔ | ✔ |
| Engage the kill switch (STOP ALL NETWORK OPERATIONS) | | | ✔ | ✔ |
| Audit log, SSH session records | | | | ✔ |
| Inventory, **bulk import**, **export**, credentials, users, roles, command profiles, lab verification | | | | ✔ |
| Operation modes, release kill switch, reset SAFE MODE, EMERGENCY operations | | | | ✔ |

## 4. MAC_OPERATOR: direct endpoint restart

MAC_OPERATOR is a separate, minimal permission set (`simple_search`, `simple_restart`), not a
rung on the ladder. Its only API is `/api/simple/*`; every other API returns 403 and is audited
as `RBAC_VIOLATION` (HIGH).

**What the role sees.** The API responses are role-aware — technical fields are not hidden by
CSS, they are never sent: `{"state", "message", "location", "can_restart", "search_id",
"request_id"}` only. The location is the administrator's label for that port
(*Device locations per port*), otherwise the switch's site and location, otherwise "Location not
recorded" — never a switch name, IP, port, VLAN, model, AOS version, LLDP, command or technical
error. Only the user's own searches and restarts are visible; another user's ids are
indistinguishable from missing ones.

**No human approval — every technical check.** `POST /api/simple/restart {search_id}` accepts
nothing else (`switch_id`, `port`, `vlan`, `command`, `role`, … are rejected). The server:

1. authenticates the user, checks the role and the per-user rate limit (3/min);
2. loads the user's own search (≤ 10 minutes old) and requires **exactly one** High-confidence
   ACCESS location on a switch whose inventory role is **access**, with every switch answering;
3. re-reads the port on the switch (**switch reachability**, **port existence**, MAC still on the
   port) through the Command Safety Firewall and the AOS command profile, and re-classifies it;
4. blocks an **administratively disabled** port (a bounce would enable it — a config change);
5. evaluates the restart policy (TRUNK / LIKELY_TRUNK / UNKNOWN / declared uplink / link
   aggregate / core or distribution switch are blocked for every role; MAC_OPERATOR needs ACCESS
   with **High** confidence);
6. runs the **endpoint evidence gate** — every signal must agree, missing evidence blocks:
   single untagged VLAN and no tagged VLANs, MAC in that VLAN, VLAN membership / LLDP / MAC
   count readable, ≤ 3 MACs on the port, admin state enabled, link up, < 10 Gbit/s, no uplink /
   trunk / management / stack / LAG wording in the port description, switch role access;
7. asks **NetBox** when configured: an interface documented as tagged, tagged-all, LAG member,
   management-only, virtual or disabled blocks; if NetBox is configured but cannot be queried,
   the restart is blocked (fail closed);
8. checks that switch, port and **VLAN** are still those of the search;
9. requires a lab-verified restart strategy for the model family and AOS version, dry run off,
   operation mode **MAINTENANCE**, no kill switch, no SAFE MODE, `NETWORK_COMMAND_EXECUTION=ENABLED`;
10. takes the switch + port locks (a second user gets "please wait"), obtains the firewall's
    sealed restart authorization, and **immediately before the change re-reads the port again**
    and re-runs the gate (any change → abort, nothing sent);
11. sends *down* (once, never repeated) → hold → *up*, then verifies: port up, MAC relearned on
    the same port and VLAN, VLAN membership and classification unchanged. Only a fully verified
    result is shown as "Device restarted successfully."; anything else is "The device could not
    be verified after restart. Please contact IT support." — the restart is never repeated
    automatically.

Before / after state, every check, the command fingerprints and the verification are in the
audit log and the port action record for administrators. Tests: `tests/test_rbac_simple.py`,
`tests/test_mac_operator_direct.py`, `tests/test_failure_modes.py`.

## 5. Bulk import and export

- Administrators only (`import_switches`, `export_switches`).
- Import files are sent as text (no multipart parsing, no file ever written to disk); limits:
  5 MB / 5000 rows in the application, 12 MB request body for this one endpoint in nginx and in
  the backend (1 MB everywhere else, enforced before authentication so an anonymous client
  cannot make the server buffer a large body).
- Files with password, key, token or secret columns are rejected; SSH credentials are only
  referenced by the name of an existing credential. Unexpected columns are rejected (a `command`
  column cannot slip through).
- Every value is validated: control characters, spreadsheet-formula prefixes (`= + - @`) and
  shell/CLI metacharacters are rejected, IPs/ports/models/AOS versions/roles are checked, and
  unsupported model/version combinations are refused. Duplicates in the file and conflicts with
  the inventory are reported per row.
- Nothing is written before the uploader confirms the preview; invalid rows must be acknowledged
  explicitly; existing switches are never overwritten unless "update" is chosen; one import at a
  time; every row is re-checked while importing and protected by UNIQUE / CHECK constraints.
- Export contains inventory metadata only — never passwords, keys, tokens or host keys (the
  credential is exported by name). CSV cells are formula-neutralised; the file name is
  generated by the server. Export is rate limited (10/min per user).

Details: [SWITCH_IMPORT_EXPORT.md](SWITCH_IMPORT_EXPORT.md).

## 6. Secrets

| Secret | Protection |
|---|---|
| Switch SSH passwords | Fernet-encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY`; never returned by the API; never logged; never imported or exported |
| `CREDENTIAL_ENCRYPTION_KEY`, `POSTGRES_PASSWORD` | environment only (`.env`, never committed, created with mode 600 on Linux; `.env.example` holds placeholders) |
| `NETBOX_TOKEN`, `ZABBIX_TOKEN` | environment only; never returned or logged (`repr()` of the clients omits them) |
| User passwords | argon2 hashes |
| Session tokens | stored as SHA-256 hashes |

A redaction filter removes anything that looks like a password, token or key from every log line,
and audit details are scrubbed of secret-named keys before they are stored. A database backup
contains only hashes and Fernet ciphertext (verified: no plaintext password, no key) — store it
like a secret and keep `CREDENTIAL_ENCRYPTION_KEY` separately.

## 7. SSH

- **Host-key pinning**: no connection happens until an administrator has enrolled the switch's host
  key after comparing its fingerprint out of band. A changed key is refused. Host-key checking is
  never disabled globally; `SSH_ALLOW_UNKNOWN_HOST_KEYS` is a lab-only switch and the UI shows a red
  warning while it is on.
- Only connection-level failures are retried (`SSH_CONNECT_RETRIES`, 0–5, default 1, with
  back-off); authentication and host-key failures never are (no account lockout storms). A
  state-changing command is never re-sent: after an ambiguous result the port's admin state is
  read first.
- Global concurrency limit (`MAX_CONCURRENT_SSH`, default 5), connect / login / command timeouts,
  an overall connect deadline, a maximum session duration (`SSH_MAX_SESSION_SECONDS`), a maximum
  of 60 commands per session, keep-alives, and a bounded close.
- Passwords are passed to the SSH library only; they are not part of any `repr()` or log line.
- Legacy SSH algorithms can be enabled per switch for old AOS 6 only.

## 8. Audit

- `audit_logs` is **append-only**. Database triggers reject UPDATE and DELETE (SQLite and
  PostgreSQL) and TRUNCATE (PostgreSQL). The application never issues either.
- Each entry records time, user, role, source IP, operation, target, switch, port, MAC, VLAN,
  profile, command fingerprint (SHA-256 of command, switch, operation and profile), risk level,
  approval, result, error and before/after state.
- Every field is bounded to its column size and oversized JSON details/state are truncated with a
  marker, so an audit entry can always be written (a crafted value cannot make auditing fail);
  CR/LF in log lines are escaped.
- Mode changes, kill switch and circuit breaker events are also written to `safety_events`.

**Limitation.** The database owner can drop triggers. For stronger guarantees run the application
with a PostgreSQL role that does not own the schema (migrations with the owner role), ship logs
(`LOG_FORMAT=json`) to an external collector, and back up the database regularly.

## 9. Integrations

- **NetBox**: HTTP `GET` only, and only to `/api/status/`, `/api/dcim/devices/` and
  `/api/dcim/interfaces/`. Query values are validated. Differences are reported as mismatches and
  alerts; nothing is ever written to NetBox. The MAC_OPERATOR restart uses NetBox as additional
  (read-only) evidence.
- **Zabbix**: JSON-RPC methods `apiinfo.version`, `host.get` and `problem.get` only. Any other
  method is refused before a request is made. The application never changes Zabbix.
- Use read-only API tokens for both. TLS verification is on by default. The URLs come from the
  environment only (no user-supplied URL is ever fetched).

## 10. Web application hardening

- Strict request schemas (`extra="forbid"`) and an ASGI guard that rejects any body field named
  like a command (`command`, `cli`, `exec`, `shell`, …) before routing.
- Request body limits (1 MB; 12 MB for the import validation) in the backend and in nginx.
- Rate limits: nginx per IP (login 30/min, API 20 req/s with bursts); backend per user for login,
  password change, MAC searches, port queries, restarts, switch test/detect/host-key fetch, lab
  verification, NetBox reconciliation, audit / history / switch exports and imports.
- Every list endpoint is paginated with an upper bound; exports are capped (50 000 audit rows,
  10 000 searches, 20 000 switches).
- Security headers: CSP (`default-src 'self'`, no inline script), `X-Frame-Options: DENY` /
  `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`, HSTS on HTTPS.
- No `eval`, `exec`, `pickle`, `yaml.load`, `shell=True`, raw-SQL string formatting or
  `innerHTML` / `dangerouslySetInnerHTML` in the code base (repository scan in the final report).
- Errors never expose stack traces; unexpected errors return a reference id that is in the
  server log. The OpenAPI documentation is disabled in production.
- CSV exports prefix cells that start with `=`, `+`, `-`, `@`, tab or CR with `'`.
- Log lines escape CR/LF, so user input cannot forge log entries.

## 11. Containers and network exposure

- No container runs as root: backend uid 10001, nginx uid 101 (`nginx-unprivileged`), PostgreSQL
  drops to the `postgres` user; `no-new-privileges`, all capabilities dropped for backend and
  nginx, read-only root filesystem for the backend, memory and PID limits.
- Two networks: `edge` (nginx, backend, outbound SSH) and `data` (backend, PostgreSQL;
  `internal`, no outside route). The web proxy cannot reach the database.
- The web ports are published on `127.0.0.1` unless `BIND_ADDRESS` is set; the backend and
  database are never published. No secret is baked into an image.

## 12. AI

There is no AI component. No AI may ever hold SSH access or call the operation API on its own. A
static test fails if an LLM SDK is imported.

## 13. Known gaps (by design or not yet implemented)

- Discovery, command profiles and restarts were tested against the simulator and documented
  output fixtures only — **not against real Alcatel-Lucent hardware**. No capability is
  LAB_VERIFIED or PRODUCTION_VERIFIED by this project.

- No multi-factor authentication and no SSO/LDAP integration.
- Rate limits and the live-progress broker are in-memory: the backend must run as **one** process
  (enforced in the Dockerfile).
- The HMAC secret that seals commands is per process; sealed requests do not survive a restart
  (intended).
- Audit immutability is enforced by the database, not by an external WORM store.
- Sessions are not bound to the client IP.
