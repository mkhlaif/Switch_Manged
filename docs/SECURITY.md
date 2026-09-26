# Security

This document describes how the platform protects the network it controls and itself. The
command path to the switches is described in detail in [SECURITY_FIREWALL.md](SECURITY_FIREWALL.md);
the verification of every AOS command in [AOS_COMMAND_VERIFICATION.md](AOS_COMMAND_VERIFICATION.md).

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
   that passed every check, after explicit human confirmation.

There is no configuration change, no VLAN change, no `write memory`, no reload and no free-text
CLI anywhere: not in the UI, not in the API, not in the code. Static tests
(`tests/test_architecture.py`) fail if a bypass path is introduced.

## 2. Authentication and sessions

- Passwords are hashed with **argon2**. Strength policy: 12+ characters and 3 of 4 character
  classes. Plaintext passwords are never stored or logged.
- Sessions: random token in an **HttpOnly, SameSite=strict** cookie (`Secure` in production) plus
  a double-submit **CSRF token** on every state-changing request. Only the SHA-256 of the session
  token is stored.
- Lockout after 5 failed logins (15 minutes). Login attempts are rate limited per IP and per
  username. Failed logins are audited.
- A password change signs out every other session. An administrator can **force logout** a user;
  disabling a user or changing their role also ends their sessions.

## 3. RBAC

Permissions are enforced **server-side on every route** (`require(Permission…)`); a static test
verifies that every API route is authenticated. The UI only mirrors them.

| Capability | MAC_OPERATOR | READ_ONLY | OPERATOR | ADMIN |
|---|:-:|:-:|:-:|:-:|
| Simplified MAC search (switch name only) | ✔ | | | |
| Simplified restart of a confident ACCESS port | ✔ | | | |
| Technical MAC search, port details, path, history, alerts, dashboard | | ✔ | ✔ | ✔ |
| View inventory, safety state, settings, integrations | | ✔ | ✔ | ✔ |
| Test SSH, restart ACCESS / LIKELY ACCESS ports, acknowledge alerts | | | ✔ | ✔ |
| Engage the kill switch (STOP ALL NETWORK OPERATIONS) | | | ✔ | ✔ |
| Audit log, SSH session records | | | | ✔ |
| Inventory, credentials, users, command profiles, lab verification | | | | ✔ |
| Operation modes, release kill switch, reset SAFE MODE, EMERGENCY operations | | | | ✔ |

**MAC_OPERATOR** is a separate, minimal permission set, not a rung on the ladder. Its only API is
`/api/simple/*`:

- `POST /api/simple/search`, `GET /api/simple/search/{id}`: returns only a state, a plain message,
  the switch name, and whether a restart may be requested. Never a port, VLAN, IP, model, command
  or technical error. Only the user's own searches are visible.
- `POST /api/simple/restart {search_id}`, `GET /api/simple/restart/{id}`: the client never names
  a switch or port. The server derives the single valid location from the user's own recent
  search and runs the **normal** restart pipeline (pre-check, policy, firewall, locks,
  post-verification). A restart is requested only when the MAC resolves to exactly one ACCESS
  location with High/Medium confidence and every switch answered. Otherwise the user sees *"This
  device cannot be restarted automatically. Please contact IT support."* and the technical reason
  is audited.

Every other API returns 403 to a MAC_OPERATOR and is audited as `RBAC_VIOLATION` (HIGH). The
simplified screen is **not** a security boundary; the backend is.

## 4. Secrets

| Secret | Protection |
|---|---|
| Switch SSH passwords | Fernet-encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY`; never returned by the API; never logged |
| `CREDENTIAL_ENCRYPTION_KEY`, `POSTGRES_PASSWORD` | environment only (`.env`, never committed; `.env.example` holds placeholders) |
| `NETBOX_TOKEN`, `ZABBIX_TOKEN` | environment only; never returned or logged (`repr()` of the clients omits them) |
| User passwords | argon2 hashes |
| Session tokens | stored as SHA-256 hashes |

A redaction filter removes anything that looks like a password, token or key from every log line,
and audit details are scrubbed of secret-named keys before they are stored.

## 5. SSH

- **Host-key pinning**: no connection happens until an administrator has enrolled the switch's host
  key after comparing its fingerprint out of band. A changed key is refused. Host-key checking is
  never disabled globally; `SSH_ALLOW_UNKNOWN_HOST_KEYS` is a lab-only switch and the UI shows a red
  warning while it is on.
- Authentication and host-key failures are never retried (no account lockout storms).
- Global concurrency limit (`MAX_CONCURRENT_SSH`, default 5), connect / command timeouts
  (`SSH_TIMEOUT`, `COMMAND_TIMEOUT`), a maximum session duration (`SSH_MAX_SESSION_SECONDS`) and a
  maximum of 60 commands per session.
- Legacy SSH algorithms can be enabled per switch for old AOS 6 only.

## 6. Audit

- `audit_logs` is **append-only**. Database triggers reject UPDATE and DELETE (SQLite and
  PostgreSQL) and TRUNCATE (PostgreSQL). The application never issues either.
- Each entry records user, role, source IP, operation, switch, port, MAC, VLAN, profile, command
  fingerprint (SHA-256 of command, switch, operation and profile), risk level, approval, result,
  error and before/after state.
- Mode changes, kill switch and circuit breaker events are also written to `safety_events`.

**Limitation.** The database owner can drop triggers. For stronger guarantees run the application
with a PostgreSQL role that does not own the schema (migrations with the owner role), ship logs
(`LOG_FORMAT=json`) to an external collector, and back up the database regularly.

## 7. Integrations

- **NetBox**: HTTP `GET` only, and only to `/api/status/`, `/api/dcim/devices/` and
  `/api/dcim/interfaces/`. Query values are validated. Differences are reported as mismatches and
  alerts; nothing is ever written to NetBox.
- **Zabbix**: JSON-RPC methods `apiinfo.version`, `host.get` and `problem.get` only. Any other
  method is refused before a request is made. The application never changes Zabbix.
- Use read-only API tokens for both. TLS verification is on by default.

## 8. Web application hardening

- Strict request schemas (`extra="forbid"`) and an ASGI guard that rejects any body field named
  like a command (`command`, `cli`, `exec`, `shell`, …) before routing.
- Security headers: CSP (`default-src 'self'`, no inline script), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, HSTS with `COOKIE_SECURE=true`.
- Errors never expose stack traces; unexpected errors return a reference id that is in the
  server log.
- Rate limits: login, MAC searches, port queries, restart prepare/execute.

## 9. AI

There is no AI component. No AI may ever hold SSH access or call the operation API on its own. A
static test fails if an LLM SDK is imported.

## 10. Known gaps (by design or not yet implemented)

- No multi-factor authentication and no SSO/LDAP integration.
- Rate limits and the live-progress broker are in-memory: the backend must run as **one** process
  (enforced in the Dockerfile).
- The HMAC secret that seals commands is per process; sealed requests do not survive a restart
  (intended).
- Audit immutability is enforced by the database, not by an external WORM store.
