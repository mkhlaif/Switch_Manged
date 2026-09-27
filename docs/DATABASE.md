# Database

PostgreSQL 16 in production (Docker volume `pgdata`, only on the internal `data` network);
SQLite for local development and the automated tests. The schema is managed exclusively by
Alembic migrations, which run automatically when the backend starts.

## Migrations

| Revision | Content |
|---|---|
| 0001 | initial schema (users, sessions, credentials, switches, command profiles, searches, results, port actions, audit, settings) |
| 0002 | Command Safety Firewall (SSH session records, structured audit fields) |
| 0003 | operations platform (RBAC incl. MAC_OPERATOR, modes, circuit breaker, verifications, alerts, safety events, snapshots, locks, append-only audit triggers) |
| 0004 | switch import: `import_jobs`; switches `hostname`, `site`, `port_locations`; case-insensitive UNIQUE (host, SSH port) and name; CHECK ssh_port / role / transport; indexes on `mac_search_results` |
| 0005 | automatic discovery: `discovery_jobs`; switches `vendor`, `discovery_status` (CHECK), `discovery_error` / `_category` / `_profile`, `discovered_at`, `system_name` / `_description` / `_object_id`, `expected_model`, `expected_aos_version`, `expected_host_key_fingerprint`, `environment` (CHECK production/lab) — typed model / version moved to the expected columns; `command_verifications.status` (CHECK LAB_VERIFIED / PRODUCTION_VERIFIED / BLOCKED / DEPRECATED) with who / when / why; `port_actions` `outcome`, `error_category`, `profile_version`; `audit_logs` `site`, `profile_version`, `error_category`, `outcome` (ADD COLUMN only: the append-only triggers stay); `import_jobs` `mode` (CHECK atomic/per_row), `discovery_job_id` |

**0004 checks the existing data first.** If two switches share a management address or a name
(ignoring upper/lower case), or a switch has an invalid port/role/transport, the upgrade stops
with the list of offending switches and changes nothing — fix them and start again. Existing
inventory data is never renamed, merged or deleted by a migration.

**SQLite batch migrations** rebuild a table by dropping it; with foreign keys enforced, that DROP
used to fire `ON DELETE SET NULL` on every referencing row (found in this audit: an upgrade on
SQLite nulled `mac_search_results.switch_id`). Migrations now run with SQLite foreign-key
enforcement off and finish with `PRAGMA foreign_key_check`, which fails the migration on any
broken reference. PostgreSQL migrations are transactional and not affected.

Verified (automated tests and Docker runs):

| Check | SQLite | PostgreSQL 16 |
|---|---|---|
| models == migrations (`alembic check`) | ✔ `tests/test_db_schema.py` | ✔ in the upgraded Docker deployment |
| clean database → head | ✔ | ✔ clean install |
| N-1 → N with existing data (0003 → 0004), references kept | ✔ | ✔ published version → new version |
| 0004 → 0005 with data: identity moved to expected metadata, audit triggers kept, → 0004 → 0005 | ✔ | ✔ published version → this release, downgrade with the old code, re-upgrade |
| N → N-1 (`alembic downgrade 0003`) → old code runs | ✔ | ✔ |
| N → N-1 → N | ✔ | ✔ |
| upgrade refused on duplicate inventory entries, nothing changed | ✔ | (same code path) |

Expression indexes (the case-insensitive `lower(...)` ones) cannot be reflected on SQLite, so
`alembic check` only warns about them there; `tests/test_db_schema.py` asserts their exact
definitions. A future SQLite batch migration of `switches` must re-create them (noted in 0004).

## Integrity rules

| Table | Constraints |
|---|---|
| `switches` | PK; UNIQUE `name`; UNIQUE `lower(name)`; UNIQUE (`lower(host)`, `ssh_port`); UNIQUE `hostname` when set; CHECK `ssh_port` 1–65535, `role` ∈ access/distribution/core/unknown, `transport` ∈ ssh/simulator, `discovery_status` ∈ not_discovered/discovered/discovery_failed/mismatch, `environment` ∈ production/lab; FK `credential_id` → credentials **RESTRICT** (a credential in use cannot be deleted) |
| `import_jobs` | CHECK status / format / on_existing / mode; FK `created_by_id` → users SET NULL |
| `discovery_jobs` | CHECK status; FK `created_by_id` → users SET NULL |
| `command_verifications` | UNIQUE (profile, capability, family, version); CHECK status |
| `users`, `user_sessions` | UNIQUE username; UNIQUE session token hash; sessions CASCADE with the user |
| `credentials`, `command_profiles`, `command_verifications`, `operation_locks` | UNIQUE name / key / (profile, capability, family, version) / (scope, target) — the lock table makes two state-changing operations on one switch or port impossible |
| `mac_search_results`, `mac_sightings`, `port_actions` | FKs to searches (CASCADE) and switches / users (SET NULL: history is kept when a switch or user is deleted) |
| `port_actions` | UNIQUE `plan_token` |
| `audit_logs` | append-only: triggers reject UPDATE, DELETE (and TRUNCATE on PostgreSQL) |

All columns are NOT NULL except genuinely optional ones (timestamps of events that may not have
happened, optional foreign keys, VLAN, confidence score).

## Reliability

- **Pool and timeouts** (PostgreSQL): pool 10 + overflow 10, 30 s wait for a connection,
  `pool_pre_ping`, connections recycled after 30 min, 10 s connect timeout, 60 s statement
  timeout (server and client side), and `idle_in_transaction_session_timeout` 60 s so an
  abandoned transaction cannot hold row locks. Tunable: `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`,
  `DB_POOL_TIMEOUT`, `DB_STATEMENT_TIMEOUT`.
- Every request uses its own session, closed (and rolled back if needed) at the end; background
  jobs (searches, restarts, imports) open their own short sessions.
- Unique races are decided by the database: a concurrent duplicate switch or user is a 409, a
  concurrently taken row of an import is reported as *failed* for that row only.
- Operation locks expire after 15 minutes and are cleared at startup; searches, port actions and
  imports that were running when the application stopped are marked *interrupted* at startup
  (no zombie jobs, no stale locks).
- The audit log is written even for oversized or malformed values (fields truncated to their
  column size).
- `GET /health` returns 503 when the database is unavailable (used by the Docker health check).

## Performance and indexes

Indexes were added only where a measurement showed a need:

| Query | Without index | With index | Index |
|---|---|---|---|
| import / switch API duplicate checks, 8 000 switches | 4 ms per lookup (sequential scan) | index search | `uq_switches_name_lower`, `uq_switches_host_port` |
| topology (latest found results), 1 000 000 result rows | 76 ms | 4.7 ms | `ix_mac_search_results_status_created` |
| dashboard "SSH failures today", 1 000 000 rows | 123 ms | 0.15 ms | same |
| delete one switch (FK SET NULL), 1 000 000 rows | 180 ms | 57 ms | `ix_mac_search_results_switch_id` |

Existing indexes: MAC of searches, search id of results, audit time / action / severity,
alerts, sessions, sightings, port-action plan token and creation time, import job status /
creation time. Small, rarely queried tables (settings, locks, verifications) have none beyond
their keys. Measured end-to-end numbers (search, import, export, list): see
FINAL_PROJECT_REPORT.md § Performance.

Retention: `mac_search_results` grows by one row per switch per search. There is no automatic
purge (history and audit value); plan database size accordingly (measured: 226 bytes per row
including indexes, 1 million rows = 216 MB) or archive
old searches with a scheduled SQL job.

## Backup and restore

[BACKUP_RESTORE.md](BACKUP_RESTORE.md): `pg_dump` custom format inside the container; restore
into a fresh database that is swapped in only after a successful restore (the previous database
is kept). Backups contain password hashes and encrypted switch credentials, never plaintext.
