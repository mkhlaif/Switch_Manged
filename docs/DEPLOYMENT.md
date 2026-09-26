# Deployment guide

This guide takes the platform from an empty server to a **safe first production state**:
read-only operations on real switches, with state-changing operations still impossible until you
deliberately enable them after lab validation.

## 1. Requirements

- Linux server with Docker Engine 24+ and the Compose plugin.
- Network reachability from the server to the switch management addresses (TCP 22).
- A DNS name and TLS certificate for the web UI (or an existing TLS-terminating load balancer).
- A dedicated SSH account on the switches. Read-only privileges are enough until you enable port
  restarts; a restart needs the privilege to run `interfaces … admin-state` (AOS 8) or
  `interfaces … admin` (AOS 6) and, for PoE cycling, `lanpower …`.
- Optional: NetBox and/or Zabbix read-only API tokens.

## 2. Install

```bash
git clone <repo> netops && cd netops
cp .env.example .env
```

Edit `.env`:

| Variable | Set to |
|---|---|
| `POSTGRES_PASSWORD` | long random value |
| `CREDENTIAL_ENCRYPTION_KEY` | `openssl rand -base64 32 \| tr '+/' '-_'` (back it up securely) |
| `COOKIE_SECURE` | `true` |
| `READ_ONLY_MODE` | `true` (keep it for the first deployment) |
| `NETWORK_COMMAND_EXECUTION` | `ENABLED` (any other value forces the kill switch) |
| `NETBOX_URL` / `NETBOX_TOKEN`, `ZABBIX_URL` / `ZABBIX_TOKEN` | optional, read-only tokens |

Never put real secrets in `.env.example` and never commit `.env`.

```bash
docker compose up -d --build
docker compose exec backend python -m app.cli create-user --role admin youradmin
```

The schema is migrated automatically (`alembic upgrade head`) on every backend start. Open
`https://<server>:8443` (with `NGINX_SITE=https.conf` and certificates in `./certs/tls.crt` and
`./certs/tls.key`) or put your load balancer in front of port 8080.

Health: `GET /api/health` returns `ok` with the firewall policy digest, or `degraded` if the
safety firewall failed its integrity check (then every command is blocked).

## 3. First configuration (read-only)

1. **Users** (*Settings → Users*): create operators, read-only users and, for non-technical staff,
   **MAC operators** (simplified screen only).
2. **Credentials** (*Settings → Credentials*): the switch SSH account.
3. **Switches** (*Switches → Add*): name, management IP, credential, location, **topology role**
   (access / distribution / core) and the **uplink ports**. Uplinks and ports of core/distribution
   switches can never be restarted outside EMERGENCY mode.
4. **Host keys**: on each switch page, *Fetch host key*, compare the fingerprint with the switch
   console, then *Trust*. Without a trusted key the platform refuses to connect.
5. **Detect** model and AOS version (`show system` only). The profile is selected by exact model
   family and version; unsupported combinations show *"Command profile unavailable for this switch
   model/version"*.

## 4. Lab verification (once per model family and AOS version)

Use one **lab** switch of each model family / AOS version you operate:

1. *Settings → Command profiles → Run read-only verification*: every read command runs once; the
   outputs must match their documented contracts. If it passes, record it (capability `READ`).
   Until then, read commands on real switches of that family/version are refused.
2. MAC search for a known endpoint and compare switch, port, VLAN, LLDP and MAC count with the CLI.
3. Switch to **MAINTENANCE** mode (*Safety Controls*), keep dry-run on, and prepare a restart of a
   lab access port. Check the exact commands.
4. Disable dry-run (*Settings → Port actions*), restart the lab port, and check the change report
   (port UP, MAC relearned, VLANs unchanged).
5. Record the strategy's lab verification (*Settings → Command profiles → Record*).
6. Turn dry-run back on and return to **NORMAL** mode.

See [AOS_COMMAND_VERIFICATION.md](AOS_COMMAND_VERIFICATION.md) for the command details.

## 5. Enabling port restarts in production

Only when the lab verification is complete and the organisation has approved it:

1. Set `READ_ONLY_MODE=false` in `.env` and `docker compose up -d`.
2. For each maintenance window, an administrator switches the operation mode to **MAINTENANCE**
   (reason required, audited) and back to **NORMAL** afterwards. In NORMAL mode restarts can be
   prepared and simulated but never executed.
3. Decide whether dry-run stays on globally. With dry-run on, nothing is ever sent.

Emergency stop: any operator or administrator can press **STOP ALL NETWORK OPERATIONS** in
*Safety Controls*; `NETWORK_COMMAND_EXECUTION=DISABLED` in `.env` does the same at the
environment level.

## 6. Operations

| Task | How |
|---|---|
| Upgrade | `git pull && docker compose up -d --build` (migrations run on start; running restarts get 90 s to finish) |
| Backup | PostgreSQL volume `pgdata` (e.g. `docker compose exec postgres pg_dump …`) **and** `CREDENTIAL_ENCRYPTION_KEY` |
| Logs | `docker compose logs backend`; `LOG_FORMAT=json` for log shippers. Levels include `SECURITY` and `AUDIT` |
| SAFE MODE tripped | investigate the reason shown in *Safety Controls* (SSH/auth failures, validation failures, unexpected CLI output), fix it, then *Reset SAFE MODE* with a reason |
| Interrupted restart | after a crash, running actions are marked *interrupted*; check the port state on the switch manually (the message names the port) |

## 7. Scaling and topology

- The backend runs as **one** process by design (global SSH limit, in-memory progress broker and
  rate limits, DB-backed locks). It handles hundreds of switches with `MAX_CONCURRENT_SSH`
  parallel sessions. Redis is not used; see the README.
- PostgreSQL is required in production (SQLite is for development and tests only).

## 8. Lab mode

`ENABLE_SIMULATOR=true` adds simulated switches (`python -m app.cli seed-lab`) and, with
`docker compose --profile lab up -d`, a lab SSH server. Never enable it in production.
