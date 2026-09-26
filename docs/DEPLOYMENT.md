# Deployment guide

From an empty machine to a **safe first production state** (read-only), and from there — only
after lab validation — to controlled port restarts.

## 1. Requirements

| Item | Requirement |
|---|---|
| Host | Windows 10/11 with Docker Desktop (WSL 2), or Linux (Ubuntu 22.04+) with Docker Engine 24+ and the Compose plugin |
| Resources | 2 vCPU, 2 GB RAM, 10 GB disk are sufficient for 100+ switches (measured backend RSS ≈ 80 MB during a 100-switch search) |
| Network | TCP/22 from the host to the switch management addresses; HTTPS from user PCs to the host |
| Switches | SSH enabled; a dedicated account; supported model/AOS (see [ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md)) |
| Optional | NetBox and/or Zabbix read-only API tokens; a TLS certificate from your internal CA |

Per-OS commands: [WINDOWS_SETUP.md](WINDOWS_SETUP.md), [LINUX_SETUP.md](LINUX_SETUP.md).

## 2. Install

```bash
git clone https://github.com/mkhlaif/Switch_Manged.git
cd Switch_Manged
./scripts/init-env.sh              # Windows: powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1
# review .env (HTTPS, BIND_ADDRESS for LAN access — see NETWORK_SETUP.md)
docker compose up -d --build
docker compose exec backend python -m app.cli create-user --role admin admin
```

- **Database initialisation** is automatic: PostgreSQL creates the database from `.env` on first
  start, and the backend runs `alembic upgrade head` on every start. No manual SQL is ever
  needed. (Manual run, if you want to see it: `docker compose exec backend alembic upgrade head`.)
- Alternative to the `create-user` command: set `INITIAL_ADMIN_USERNAME` /
  `INITIAL_ADMIN_PASSWORD` in `.env` before the first start (used only while no user exists), then
  remove the password from `.env`.
- Health: `/health` returns `{"status":"healthy","database":"ok","safety_firewall":"ok",…}`;
  HTTP 503 when the database is unavailable. It never returns configuration values.

## 3. Read-only default

A fresh installation cannot change anything on a switch:

| Setting | Fresh value | Effect |
|---|---|---|
| `NETWORK_COMMAND_EXECUTION` | `DISABLED` | kill switch engaged: every state-changing command blocked |
| `READ_ONLY_MODE` | `true` | operation mode forced to READ_ONLY |
| operation mode (UI) | NORMAL | even without the two settings above, restarts are only simulated |
| dry run (UI) | on | a confirmed restart only shows the commands |
| lab verification | none | commands are refused on real switches until verified per model/version |

The safety indicator shows **STOPPED** and **READ ONLY**.

## 4. First-time configuration

As administrator:

1. **Credentials** — *Settings → Credentials → Add credential*: the switch SSH account (stored
   encrypted, never displayed again).
2. **Switches** — *Switches → Add switch*: name, management IP, SSH port, credential, site,
   location, **topology role** (access / distribution / core), **uplink ports** (e.g.
   `1/1/49, 1/1/50` or `1/25`), optionally *device locations per port* for MAC operators. Model
   and AOS version may be left empty. Many switches at once: *Switches → Import* with a CSV/JSON
   file (credentials referenced by name, never passwords) — [SWITCH_IMPORT_EXPORT.md](SWITCH_IMPORT_EXPORT.md).
3. **Host key** — on the switch page *Fetch host key*, compare the SHA-256 fingerprint with the
   switch console (`show ssh …` / your records), type its last 8 characters, *Trust this key*.
4. **Test SSH connection** — runs only `show system`.
5. **Detect model / AOS** — fills model and version and shows the selected command profile. If it
   says *"Command profile unavailable for this switch model/version"*, the combination is not
   supported (see [ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md)).
6. **Lab verification (read-only)** — *Settings → Command profiles → Run read-only verification
   on a lab switch…*: pick one switch per model family / AOS version, a known endpoint port and
   MAC, *Run checks*; if every command passes, *Record READ verification*. Until then MAC searches
   on real switches of that family/version are refused.
7. **Test a MAC search** (*MAC Search*) for a known device and compare the switch/port/VLAN with
   the switch CLI.
8. Create user accounts (*Settings → Users*): READ_ONLY, OPERATOR, ADMIN, and MAC_OPERATOR for
   non-technical staff. MAC operators restart devices without asking an administrator, so check
   the prerequisites in [ADMIN_GUIDE.md § MAC operators](ADMIN_GUIDE.md#mac-operators) (switch
   role `access`, device locations, maintenance windows).

Optional: NetBox / Zabbix URLs and tokens in `.env`, then `docker compose up -d`; check
*Settings → Integrations*.

## 5. Production enablement

**Never** enable state changes immediately after installation. Order:

```
Fresh install ─► READ ONLY ─► Add switches ─► Test SSH ─► Test MAC search ─► Verify AOS profiles
  ─► Run tests ─► Test with a LAB switch ─► Enable controlled restart ─► Test an endpoint port
  ─► Production
```

1. Complete section 4 for every model family / AOS version.
2. Run the automated tests on the version you deploy (`cd backend && python -m pytest`;
   `cd frontend && npm test`) — or check that CI is green for that commit.
3. **Lab switch test** — on a lab switch of each model family / version (the application only
   executes a restart strategy that has a verification record for that family and version, so
   the first execution is validated by hand):
   1. With dry run **on**, prepare a restart of a lab access port (*MAC Search* → result → restart).
      Note the exact commands and check the classification (ACCESS) and the command safety test.
   2. On the **lab switch console**, run those two commands once by hand and confirm that the
      port goes down and comes back up.
   3. *Settings → Command profiles*: **Record** the strategy's verification for that model family
      and AOS version, with your evidence in the notes.
   4. In `.env`: `READ_ONLY_MODE=false` and `NETWORK_COMMAND_EXECUTION=ENABLED`, then
      `docker compose up -d`.
   5. *Safety Controls → Maintenance* (reason required, audited); *Settings → Port actions*: dry
      run **off** (confirmation dialog).
   6. Restart the lab port through the application (`RESTART PORT <port>`) and check the change
      report: port UP, MAC relearned, VLANs unchanged.
   7. Dry run back **on**, *Safety Controls → Normal*. Until production go-live you may also set
      `READ_ONLY_MODE=true` again.
4. **Controlled production use** — for each maintenance window: *Safety Controls →
   Maintenance* (reason), perform the restarts, back to *Normal*. Keep dry run on outside planned
   windows if your process requires it.
5. Keep **STOP ALL NETWORK OPERATIONS** (*Safety Controls*) at hand; operators may engage it,
   only administrators release it. `NETWORK_COMMAND_EXECUTION=DISABLED` in `.env` does the same
   at host level.

## 6. HTTPS and LAN access

See [NETWORK_SETUP.md](NETWORK_SETUP.md): certificates in `./certs`, `NGINX_SITE=https.conf`,
`BIND_ADDRESS`, firewall rules, load balancers.

## 7. Operations

| Task | Document |
|---|---|
| Backup / restore | [BACKUP_RESTORE.md](BACKUP_RESTORE.md) |
| Update / rollback | [UPGRADE.md](UPGRADE.md) |
| Problems | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| SAFE MODE tripped | investigate the reason in *Safety Controls*, fix it, *Reset SAFE MODE* with a reason |
| Interrupted restart after a crash | the action is marked *interrupted*; check the named port on the switch manually |

## 8. Lab mode (testing only)

`ENABLE_SIMULATOR=true` in `.env`, `docker compose up -d`, then
`docker compose exec backend python -m app.cli seed-lab` adds seven simulated switches;
`docker compose --profile lab up -d` also starts `sim-ssh` (simulated switches over real SSH,
ports 2201–2207, user `lab` / `lab-password`). **Never enable lab mode in production.**
