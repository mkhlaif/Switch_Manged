# Backup and restore

The PostgreSQL database holds users, inventory, encrypted switch credentials, verification
records, history and the audit log. Back up **two** things:

1. the database (scripts below), and
2. `CREDENTIAL_ENCRYPTION_KEY` from `.env` — stored separately and securely (password manager /
   vault). Without it the switch passwords in a backup cannot be decrypted.

Backups contain password hashes and encrypted credentials: protect them like secrets. The
`backups/` directory is git-ignored.

## Backup

Run from the project directory while the services are running:

```bash
./scripts/backup.sh                      # Linux  → ./backups/netops-<UTC timestamp>.dump
./scripts/backup.sh /var/backups/netops  # other directory
```

```powershell
.\scripts\backup.ps1                     # Windows → .\backups\netops-<UTC timestamp>.dump
```

`pg_dump` runs inside the `postgres` container with its own environment; no password appears on
the command line. The dump uses PostgreSQL's custom format (compressed). The scripts fail if the
dump is suspiciously small.

Schedule it (Linux cron example in [LINUX_SETUP.md](LINUX_SETUP.md#8-logs-updates-backups); on
Windows use Task Scheduler with `powershell -File …\scripts\backup.ps1`) and copy the files to
separate storage.

## Restore

**Destructive** — replaces the current database content:

```bash
./scripts/restore.sh backups/netops-20260926T082936Z.dump        # asks you to type RESTORE
```

```powershell
.\scripts\restore.ps1 -File .\backups\netops-20260926T082936Z.dump   # asks you to type RESTORE
```

The script stops `backend` and `frontend` (no restart can run during the restore), restores with
`pg_restore --clean --if-exists`, and starts them again; the backend applies newer migrations
on start. `.env` must contain the `CREDENTIAL_ENCRYPTION_KEY` that was in use when the backup was
taken. Check afterwards: `/health` and a sign-in.

Verified during the project's fresh-machine test: backup → change → restore returned the exact
backed-up state, and the audit log's append-only protection was active again after the restore.

## Disaster recovery on a new machine

1. Install as in [DEPLOYMENT.md](DEPLOYMENT.md) (clone, `.env`), but put the **original**
   `CREDENTIAL_ENCRYPTION_KEY` into `.env` before the first start.
2. `docker compose up -d --build`, wait until healthy.
3. Restore the latest dump as above.
4. Re-check host keys if the new server has a different IP towards the switches (the switches'
   keys do not change).
