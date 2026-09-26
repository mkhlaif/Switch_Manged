# Backup and restore

The PostgreSQL database holds users, inventory, encrypted switch credentials, verification
records, history and the audit log. Back up **two** things:

1. the database (scripts below), and
2. `CREDENTIAL_ENCRYPTION_KEY` from `.env` — stored separately and securely (password manager /
   vault). Without it the switch passwords in a backup cannot be decrypted.

Backups contain password hashes and encrypted credentials: protect them like secrets. The
`backups/` directory is git-ignored; the Linux script creates files readable by the owner only
(mode 600).

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

**Destructive** — replaces the current database content. Run from the installation directory:

```bash
./scripts/restore.sh backups/netops-20260926T082936Z.dump          # asks you to type RESTORE
./scripts/restore.sh --yes backups/netops-20260926T082936Z.dump    # no prompt (scripted tests)
```

```powershell
.\scripts\restore.ps1 -File .\backups\netops-20260926T082936Z.dump        # asks you to type RESTORE
.\scripts\restore.ps1 -File .\backups\netops-20260926T082936Z.dump -Yes   # no prompt
```

What the script does:

1. stops `backend` and `frontend` (no restart or import can run during the restore);
2. checks that the file is a valid PostgreSQL dump (a damaged file is refused, nothing changed);
3. restores it into a **new, empty database** (`scripts/pg-restore-swap.sh`, run inside the
   postgres container); if that fails, the new database is dropped and the current one is
   untouched;
4. only then swaps the databases: the restored one gets the normal name, the previous one is
   **kept** as `<db>_pre_restore_<timestamp>`;
5. **always** starts `backend` and `frontend` again, also when the restore failed; the backend
   applies newer migrations on start.

After checking the application (`/health`, sign in, a MAC search), remove the kept database:

```bash
docker compose exec postgres dropdb -U netops netops_pre_restore_20260926135341
```

Why a new database instead of `pg_restore --clean` (the previous behaviour): `--clean` only drops
objects that are in the backup. After an upgrade, tables created by the newer migration stayed,
blocked the drop of the old tables and left a mixed old/new database — found in this project's
rollback test, and fixed.

`.env` must contain the `CREDENTIAL_ENCRYPTION_KEY` that was in use when the backup was taken.
The scripts judge docker by its exit code only, so they also work when their output is logged
(for example from Task Scheduler).

Verified (Windows PowerShell and Ubuntu 24.04): backup → change → restore returned exactly the
backed-up state (the later change was gone, switches, host keys, users and search history were
intact); a corrupted backup file was refused with the database unchanged and the application
running; restoring a pre-upgrade backup over an upgraded database gave exactly the old schema and
data. A backup file contains no plaintext password, token or key (checked for the switch password,
the user passwords, `POSTGRES_PASSWORD` and `CREDENTIAL_ENCRYPTION_KEY`) — only argon2 hashes and
Fernet ciphertext.

## Disaster recovery on a new machine

1. Install as in [DEPLOYMENT.md](DEPLOYMENT.md) (clone, `.env`), but put the **original**
   `CREDENTIAL_ENCRYPTION_KEY` into `.env` before the first start.
2. `docker compose up -d --build`, wait until healthy.
3. Restore the latest dump as above.
4. Re-check host keys if the new server has a different IP towards the switches (the switches'
   keys do not change).
