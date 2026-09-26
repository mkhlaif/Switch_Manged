# Upgrade procedure

Never update production blindly. Read the release notes / commit log first, and prefer testing
the new version on a lab installation.

## Before

1. Read what changed: `git fetch && git log --oneline HEAD..origin/main`.
2. Check that CI is green for the commit you will deploy.
3. Plan a window where no restart is needed; switch to *Safety Controls → Normal*.
4. Note the current commit for rollback: `git rev-parse HEAD`.

## Upgrade

```bash
cd /opt/netops/Switch_Manged          # your installation directory
./scripts/backup.sh                    # 1. backup (Windows: .\scripts\backup.ps1)
git pull                               # 2. new version
cp -r scripts /tmp/netops-scripts      # 3. keep the new scripts for a rollback (see below)
docker compose up -d --build           # 4. rebuild; migrations run automatically at backend start
docker compose ps                      # 5. all services "healthy"
curl -fsS http://127.0.0.1:8080/health # 6. health (https.conf: curl -fsSk https://127.0.0.1:8443/health)
```

Windows: step 3 is `Copy-Item -Recurse scripts $env:TEMP\netops-scripts`.

Then sign in, check the safety indicator and run one MAC search. Compare `.env.example` with your
`.env` for new variables (`git diff <old-commit> HEAD -- .env.example`).

Running restarts get up to 90 seconds to finish (send the restore command and verify) when the
backend is stopped.

### Upgrading to the release with switch import (migration 0004)

- The migration first checks the inventory. If two switches share a management address or a name
  (ignoring upper/lower case), or a switch has an invalid SSH port / role / transport, the
  backend does **not** start and its log (`docker compose logs backend`) lists the switches to
  fix — nothing is changed. Fix them with the old version (roll back as below), then upgrade
  again.
- The web container now runs nginx as an unprivileged user: with HTTPS on Linux, make the key
  readable for it before starting (`sudo chown 101:101 certs/tls.key && sudo chmod 400
  certs/tls.key`, see [NETWORK_SETUP.md](NETWORK_SETUP.md)).
- MAC operators can only restart devices on switches whose role is `access`
  ([ADMIN_GUIDE.md](ADMIN_GUIDE.md#mac-operators)).

Tested: published version with data → backup → new code → `docker compose up -d --build` →
migration 0003 → 0004 on PostgreSQL, `alembic check` clean, all data and search history kept.

## Rollback

A new version may have changed the database schema. The old code refuses to start on a newer
schema ("Can't locate revision …"), so **the database must go back first**. Two tested ways:

### A. Restore the backup from step 1 (exact pre-upgrade state)

Everything changed after the upgrade is lost. Use the restore script of the **newer** version
(the copy from step 3): older scripts restored with `pg_restore --clean`, which cannot cleanly
remove tables added by a newer migration.

```bash
git checkout <previous-commit>                                   # old code
docker compose build                                             # old images (do not start yet)
/tmp/netops-scripts/restore.sh --yes backups/netops-<timestamp>.dump   # restore + start
docker compose ps && curl -fsS http://127.0.0.1:8080/health
```

```powershell
git checkout <previous-commit>
docker compose build
& $env:TEMP\netops-scripts\restore.ps1 -File .\backups\netops-<timestamp>.dump -Yes
docker compose ps
```

The restore goes into a new database that is swapped in only when it succeeded; the upgraded
database is kept as `<db>_pre_restore_<timestamp>` until you drop it
([BACKUP_RESTORE.md](BACKUP_RESTORE.md)).

Tested: after an upgrade with post-upgrade changes (new users, import jobs), this returned
exactly the pre-upgrade users, switches and search history, schema 0003, application healthy.

### B. Downgrade the schema (keeps data created after the upgrade)

Run the **new** code's downgrade while it is still installed, then switch the code back:

```bash
docker compose exec backend alembic downgrade 0003     # the previous version's head revision
git checkout <previous-commit>
docker compose up -d --build
```

Columns and tables added by the newer migration are removed (for 0004: hostname, site, port
locations, import jobs). Tested on PostgreSQL: the old version started and all switches, users
and search history were intact.

## After an AOS upgrade on the switches

A new AOS version prefix (for example 8.9 → 8.10) needs its own lab verification record before
the application uses its commands on that model family: run the read-only verification again
(*Settings → Command profiles*) and re-record the restart strategies after testing them on a lab
switch.
