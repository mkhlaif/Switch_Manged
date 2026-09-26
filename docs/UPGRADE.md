# Upgrade procedure

Never update production blindly. Read the release notes / commit log first, and prefer testing
the new version on a lab installation.

## Before

1. Read what changed: `git fetch && git log --oneline HEAD..origin/main`.
2. Check that CI is green for the commit you will deploy.
3. Plan a window where no restart is needed; optionally switch to *Safety Controls → Normal*.
4. Note the current commit for rollback: `git rev-parse HEAD`.

## Upgrade

```bash
cd /opt/netops/Switch_Manged          # your installation directory
./scripts/backup.sh                    # 1. backup (Windows: .\scripts\backup.ps1)
git pull                               # 2. new version
docker compose up -d --build           # 3. rebuild; migrations run automatically at backend start
docker compose ps                      # 4. all services "healthy"
curl -fsS http://127.0.0.1:8080/health # 5. health (https.conf: curl -fsSk https://127.0.0.1:8443/health)
```

Then sign in, check the safety indicator and run one MAC search. Compare `.env.example` with your
`.env` for new variables (`git diff <old-commit> HEAD -- .env.example`).

Running restarts get up to 90 seconds to finish (send the restore command and verify) when the
backend is stopped.

## Rollback

If the new version misbehaves:

```bash
git checkout <previous-commit>
docker compose up -d --build
```

If the new version applied a **database migration**, the old code may not work with the new
schema. Then restore the backup taken in step 1 (see [BACKUP_RESTORE.md](BACKUP_RESTORE.md))
after checking out the previous commit. (Alembic downgrades exist, but restoring the backup is
the safer path.)

Verified during the project's fresh-machine test: backup → `git pull` → `docker compose up -d
--build` → all services healthy.

## After an AOS upgrade on the switches

A new AOS version prefix (for example 8.9 → 8.10) needs its own lab verification record before
the application uses its commands on that model family: run the read-only verification again
(*Settings → Command profiles*) and re-record the restart strategies after testing them on a lab
switch.
