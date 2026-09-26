#!/usr/bin/env sh
# Restore a backup made by scripts/backup.sh into the Docker Compose deployment.
#
#   ./scripts/restore.sh backups/netops-YYYYMMDDTHHMMSSZ.dump
#   ./scripts/restore.sh --yes backups/netops-...dump    (no prompt; scripted recovery tests)
#
# DESTRUCTIVE: the database content is replaced by the backup. The backup is restored into a
# NEW database first (scripts/pg-restore-swap.sh); only when that succeeded is it swapped in, and
# the previous database is kept as <db>_pre_restore_<timestamp>. The backend is stopped during
# the restore (no port action can run) and is ALWAYS started again afterwards; it applies newer
# migrations on start. For a rollback to an older version, build the older version first
# (docs/UPGRADE.md). CREDENTIAL_ENCRYPTION_KEY in .env must be the key that was in use when the
# backup was taken.
set -eu

YES=0
if [ "${1:-}" = "--yes" ]; then
    YES=1
    shift
fi
FILE="${1:-}"
if [ -z "${FILE}" ] || [ ! -f "${FILE}" ]; then
    echo "usage: $0 [--yes] <backup-file.dump>" >&2
    exit 2
fi
HELPER="$(dirname "$0")/pg-restore-swap.sh"
# Run from the installation directory (docker-compose.yml); the scripts themselves may live
# elsewhere, e.g. a copy of the newer scripts during a rollback (docs/UPGRADE.md).
[ -f docker-compose.yml ] || { echo "Run this from the installation directory." >&2; exit 2; }

if [ "${YES}" -ne 1 ]; then
    printf 'This REPLACES the current database with %s. Type RESTORE to continue: ' "${FILE}"
    read -r ANSWER
    if [ "${ANSWER}" != "RESTORE" ]; then
        echo "Aborted; nothing was changed."
        exit 1
    fi
fi

docker compose stop backend frontend
# Never leave the application stopped, whatever happens below.
trap 'docker compose up -d backend frontend' EXIT
docker compose exec -T postgres sh -c 'cat > /tmp/netops-restore.dump' < "${FILE}"
docker compose exec -T postgres sh -c 'cat > /tmp/pg-restore-swap.sh' < "${HELPER}"
STATUS=0
docker compose exec -T postgres sh /tmp/pg-restore-swap.sh || STATUS=$?
docker compose exec -T postgres rm -f /tmp/pg-restore-swap.sh /tmp/netops-restore.dump || true
if [ "${STATUS}" -ne 0 ]; then
    echo "ERROR: restore failed (exit ${STATUS}); the previous database is unchanged." >&2
    exit 1
fi
echo "Restore finished. Check: curl -fsS http://127.0.0.1:${HTTP_PORT:-8080}/health"
