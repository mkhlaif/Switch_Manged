#!/usr/bin/env sh
# Restore a backup made by scripts/backup.sh into the Docker Compose deployment.
#
#   ./scripts/restore.sh backups/netops-YYYYMMDDTHHMMSSZ.dump
#
# DESTRUCTIVE: replaces the current database content with the backup. The backend is stopped
# during the restore (no port action can run), then started again; it applies any newer
# migrations on start. The CREDENTIAL_ENCRYPTION_KEY in .env must be the key that was in use
# when the backup was taken.
set -eu

FILE="${1:-}"
if [ -z "${FILE}" ] || [ ! -f "${FILE}" ]; then
    echo "usage: $0 <backup-file.dump>" >&2
    exit 2
fi

printf 'This REPLACES the current database with %s. Type RESTORE to continue: ' "${FILE}"
read -r ANSWER
if [ "${ANSWER}" != "RESTORE" ]; then
    echo "Aborted; nothing was changed."
    exit 1
fi

docker compose stop backend frontend
docker compose exec -T postgres sh -c \
    'pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "${FILE}"
docker compose up -d backend frontend
echo "Restore finished. Check: curl -fsS http://127.0.0.1:${HTTP_PORT:-8080}/health"
