#!/usr/bin/env sh
# Back up the PostgreSQL database of a Docker Compose deployment.
#
#   ./scripts/backup.sh [output-directory]        (default: ./backups)
#
# Runs pg_dump INSIDE the postgres container using the container's own environment, so no
# database password is passed on the command line or stored in the backup file name.
# The dump (custom format, compressed) contains user password hashes and encrypted switch
# credentials: store it like a secret. Back up CREDENTIAL_ENCRYPTION_KEY separately — without
# it the switch credentials in the dump cannot be decrypted.
set -eu

OUT_DIR="${1:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="${OUT_DIR}/netops-${STAMP}.dump"

mkdir -p "${OUT_DIR}"
umask 077
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "${FILE}"

SIZE="$(wc -c < "${FILE}")"
if [ "${SIZE}" -lt 1024 ]; then
    echo "ERROR: backup ${FILE} is only ${SIZE} bytes; check 'docker compose ps' and the postgres logs." >&2
    exit 1
fi
echo "Backup written: ${FILE} (${SIZE} bytes)"
