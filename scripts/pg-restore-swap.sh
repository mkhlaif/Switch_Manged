#!/usr/bin/env sh
# Runs INSIDE the postgres container (called by restore.sh / restore.ps1): restores the dump at
# /tmp/netops-restore.dump into a NEW database and only then swaps it in.
#
# Why not "pg_restore --clean": it only drops objects that exist in the backup. Tables added by
# a newer migration (e.g. after an upgrade) would stay, can block dropping the old tables, and
# leave a mixed old/new schema. Restoring into a fresh database gives exactly the backup, and the
# current database is untouched if the restore fails. The previous database is kept as
# <db>_pre_restore_<timestamp> so the restore itself can be undone.
set -eu

DUMP=/tmp/netops-restore.dump
TS="$(date -u +%Y%m%d%H%M%S)"
TMP_DB="${POSTGRES_DB}_restore_${TS}"
OLD_DB="${POSTGRES_DB}_pre_restore_${TS}"
PSQL="psql -v ON_ERROR_STOP=1 -U ${POSTGRES_USER} -d postgres -qtA"

pg_restore --list "${DUMP}" > /dev/null   # a damaged/foreign file fails here, nothing changed
createdb -U "${POSTGRES_USER}" "${TMP_DB}"
if ! pg_restore --no-owner --exit-on-error -U "${POSTGRES_USER}" -d "${TMP_DB}" "${DUMP}"; then
    dropdb -U "${POSTGRES_USER}" "${TMP_DB}"
    echo "ERROR: the backup could not be restored; the current database was NOT changed." >&2
    exit 1
fi
${PSQL} -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${POSTGRES_DB}' AND pid <> pg_backend_pid();" > /dev/null
${PSQL} -c "ALTER DATABASE \"${POSTGRES_DB}\" RENAME TO \"${OLD_DB}\";"
${PSQL} -c "ALTER DATABASE \"${TMP_DB}\" RENAME TO \"${POSTGRES_DB}\";"
rm -f "${DUMP}"
echo "Database restored. The previous database is kept as ${OLD_DB}; after checking the"
echo "application, remove it with: docker compose exec postgres dropdb -U ${POSTGRES_USER} ${OLD_DB}"
