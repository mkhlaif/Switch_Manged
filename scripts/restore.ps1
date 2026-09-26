# Restore a backup made by scripts\backup.ps1 (Windows PowerShell).
#
#   .\scripts\restore.ps1 -File .\backups\netops-YYYYMMDDTHHMMSSZ.dump
#   (-Yes skips the confirmation prompt, e.g. in a scripted disaster-recovery test)
#
# DESTRUCTIVE: replaces the current database content. The backend is stopped during the restore
# and started again afterwards (it applies newer migrations on start). CREDENTIAL_ENCRYPTION_KEY
# in .env must be the key that was in use when the backup was taken.
param([Parameter(Mandatory = $true)][string]$File, [switch]$Yes)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) { throw "Backup file not found: $File" }
if (-not $Yes) {
    $answer = Read-Host "This REPLACES the current database with $File. Type RESTORE to continue"
    if ($answer -ne "RESTORE") { Write-Output "Aborted; nothing was changed."; exit 1 }
}

docker compose stop backend frontend
$container = (docker compose ps -q postgres).Trim()
docker cp $File "${container}:/tmp/netops-restore.dump"
docker compose exec -T postgres sh -c 'pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB" /tmp/netops-restore.dump'
$restoreExit = $LASTEXITCODE
docker compose exec -T postgres rm -f /tmp/netops-restore.dump | Out-Null
docker compose up -d backend frontend
if ($restoreExit -ne 0) { Write-Warning "pg_restore reported errors (exit $restoreExit); review the output above." }
Write-Output "Restore finished. Check: http://127.0.0.1:8080/health"
