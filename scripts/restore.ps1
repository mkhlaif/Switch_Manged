# Restore a backup made by scripts\backup.ps1 (Windows PowerShell).
#
#   .\scripts\restore.ps1 -File .\backups\netops-YYYYMMDDTHHMMSSZ.dump
#   (-Yes skips the confirmation prompt, e.g. in a scripted disaster-recovery test)
#
# DESTRUCTIVE: the database content is replaced by the backup. The backup is restored into a
# NEW database first (scripts\pg-restore-swap.sh); only when that succeeded is it swapped in, and
# the previous database is kept as <db>_pre_restore_<timestamp>. The backend is stopped during
# the restore and ALWAYS started again afterwards (it applies newer migrations on start). For a
# rollback to an older version, build the older version first (docs\UPGRADE.md).
# CREDENTIAL_ENCRYPTION_KEY in .env must be the key that was in use when the backup was taken.
param([Parameter(Mandatory = $true)][string]$File, [switch]$Yes)
$ErrorActionPreference = "Stop"
# Run from the installation directory (where docker-compose.yml is), as documented.

# docker writes progress to stderr. Windows PowerShell 5.1 turns redirected native stderr into
# error records, which would abort this script half-way (e.g. when its output is logged), so
# native commands run with "Continue" and are judged by their exit code only.
function Invoke-Docker {
    $ErrorActionPreference = "Continue"
    & docker @args 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
    }
    if ($LASTEXITCODE -ne 0) { throw "docker $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

if (-not (Test-Path "docker-compose.yml")) { throw "Run this from the installation directory." }
if (-not (Test-Path $File)) { throw "Backup file not found: $File" }
$File = (Resolve-Path $File).Path
if (-not $Yes) {
    $answer = Read-Host "This REPLACES the current database with $File. Type RESTORE to continue"
    if ($answer -ne "RESTORE") { Write-Output "Aborted; nothing was changed."; exit 1 }
}

$container = ((Invoke-Docker compose ps -q postgres) | Select-Object -Last 1)
if (-not $container) { throw "The postgres container is not running ('docker compose ps')." }
$container = $container.Trim()
$ok = $false
Invoke-Docker compose stop backend frontend
try {
    # docker cp is byte-exact (PowerShell pipelines are not, for binary data).
    Invoke-Docker cp $File "${container}:/tmp/netops-restore.dump"
    Invoke-Docker cp (Join-Path $PSScriptRoot "pg-restore-swap.sh") "${container}:/tmp/pg-restore-swap.sh"
    try {
        Invoke-Docker compose exec -T postgres sh /tmp/pg-restore-swap.sh
        $ok = $true
    } catch {
        Write-Warning "Restore failed: $_ The previous database is unchanged."
    }
    try { Invoke-Docker compose exec -T postgres rm -f /tmp/pg-restore-swap.sh /tmp/netops-restore.dump | Out-Null } catch {}
} finally {
    # Never leave the application stopped.
    Invoke-Docker compose up -d backend frontend
}
if (-not $ok) { exit 1 }
Write-Output "Restore finished. Check the health endpoint, e.g. http://127.0.0.1:8080/health"
