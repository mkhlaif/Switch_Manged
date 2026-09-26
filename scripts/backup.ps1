# Back up the PostgreSQL database of a Docker Compose deployment (Windows PowerShell).
#
#   .\scripts\backup.ps1 [-OutDir .\backups]
#
# pg_dump runs INSIDE the postgres container with the container's own environment, so no
# database password is passed on the command line. The dump contains password hashes and
# encrypted switch credentials: store it like a secret, and back up CREDENTIAL_ENCRYPTION_KEY
# separately.
param([string]$OutDir = ".\backups")
$ErrorActionPreference = "Stop"

# docker writes progress to stderr; judge native commands by their exit code only (Windows
# PowerShell 5.1 would otherwise abort when the output is redirected, e.g. in Task Scheduler).
function Invoke-Docker {
    $ErrorActionPreference = "Continue"
    & docker @args 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
    }
    if ($LASTEXITCODE -ne 0) { throw "docker $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$file = Join-Path $OutDir "netops-$stamp.dump"

# Write the dump inside the container, then copy it out: PowerShell pipelines are not
# byte-safe for binary data.
Invoke-Docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/netops.dump'
$container = ((Invoke-Docker compose ps -q postgres) | Select-Object -Last 1).Trim()
Invoke-Docker cp "${container}:/tmp/netops.dump" $file | Out-Null
Invoke-Docker compose exec -T postgres rm -f /tmp/netops.dump | Out-Null

$size = (Get-Item $file).Length
if ($size -lt 1024) { throw "Backup $file is only $size bytes; check 'docker compose ps'." }
Write-Output "Backup written: $file ($size bytes)"
