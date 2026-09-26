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

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$file = Join-Path $OutDir "netops-$stamp.dump"

# Write the dump inside the container, then copy it out: PowerShell pipelines are not
# byte-safe for binary data.
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/netops.dump'
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed (exit $LASTEXITCODE)" }
$container = (docker compose ps -q postgres).Trim()
docker cp "${container}:/tmp/netops.dump" $file
docker compose exec -T postgres rm -f /tmp/netops.dump | Out-Null

$size = (Get-Item $file).Length
if ($size -lt 1024) { throw "Backup $file is only $size bytes; check 'docker compose ps'." }
Write-Output "Backup written: $file ($size bytes)"
