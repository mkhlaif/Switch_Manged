# Create .env from .env.example with freshly generated secrets (Windows PowerShell).
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1
#
# Generates POSTGRES_PASSWORD and CREDENTIAL_ENCRYPTION_KEY (Fernet key) with the .NET
# cryptographic random number generator. Never overwrites an existing .env. All other values
# keep the safe defaults of the template (READ_ONLY_MODE=true, NETWORK_COMMAND_EXECUTION=DISABLED).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (Test-Path ".env") {
    Write-Error ".env already exists; it was not modified."
    exit 1
}

function New-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return , $bytes
}

$pgPassword = -join ((New-RandomBytes 24) | ForEach-Object { $_.ToString("x2") })
$fernetKey = [Convert]::ToBase64String((New-RandomBytes 32)).Replace('+', '-').Replace('/', '_')

$content = [System.IO.File]::ReadAllText((Join-Path (Get-Location) ".env.example"))
$content = $content -replace '(?m)^POSTGRES_PASSWORD=[^\r\n]*', "POSTGRES_PASSWORD=$pgPassword"
$content = $content -replace '(?m)^CREDENTIAL_ENCRYPTION_KEY=[^\r\n]*', "CREDENTIAL_ENCRYPTION_KEY=$fernetKey"
# UTF-8 without BOM: Docker Compose must read the first variable name correctly.
[System.IO.File]::WriteAllText((Join-Path (Get-Location) ".env"), $content, (New-Object System.Text.UTF8Encoding($false)))

Write-Output "Created .env with a generated database password and credential encryption key."
Write-Output "Back up CREDENTIAL_ENCRYPTION_KEY securely: without it stored switch passwords are lost."
