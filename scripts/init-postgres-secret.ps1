param(
    [string]$Path = "./data/secrets/postgres_password"
)

$ErrorActionPreference = "Stop"
$parent = Split-Path -Parent $Path
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
if (-not (Test-Path -LiteralPath $Path)) {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $generator.GetBytes($bytes)
    $generator.Dispose()
    [Convert]::ToBase64String($bytes) | Set-Content -LiteralPath $Path -NoNewline
    Write-Output "Created PostgreSQL password file at $Path. Protect it and do not commit it."
} else {
    Write-Output "PostgreSQL password file already exists; it was not replaced."
}
