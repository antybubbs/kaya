param(
    [string[]]$TestPath = @("tests/test_flow_collector.py", "tests/test_flow_accounting.py", "tests/test_device_traffic.py", "tests/test_network_traffic_snmp_integration.py", "tests/test_network_traffic.py", "tests/test_network_traffic_reporting.py", "tests/test_network_traffic_admin.py", "tests/test_network_discovery.py", "tests/test_migration_graph.py"),
    [switch]$KeepEnvironment
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$root = Join-Path ([IO.Path]::GetTempPath()) ("kaya-python312-" + [guid]::NewGuid().ToString("N"))
$uv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"
$python = Join-Path $root "venv\Scripts\python.exe"

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    if (-not (Test-Path -LiteralPath $uv)) {
        throw "uv is not installed at $uv. Install the official uv distribution in user space first."
    }
    & $uv python install 3.12.15 | Out-Host
    & $uv venv (Join-Path $root "venv") --python 3.12.15 | Out-Host
    & $uv pip install --python $python -r (Join-Path $repo "requirements.txt") pytest | Out-Host
    $env:SECRET_KEY = & $python -c "import secrets; print(secrets.token_urlsafe(48))"
    $env:ENCRYPTION_KEY = & $python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    $env:DATABASE_URL = "sqlite:///" + ((Join-Path $root "kaya-test.db") -replace "\\", "/")
    $baseTemp = Join-Path $root "pytest-tmp"
    Push-Location $repo
    try {
        & $python -m pytest --basetemp $baseTemp -q @TestPath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item Env:SECRET_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:ENCRYPTION_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    if ($KeepEnvironment) { Write-Output "Disposable environment retained at $root" }
    elseif (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
