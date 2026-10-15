param(
    [string]$Python312 = "",
    [string]$BaseUrl = "http://127.0.0.1:18088",
    [string]$ArtifactDir = (Join-Path ([IO.Path]::GetTempPath()) ("kaya-stage2b-browser-" + [guid]::NewGuid().ToString("N")))
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$marker = "I_UNDERSTAND_DISPOSABLE_STAGE2B"
$url = $env:KAYA_TEST_POSTGRES_URL
$node = (Get-Command node.exe -ErrorAction Stop).Source
$port = ([Uri]$BaseUrl).Port
$fixtureFile = Join-Path $ArtifactDir "fixture.json"
$appOut = Join-Path $ArtifactDir "kaya.out.log"
$appErr = Join-Path $ArtifactDir "kaya.err.log"
$sqlCountFile = Join-Path $ArtifactDir "sql-count.json"
$environmentRoot = Join-Path ([IO.Path]::GetTempPath()) ("kaya-stage2b-python312-" + [guid]::NewGuid().ToString("N"))
$uvCache = Join-Path $environmentRoot "uv-cache"
$python = $null
$app = $null

function Stop-StartedApp {
    if ($script:app -and -not $script:app.HasExited) {
        Stop-Process -Id $script:app.Id -Force -ErrorAction SilentlyContinue
        $script:app = $null
    }
}

try {
    if ($env:KAYA_STAGE2B_TEST_MARKER -ne $marker) { throw "Set KAYA_STAGE2B_TEST_MARKER=$marker before running acceptance." }
    if (-not $url) { throw "KAYA_TEST_POSTGRES_URL is required and must identify the disposable PostgreSQL test database." }
    $parsed = [Uri]$url
    if ($parsed.Host -notin @("127.0.0.1", "localhost", "::1") -or $parsed.AbsolutePath -notmatch "(?i)(test|pytest|kaya-test)" -or $parsed.AbsolutePath -match "(?i)(prod|development|/kaya$)") {
        throw "Refusing a non-disposable PostgreSQL URL. Use a local database whose name contains test, pytest or kaya-test."
    }
    $uv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"
    if (-not (Test-Path -LiteralPath $uv)) { throw "uv was not found at $uv. Install the approved user-space uv distribution first." }
    if (-not $Python312) { $Python312 = Join-Path $env:APPDATA "uv\python\cpython-3.12-windows-x86_64-none\python.exe" }
    if (-not (Test-Path -LiteralPath $Python312)) { throw "Python 3.12.15 was not found at $Python312." }
    New-Item -ItemType Directory -Force -Path $environmentRoot,$uvCache | Out-Null
    $env:UV_CACHE_DIR = $uvCache
    & $uv venv (Join-Path $environmentRoot "venv") --python (Resolve-Path -LiteralPath $Python312).Path
    if ($LASTEXITCODE -ne 0) { throw "uv could not create the disposable Python 3.12 environment (exit $LASTEXITCODE)." }
    $python = Join-Path $environmentRoot "venv\Scripts\python.exe"
    & $uv pip install --python $python -r (Join-Path $repo "requirements.txt") pytest
    if ($LASTEXITCODE -ne 0) { throw "Pinned Python dependencies could not be installed (exit $LASTEXITCODE)." }
    & $python -c "import alembic, pandas, pysnmp, smbclient, sqlalchemy, pytest; print('Kaya Stage 2B Python dependencies verified')"
    if ($LASTEXITCODE -ne 0) { throw "The disposable Python environment failed the required import check." }
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { throw "Refusing to use occupied test port $port." }
    New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

    $env:KAYA_STAGE2B_TEST_MARKER = $marker
    $env:KAYA_TEST_POSTGRES_CONTAINER = "1"
    $containerName = "kaya-stage2b-acceptance-postgres-1"
    $containerAddress = (& docker inspect -f "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}" $containerName).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $containerAddress) { throw "Could not verify the disposable PostgreSQL container address for $containerName." }
    $env:KAYA_TEST_POSTGRES_SERVER_ADDR = $containerAddress
    $env:PYTHONPATH = $repo
    $env:APP_ENV = "test"
    $env:DATABASE_URL = $url
    $env:SECRET_KEY = "stage2b-browser-synthetic-secret-012345678901234567890"
    $env:ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    & $python "$repo\scripts\kaya_test_migrations.py" upgrade head --url $url
    if ($LASTEXITCODE -ne 0) { throw "Disposable PostgreSQL migration failed (exit $LASTEXITCODE). Seeding and application startup were skipped." }
    & $python "$repo\scripts\stage2b_acceptance_seed.py" --url $url --fixture-file $fixtureFile
    if ($LASTEXITCODE -ne 0) { throw "Stage 2B fixture seeding failed (exit $LASTEXITCODE). Application startup was skipped." }
    $env:GUACD_HOST = ""
    $env:GUACD_PORT = ""
    if (-not $env:KAYA_REMOTE_WS_PORT) { $env:KAYA_REMOTE_WS_PORT = "30188" }
    $env:BASE_URL = $BaseUrl
    $env:ARTIFACT_DIR = $ArtifactDir
    $env:FIXTURE_FILE = $fixtureFile
    $env:SQL_COUNT_FILE = $sqlCountFile
    $env:KAYA_STAGE2B_SQL_COUNT_FILE = $sqlCountFile
    $env:KAYA_STAGE2B_PORT = [string]$port
    $env:KAYA_STAGE2B_PYTHON = $python
    $env:ACCEPTANCE_ADMIN_EMAIL = "stage2b-admin@example.invalid"
    $env:ACCEPTANCE_VIEWER_EMAIL = "stage2b-viewer@example.invalid"
    $env:ACCEPTANCE_PASSWORD = "Stage2B-fixture-password-012345"
    $app = Start-Process -FilePath $python -ArgumentList "-m", "scripts.stage2b_test_server" -WorkingDirectory $repo -RedirectStandardOutput $appOut -RedirectStandardError $appErr -PassThru

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { $health = Invoke-WebRequest -Uri "$BaseUrl/login" -UseBasicParsing -TimeoutSec 2; if ($health.StatusCode -ge 200 -and $health.StatusCode -lt 500) { break } } catch { }
        if ($app.HasExited) { throw "Kaya exited before browser acceptance started. See $appErr" }
        Start-Sleep -Seconds 1
    }
    if ($app.HasExited) { throw "Kaya exited before browser acceptance started. See $appErr" }
    & $node "$repo\scripts\stage2b_browser_acceptance.mjs"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output "Stage 2B browser acceptance completed. Artifacts: $ArtifactDir"
} finally {
    Stop-StartedApp
    Remove-Item Env:UV_CACHE_DIR -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $environmentRoot) { Remove-Item -LiteralPath $environmentRoot -Recurse -Force -ErrorAction SilentlyContinue }
    foreach ($name in @("DATABASE_URL", "SECRET_KEY", "ENCRYPTION_KEY", "GUACD_HOST", "GUACD_PORT", "KAYA_REMOTE_WS_PORT", "BASE_URL", "ARTIFACT_DIR", "FIXTURE_FILE", "SQL_COUNT_FILE", "KAYA_STAGE2B_SQL_COUNT_FILE", "KAYA_STAGE2B_PORT", "KAYA_STAGE2B_PYTHON", "ACCEPTANCE_ADMIN_EMAIL", "ACCEPTANCE_VIEWER_EMAIL", "ACCEPTANCE_PASSWORD", "KAYA_STAGE2B_TEST_MARKER", "KAYA_TEST_POSTGRES_CONTAINER", "KAYA_TEST_POSTGRES_SERVER_ADDR", "PYTHONPATH", "APP_ENV")) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
}
