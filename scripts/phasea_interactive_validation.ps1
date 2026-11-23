[CmdletBinding()]
param(
    [int]$PostgresPort = 55432,
    [switch]$KeepArtifacts,
    [switch]$SkipDependencies
)

<#
.SYNOPSIS
    Run Phase A collector validation against a uniquely named disposable PostgreSQL.

.DESCRIPTION
    This runner is intended for a normal interactive Windows PowerShell session.
    It never uses the application's database, never reuses a Compose project, and
    only removes the Compose project it creates.  It does not run benchmarks because
    this repository does not currently provide a documented synthetic NSEL benchmark
    harness; the result records that benchmark evidence is blocked rather than
    manufacturing a comparison.
#>

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python312 = "C:\Users\me\AppData\Roaming\uv\python\cpython-3.12-windows-x86_64-none\python.exe"
$uv = "C:\Users\me\.local\bin\uv.exe"
$composeFile = Join-Path $repo "ci\compose\docker-compose.postgres-test.yml"
$runId = "{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), ([guid]::NewGuid().ToString("N").Substring(0, 12))
$project = "kaya-phasea-$($runId.ToLowerInvariant())"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "kaya-phasea-$runId"
$venv = Join-Path $tempRoot "venv"
$testPython = Join-Path $venv "Scripts\python.exe"
$artifacts = Join-Path $repo "artifacts\phasea-validation-$runId"
$composeEnv = Join-Path $tempRoot "compose.env"
$database = "kaya_test"
$dbUser = "kaya_test"
$dbPassword = "kaya_test_only"
$databaseUrl = "postgresql+psycopg://${dbUser}:${dbPassword}@127.0.0.1:${PostgresPort}/${database}"
$composeStarted = $false
$transcriptStarted = $false
$script:CurrentStage = "initialization"
$script:LastNativeExitCode = 0
$primaryFailure = $null
$primaryStage = $null
$primaryMessage = $null
$primaryExitCode = 1
$cleanupFailure = $null

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command is not available: $Name"
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Stage,
        [switch]$AllowFailure
    )
    $script:CurrentStage = $Stage
    $safeStage = $Stage -replace "[^A-Za-z0-9_.-]", "_"
    $stdoutPath = Join-Path $artifacts "native-$safeStage-stdout.txt"
    $stderrPath = Join-Path $artifacts "native-$safeStage-stderr.txt"
    # Start-Process redirects native streams before they enter PowerShell. In
    # Windows PowerShell 5.1, ordinary native stderr can otherwise become an
    # ErrorRecord and Stop can terminate on Compose progress such as "Stopping".
    $startArguments = @(
        foreach ($argument in $Arguments) {
            if ($argument -match '[\s"]') {
                '"' + ($argument -replace '"', '\"') + '"'
            } else {
                $argument
            }
        }
    )
    $process = Start-Process -FilePath $File -ArgumentList $startArguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $exitCode = $process.ExitCode
    $script:LastNativeExitCode = $exitCode
    # Get-Content -Raw returns $null for an existing empty file. Normalize both
    # streams so callers can safely use .Trim() for commands with no output.
    $stdout = [string]::Empty
    if (Test-Path -LiteralPath $stdoutPath) {
        $capturedStdout = Get-Content -LiteralPath $stdoutPath -Raw
        if ($null -ne $capturedStdout) { $stdout = [string]$capturedStdout }
    }
    $stderr = [string]::Empty
    if (Test-Path -LiteralPath $stderrPath) {
        $capturedStderr = Get-Content -LiteralPath $stderrPath -Raw
        if ($null -ne $capturedStderr) { $stderr = [string]$capturedStderr }
    }
    if ($stdout) { Write-Host $stdout.TrimEnd() }
    if ($stderr) { Write-Host "[$Stage stderr]"; Write-Host $stderr.TrimEnd() }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "Stage '$Stage' failed with exit code $exitCode`: $File $($Arguments -join ' '). See $stdoutPath and $stderrPath."
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr; StdoutPath = $stdoutPath; StderrPath = $stderrPath }
}

function Invoke-Checked([string]$File, [string[]]$Arguments, [string]$Stage) {
    return Invoke-NativeCapture -File $File -Arguments $Arguments -Stage $Stage
}

function Write-Result([hashtable]$Result) {
    $Result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $artifacts "summary.json") -Encoding UTF8
}

function Assert-Tools {
    if (-not (Test-Path -LiteralPath $python312 -PathType Leaf)) { throw "Python 3.12.15 was not found at $python312" }
    if (-not (Test-Path -LiteralPath $uv -PathType Leaf)) { throw "uv was not found at $uv" }
    if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) { throw "Missing disposable Compose file: $composeFile" }
    $versionResult = Invoke-Checked $python312 @("--version") "verify-python"
    $version = ($versionResult.Stdout + $versionResult.Stderr).Trim()
    if ($version -notmatch '^Python 3\.12\.15$') { throw "Refusing unsupported interpreter: $version" }
    Invoke-Checked $uv @("--version") "verify-uv" | Out-Null
    Require-Command "docker"
    Require-Command "docker.exe"
}

function Assert-PortUnused([int]$Port) {
    if ($Port -lt 1024 -or $Port -gt 65535) { throw "PostgresPort must be between 1024 and 65535." }
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        throw "Refusing to use occupied PostgreSQL test port $Port. Stop identifying the owner or choose -PostgresPort explicitly."
    }
}

function Assert-DockerDaemon {
    Invoke-Checked "docker.exe" @("version") "docker-version" | Out-Null
    Invoke-Checked "docker.exe" @("info") "docker-info" | Out-Null
    Invoke-Checked "docker.exe" @("context", "show") "docker-context" | Out-Null
}

function Assert-NewProject {
    $check = Invoke-NativeCapture "docker.exe" @("compose", "-p", $project, "-f", $composeFile, "ps", "-aq") "verify-new-compose-project" -AllowFailure
    if ($check.ExitCode -ne 0) { throw "Could not verify that Compose project $project is unused." }
    if ($check.Stdout.Trim()) { throw "Refusing to reuse existing Compose project $project." }
}

function Assert-DisposablePostgres {
    $containerId = (Invoke-Checked "docker.exe" @("compose", "-p", $project, "-f", $composeFile, "ps", "-q", "postgres") "inspect-compose-container").Stdout.Trim()
    if (-not $containerId) { throw "Disposable PostgreSQL container was not found in project $project." }
    # Use JSON for labels so Windows PowerShell does not strip the embedded
    # quotes required by Go's index template syntax.
    $labelJson = (Invoke-Checked "docker.exe" @("inspect", "--format", "{{json .Config.Labels}}", $containerId) "inspect-compose-labels").Stdout.Trim()
    $labels = $labelJson | ConvertFrom-Json
    if ($labels.'com.docker.compose.project' -ne $project -or $labels.'com.docker.compose.service' -ne "postgres") {
        throw "Container ownership check failed: $labelJson"
    }
    $image = (Invoke-Checked "docker.exe" @("inspect", "--format", "{{.Config.Image}}", $containerId) "inspect-compose-image").Stdout
    if ($image.Trim() -ne "postgres:16.14") { throw "Unexpected PostgreSQL image: $image" }
    $postgresDataPath = "/var/lib/postgresql/data"
    $tmpfsJson = (Invoke-Checked "docker.exe" @("inspect", "--format", "{{json .HostConfig.Tmpfs}}", $containerId) "inspect-compose-storage").Stdout.Trim()
    if (-not $tmpfsJson -or $tmpfsJson -eq "null") { throw "Refusing non-disposable PostgreSQL storage: HostConfig.Tmpfs is missing." }
    $tmpfs = $tmpfsJson | ConvertFrom-Json
    $tmpfsPaths = @($tmpfs.PSObject.Properties | ForEach-Object { $_.Name })
    if ($tmpfsPaths -notcontains $postgresDataPath) {
        throw "Refusing non-disposable PostgreSQL storage: $postgresDataPath is not configured as tmpfs."
    }
    $mountsJson = (Invoke-Checked "docker.exe" @("inspect", "--format", "{{json .Mounts}}", $containerId) "inspect-compose-mounts").Stdout.Trim()
    if ($mountsJson -and $mountsJson -ne "null") {
        $mounts = $mountsJson | ConvertFrom-Json
        foreach ($mount in @($mounts)) {
            $destination = [string]$mount.Destination
            $isPostgresDataMount = $destination -eq $postgresDataPath -or $postgresDataPath.StartsWith($destination.TrimEnd("/") + "/")
            if ($isPostgresDataMount -and $mount.Type -ne "tmpfs") {
                throw "Refusing persistent PostgreSQL storage at $destination (type $($mount.Type))."
            }
        }
    }
    $config = (Invoke-Checked "docker.exe" @("inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", $containerId) "inspect-compose-environment").Stdout
    if ($config -notmatch '^POSTGRES_DB=kaya_test$' -or $config -notmatch '^POSTGRES_USER=kaya_test$' -or $config -notmatch '^POSTGRES_PASSWORD=kaya_test_only$') {
        throw "PostgreSQL disposable marker/credentials check failed."
    }
    $actualDb = (Invoke-Checked "docker.exe" @("compose", "-p", $project, "-f", $composeFile, "exec", "-T", "postgres", "psql", "-U", $dbUser, "-d", $database, "-Atqc", "SELECT current_database()") "verify-database-identity").Stdout.Trim()
    if ($actualDb -ne $database) { throw "Connected database verification failed: $actualDb" }
    $serverAddress = (Invoke-Checked "docker.exe" @("inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", $containerId) "inspect-compose-address").Stdout.Trim()
    if (-not $serverAddress) { throw "Could not determine disposable PostgreSQL container address." }
    return @{ ContainerId = $containerId; ServerAddress = $serverAddress }
}

try {
    New-Item -ItemType Directory -Force -Path $tempRoot, $artifacts | Out-Null
    Start-Transcript -LiteralPath (Join-Path $artifacts "execution.log") -Force | Out-Null
    $transcriptStarted = $true
    Write-Host "Phase A validation run: $runId"
    Write-Host "Artifacts: $artifacts"

    Assert-Tools
    Assert-PortUnused $PostgresPort
    Assert-DockerDaemon
    Assert-NewProject

    @(
        "KAYA_POSTGRES_TEST_PORT=$PostgresPort"
        "POSTGRES_DB=$database"
        "POSTGRES_USER=$dbUser"
        "POSTGRES_PASSWORD=$dbPassword"
    ) | Set-Content -LiteralPath $composeEnv -Encoding ASCII

    if (-not $SkipDependencies) {
        Invoke-Checked $uv @("venv", $venv, "--python", $python312) "create-python-venv" | Out-Null
        Invoke-Checked $uv @("pip", "install", "--python", $testPython, "-r", (Join-Path $repo "requirements.txt"), "pytest") "install-python-dependencies" | Out-Null
    }
    if (-not (Test-Path -LiteralPath $testPython -PathType Leaf)) { throw "Isolated Python environment is missing: $testPython" }
    $testVersionResult = Invoke-Checked $testPython @("--version") "verify-isolated-python"
    $actualTestVersion = ($testVersionResult.Stdout + $testVersionResult.Stderr).Trim()
    if ($actualTestVersion -notmatch '^Python 3\.12\.15$') { throw "Isolated environment is not Python 3.12.15: $actualTestVersion" }
    Invoke-Checked $testPython @("-c", "import pysnmp, psycopg, sqlalchemy, pytest; print('dependency-imports-ok')") "verify-python-dependencies" | Out-Null

    $composeStarted = $true
    Invoke-Checked "docker.exe" @("compose", "--env-file", $composeEnv, "-p", $project, "-f", $composeFile, "up", "-d", "--wait", "postgres") "start-disposable-postgres" | Out-Null
    $pg = Assert-DisposablePostgres
    $env:KAYA_TEST_POSTGRES_CONTAINER = "1"
    $env:KAYA_TEST_POSTGRES_SERVER_ADDR = $pg.ServerAddress
    $env:KAYA_TEST_POSTGRES_URL = $databaseUrl
    $env:FLOW_POSTGRES_TEST_URL = $databaseUrl
    $env:DATABASE_URL = $databaseUrl
    $env:SECRET_KEY = "phasea-validation-synthetic-secret-do-not-use"
    $env:ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" 
    $env:PYTHONPATH = $repo

    Invoke-Checked $testPython @(
        (Join-Path $repo "scripts\kaya_test_migrations.py"), "upgrade", "head", "--url", $databaseUrl
    ) "apply-guarded-migrations" | Out-Null
    $migrationGuard = Invoke-NativeCapture $testPython @(
        (Join-Path $repo "scripts\kaya_test_migrations.py"), "upgrade", "head", "--url", "postgresql+psycopg://kaya_test:kaya_test_only@example.invalid/kaya"
    ) "verify-migration-rejection" -AllowFailure
    $migrationGuard | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $artifacts "migration-guard-check.json") -Encoding UTF8
    if ($migrationGuard.ExitCode -eq 0) { throw "Migration guard unexpectedly accepted a non-local, non-test database target." }

    Push-Location $repo
    try {
        $testPaths = @(
            "tests/test_flow_collector.py",
            "tests/test_flow_collector_postgres_concurrency.py",
            "tests/test_network_traffic.py",
            "tests/test_network_traffic_snmp_integration.py",
            "tests/test_endpoint_traffic_accounting.py",
            "tests/test_device_traffic.py"
        )
        $pytestArguments = @("-m", "pytest", "-q", "--basetemp", (Join-Path $artifacts "pytest-tmp")) + $testPaths
        $testResult = Invoke-NativeCapture $testPython $pytestArguments "run-targeted-pytest" -AllowFailure
        $testExit = $testResult.ExitCode
    } finally { Pop-Location }

    $summary = [ordered]@{
        run_id = $runId
        python = $actualTestVersion
        compose_project = $project
        postgres_target = $databaseUrl
        tests_exit_code = $testExit
        benchmark_status = "BLOCKED: no documented synthetic NSEL benchmark harness is present in this repository"
        benchmark_evidence = $null
        resources = "disposable Compose postgres service with tmpfs storage; isolated Python venv; artifacts directory"
        cleanup = "pending"
    }
    Write-Result $summary
    if ($testExit -ne 0) { throw "Targeted pytest suite failed with exit code $testExit. See $artifacts\pytest.log" }
    Write-Host "Validation tests passed. Benchmark status is explicitly BLOCKED; no performance claim was made."
} catch {
    $primaryFailure = $_
    $primaryStage = $script:CurrentStage
    $primaryMessage = $_.Exception.Message
    if ($script:LastNativeExitCode -ne 0) { $primaryExitCode = $script:LastNativeExitCode }
    $failure = [ordered]@{
        run_id = $runId
        status = "FAILED_OR_BLOCKED"
        stage = $primaryStage
        exit_code = $primaryExitCode
        error = $primaryMessage
        artifacts = $artifacts
    }
    try { $failure | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifacts "failure.json") -Encoding UTF8 } catch { $cleanupFailure = $_ }
} finally {
    try {
        Remove-Item Env:KAYA_TEST_POSTGRES_CONTAINER,Env:KAYA_TEST_POSTGRES_SERVER_ADDR,Env:KAYA_TEST_POSTGRES_URL,Env:FLOW_POSTGRES_TEST_URL,Env:DATABASE_URL,Env:SECRET_KEY,Env:ENCRYPTION_KEY,Env:PYTHONPATH -ErrorAction SilentlyContinue
        if ($composeStarted) {
            $cleanupResult = Invoke-NativeCapture "docker.exe" @("compose", "--env-file", $composeEnv, "-p", $project, "-f", $composeFile, "down", "--remove-orphans") "cleanup-run-owned-compose" -AllowFailure
            if ($cleanupResult.ExitCode -ne 0) {
                $cleanupFailure = "Cleanup failed with exit code $($cleanupResult.ExitCode). See $($cleanupResult.StdoutPath) and $($cleanupResult.StderrPath)."
            }
        }
        if (Test-Path -LiteralPath $composeEnv) { Remove-Item -LiteralPath $composeEnv -Force }
        if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
    } catch {
        $cleanupFailure = $_.Exception.Message
    }
    try {
        if ($cleanupFailure) { Set-Content -LiteralPath (Join-Path $artifacts "cleanup-error.txt") -Value $cleanupFailure -Encoding UTF8 }
    } catch { }
    try { if ($transcriptStarted) { Stop-Transcript | Out-Null } } catch { }
}

if ($primaryFailure) {
    Write-Host "Phase A validation failed at stage '$primaryStage': $primaryMessage"
    if ($cleanupFailure) { Write-Host "Cleanup reported separately: $cleanupFailure" }
    exit $primaryExitCode
}
if ($cleanupFailure) {
    Write-Host "Phase A validation cleanup failed: $cleanupFailure"
    exit 1
}
exit 0

