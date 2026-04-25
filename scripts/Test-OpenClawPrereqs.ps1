param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message) | Out-Null
    if (-not $Quiet) { Write-Host "[FAIL] $Message" -ForegroundColor Red }
}

function Add-Warning {
    param([string]$Message)
    $warnings.Add($Message) | Out-Null
    if (-not $Quiet) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
}

function Add-Ok {
    param([string]$Message)
    if (-not $Quiet) { Write-Host "[ OK ] $Message" -ForegroundColor Green }
}

function Test-PortAvailable {
    param([int]$Port)
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return $null -eq $listener
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    Add-Ok "Docker CLI is on PATH"
} else {
    Add-Failure "Docker CLI is not installed or not on PATH. Install Docker Desktop or Docker Engine before starting OpenClaw."
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        $composeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0 -and $composeVersion) {
            Add-Ok "Docker Compose v2 is available: $composeVersion"
        } else {
            Add-Failure "Docker Compose v2 is not available. Docker Desktop normally includes it."
        }
    } catch {
        Add-Failure "Docker Compose v2 check failed: $($_.Exception.Message)"
    }

    try {
        docker info 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) {
            Add-Ok "Docker daemon is running"
        } else {
            Add-Failure "Docker daemon is not running. Start Docker Desktop and retry."
        }
    } catch {
        Add-Failure "Docker daemon check failed: $($_.Exception.Message)"
    }

    try {
        $memRaw = docker info --format "{{.MemTotal}}" 2>$null
        if ($LASTEXITCODE -eq 0 -and $memRaw) {
            [int64]$mem = $memRaw
            if ($mem -lt 2147483648) {
                Add-Failure "Docker reports less than 2 GB RAM. OpenClaw Docker builds may fail with OOM."
            } else {
                Add-Ok ("Docker memory is at least 2 GB ({0:N1} GB)" -f ($mem / 1GB))
            }
        }
    } catch {
        Add-Warning "Could not read Docker memory limit: $($_.Exception.Message)"
    }
}

if (Get-Command git -ErrorAction SilentlyContinue) {
    Add-Ok "Git is available"
} else {
    Add-Warning "Git is not on PATH. It is useful for updates and source verification."
}

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    Add-Ok "WSL is available"
} else {
    Add-Warning "WSL is not available. Docker Desktop on Windows is more stable with WSL2."
}

foreach ($port in @(18789, 18790)) {
    if (Test-PortAvailable -Port $port) {
        Add-Ok "TCP port $port is available"
    } else {
        Add-Failure "TCP port $port is already listening. Change OPENCLAW_GATEWAY_PORT/OPENCLAW_BRIDGE_PORT or stop the conflicting service."
    }
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        $scout = docker scout version 2>$null
        if ($LASTEXITCODE -eq 0 -and $scout) {
            Add-Ok "Docker Scout is available for image CVE audits"
        } else {
            Add-Warning "Docker Scout is not available. Audits will skip Docker Scout CVE scanning."
        }
    } catch {
        Add-Warning "Docker Scout check failed. Audits will skip Docker Scout CVE scanning."
    }
}

if ($failures.Count -gt 0) {
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "Prerequisite check failed with $($failures.Count) blocking issue(s)." -ForegroundColor Red
    }
    exit 1
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Prerequisite check passed." -ForegroundColor Green
}
exit 0

