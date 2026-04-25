param(
    [switch]$UseSandboxOverlay
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Reports = Join-Path $Root "reports"
New-Item -ItemType Directory -Force -Path $Reports | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportPath = Join-Path $Reports "openclaw-audit-$timestamp.md"
$composeArgs = @("-f", (Join-Path $Root "compose.yaml"))
if ($UseSandboxOverlay) {
    $composeArgs += @("-f", (Join-Path $Root "compose.sandbox-dind.yaml"))
}
$envFile = Join-Path $Root ".env"

function Get-DotEnvValue {
    param(
        [string]$Path,
        [string]$Name
    )
    if (-not (Test-Path $Path)) { return $null }
    $line = Get-Content $Path | Where-Object { $_ -match "^$([regex]::Escape($Name))=" } | Select-Object -First 1
    if (-not $line) { return $null }
    return $line.Split("=", 2)[1]
}

$lines = New-Object System.Collections.Generic.List[string]
function Add-Line {
    param([string]$Line = "")
    $lines.Add($Line) | Out-Null
}

Add-Line "# OpenClaw Security Audit"
Add-Line ""
Add-Line "- Timestamp: $(Get-Date -Format o)"
Add-Line "- Repository root: redacted"
Add-Line "- Sandbox overlay: $UseSandboxOverlay"
Add-Line ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Add-Line "## Result"
    Add-Line ""
    Add-Line "FAIL: Docker CLI is not installed or not on PATH."
    Set-Content -Path $reportPath -Value $lines -Encoding ascii
    Write-Host "Audit failed: Docker CLI is missing. Report: $reportPath" -ForegroundColor Red
    exit 1
}

Add-Line "## Compose Validation"
Add-Line ""
docker compose @composeArgs config 1>$null 2>$null
if ($LASTEXITCODE -eq 0) {
    Add-Line "- PASS: Compose config validates."
} else {
    Add-Line "- FAIL: Compose config does not validate."
}

Add-Line ""
Add-Line "## Runtime State"
Add-Line ""
$ps = docker compose @composeArgs ps 2>&1
Add-Line '```text'
Add-Line ($ps -join "`n")
Add-Line '```'

Add-Line ""
Add-Line "## Gateway Container Controls"
Add-Line ""
$inspectRaw = docker inspect openclaw-gateway-secure 2>$null
if ($LASTEXITCODE -eq 0 -and $inspectRaw) {
    $inspect = $inspectRaw | ConvertFrom-Json
    $hostConfig = $inspect[0].HostConfig
    $mounts = $inspect[0].Mounts
    $portBindings = $hostConfig.PortBindings
    $securityOpt = @($hostConfig.SecurityOpt)
    $capDrop = @($hostConfig.CapDrop)
    $hasDockerSock = $false
    foreach ($mount in $mounts) {
        if (($mount.Source -match "docker\.sock") -or ($mount.Destination -match "docker\.sock")) {
            $hasDockerSock = $true
        }
    }
    Add-Line "- Privileged: $($hostConfig.Privileged)"
    Add-Line "- Read-only root filesystem: $($hostConfig.ReadonlyRootfs)"
    Add-Line "- CapDrop: $($capDrop -join ', ')"
    Add-Line "- SecurityOpt: $($securityOpt -join ', ')"
    Add-Line "- Host docker.sock mounted: $hasDockerSock"
    Add-Line "- Memory limit bytes: $($hostConfig.Memory)"
    Add-Line "- Pids limit: $($hostConfig.PidsLimit)"
    if ($hostConfig.Privileged -eq $false -and $hostConfig.ReadonlyRootfs -eq $true -and $capDrop -contains "ALL" -and ($securityOpt -contains "no-new-privileges:true" -or $securityOpt -contains "no-new-privileges")) {
        Add-Line "- PASS: Gateway container hardening controls are present."
    } else {
        Add-Line "- FAIL: One or more gateway hardening controls are missing."
    }
    if ($hasDockerSock) {
        Add-Line "- FAIL: Host Docker socket is mounted into the gateway."
    } else {
        Add-Line "- PASS: Host Docker socket is not mounted into the gateway."
    }
    Add-Line "- Port bindings: $($portBindings | ConvertTo-Json -Compress)"
} else {
    Add-Line "- WARN: Gateway container is not present; start it before runtime inspection."
}

Add-Line ""
Add-Line "## Health"
Add-Line ""
$gatewayToken = $env:OPENCLAW_GATEWAY_TOKEN
if (-not $gatewayToken) {
    $gatewayToken = Get-DotEnvValue -Path $envFile -Name "OPENCLAW_GATEWAY_TOKEN"
}
$health = docker compose @composeArgs exec -T openclaw-gateway node /app/dist/index.js health --token $gatewayToken 2>&1
if ($LASTEXITCODE -eq 0) {
    Add-Line "- PASS: Authenticated health command succeeded."
} else {
    Add-Line "- WARN: Authenticated health command failed or token was not exported in this shell."
}
Add-Line '```text'
Add-Line ($health -join "`n")
Add-Line '```'

Add-Line ""
Add-Line "## Image Vulnerability Scan"
Add-Line ""
$image = "ghcr.io/phioranex/openclaw-docker:latest"
$envImage = Get-DotEnvValue -Path $envFile -Name "OPENCLAW_IMAGE"
if ($envImage) { $image = $envImage }

$scoutVersion = docker scout version 2>$null
if ($LASTEXITCODE -eq 0) {
    $scan = docker scout cves --platform linux/amd64 --only-severity critical,high $image 2>&1
    Add-Line "- Docker Scout scan attempted for `$image`."
    Add-Line '```text'
    Add-Line ($scan -join "`n")
    Add-Line '```'
} elseif (Get-Command trivy -ErrorAction SilentlyContinue) {
    $scan = trivy image --severity CRITICAL,HIGH $image 2>&1
    Add-Line "- Trivy scan attempted for `$image`."
    Add-Line '```text'
    Add-Line ($scan -join "`n")
    Add-Line '```'
} else {
    Add-Line "- WARN: No supported local scanner found. Install Docker Scout or Trivy for CVE audit coverage."
}

Set-Content -Path $reportPath -Value $lines -Encoding ascii
Write-Host "Audit report written to $reportPath"
