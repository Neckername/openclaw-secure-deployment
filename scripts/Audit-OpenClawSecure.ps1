param(
    [switch]$UseSandboxOverlay,
    [int]$ScanTimeoutSeconds = 120
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
$runtimeConfigPath = Join-Path $Root "runtime\config\openclaw.json"
$pairedDevicesPath = Join-Path $Root "runtime\config\devices\paired.json"
$localOnlyDisabledPlugins = @("bonjour", "device-pair", "phone-control", "talk-voice")

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
$failureCount = 0
function Add-Line {
    param([string]$Line = "")
    $lines.Add($Line) | Out-Null
}
function Add-Pass {
    param([string]$Message)
    Add-Line "- PASS: $Message"
}
function Add-Fail {
    param([string]$Message)
    $script:failureCount++
    Add-Line "- FAIL: $Message"
}
function Add-Warn {
    param([string]$Message)
    Add-Line "- WARN: $Message"
}
function Test-EnvValue {
    param(
        [object[]]$Env,
        [string]$Name,
        [string]$Value
    )
    return ($Env -contains "$Name=$Value")
}
function Test-LoopbackPortBindings {
    param([object]$PortBindings)
    $badBindings = @()
    $hasBindings = $false
    if ($PortBindings) {
        foreach ($port in $PortBindings.PSObject.Properties) {
            foreach ($binding in @($port.Value)) {
                if (-not $binding) { continue }
                $hasBindings = $true
                $hostIp = [string]$binding.HostIp
                if ($hostIp -ne "127.0.0.1" -and $hostIp -ne "::1") {
                    $badBindings += ("{0} -> {1}:{2}" -f $port.Name, $hostIp, $binding.HostPort)
                }
            }
        }
    }
    return [pscustomobject]@{
        HasBindings = $hasBindings
        IsLoopbackOnly = ($badBindings.Count -eq 0)
        BadBindings = $badBindings
    }
}
function Get-PluginEnabledValue {
    param(
        [object]$Config,
        [string]$Plugin
    )
    if (-not $Config -or -not $Config.plugins -or -not $Config.plugins.entries) { return $null }
    $entryProperty = $Config.plugins.entries.PSObject.Properties[$Plugin]
    if (-not $entryProperty) { return $null }
    $enabledProperty = $entryProperty.Value.PSObject.Properties["enabled"]
    if (-not $enabledProperty) { return $null }
    return [bool]$enabledProperty.Value
}
function Get-JsonCollectionCount {
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [array]) { return $Value.Count }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        return @($Value.PSObject.Properties).Count
    }
    return 1
}
function Invoke-NativeWithTimeout {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutSeconds
    )
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $knownScannerIds = @(Get-Process -Name docker, docker-scout, trivy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $argumentText = (($Arguments | ForEach-Object {
        if ($_ -match '\s|"') {
            '"' + ($_ -replace '"', '\"') + '"'
        } else {
            $_
        }
    }) -join " ")
    $process = Start-Process -FilePath $FilePath -ArgumentList $argumentText -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    $completed = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $completed) {
        try { $process.Kill() } catch {}
        Get-Process -Name docker, docker-scout, trivy -ErrorAction SilentlyContinue |
            Where-Object { $knownScannerIds -notcontains $_.Id } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $output = @()
    if (Test-Path $stdout) { $output += Get-Content -Path $stdout -ErrorAction SilentlyContinue }
    if (Test-Path $stderr) { $output += Get-Content -Path $stderr -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Completed = $completed
        ExitCode = if ($completed) { $process.ExitCode } else { 124 }
        Output = $output
    }
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
    Add-Pass "Compose config validates."
} else {
    Add-Fail "Compose config does not validate."
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
$gatewayInspectAvailable = ($LASTEXITCODE -eq 0 -and $inspectRaw)
if ($gatewayInspectAvailable) {
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
        Add-Pass "Gateway container hardening controls are present."
    } else {
        Add-Fail "One or more gateway hardening controls are missing."
    }
    if ($hasDockerSock) {
        Add-Fail "Host Docker socket is mounted into the gateway."
    } else {
        Add-Pass "Host Docker socket is not mounted into the gateway."
    }
    Add-Line "- Port bindings: $($portBindings | ConvertTo-Json -Compress)"
    $gatewayPortCheck = Test-LoopbackPortBindings -PortBindings $portBindings
    if ($gatewayPortCheck.IsLoopbackOnly -and $gatewayPortCheck.HasBindings) {
        Add-Pass "Gateway host port bindings are loopback-only."
    } elseif ($gatewayPortCheck.IsLoopbackOnly) {
        Add-Warn "Gateway has no host port bindings; local browser access may not work."
    } else {
        Add-Fail "Gateway has non-loopback host port bindings: $($gatewayPortCheck.BadBindings -join ', ')."
    }
} else {
    Add-Line "- WARN: Gateway container is not present; start it before runtime inspection."
}

Add-Line ""
Add-Line "## Local-Only Plugin Controls"
Add-Line ""
$effectiveConfig = $null
if (Test-Path $runtimeConfigPath) {
    try {
        $effectiveConfig = Get-Content -Raw -Path $runtimeConfigPath | ConvertFrom-Json
    } catch {
        Add-Fail "Effective OpenClaw config could not be parsed: $($_.Exception.Message)"
    }
} else {
    Add-Warn "Effective OpenClaw config is not present at runtime\config\openclaw.json."
}

$gatewayLogText = ""
$latestReadyPluginLine = $null
if ($gatewayInspectAvailable) {
    $startedAt = $inspect[0].State.StartedAt
    $gatewayLogs = docker logs --since $startedAt openclaw-gateway-secure 2>&1
    $gatewayLogText = ($gatewayLogs -join "`n")
    $latestReadyPluginLine = @($gatewayLogs | Where-Object { $_ -match "ready \(\d+ plugins:" } | Select-Object -Last 1)
}

foreach ($plugin in $localOnlyDisabledPlugins) {
    $enabled = Get-PluginEnabledValue -Config $effectiveConfig -Plugin $plugin
    if ($enabled -eq $true) {
        Add-Fail "Local-only profile plugin '$plugin' is enabled in effective config."
    } elseif ($enabled -eq $false) {
        Add-Pass "Local-only profile plugin '$plugin' is explicitly disabled."
    } else {
        Add-Warn "Local-only profile plugin '$plugin' is not explicitly present in effective config."
    }

    if ($latestReadyPluginLine -and $latestReadyPluginLine -match ("(?i)\b" + [regex]::Escape($plugin) + "\b")) {
        Add-Fail "Local-only profile plugin '$plugin' appears in the latest gateway ready plugin list."
    }
}
if (-not $gatewayInspectAvailable) {
    Add-Warn "Gateway logs were not inspected because the gateway container is not present."
} elseif (-not $latestReadyPluginLine) {
    Add-Warn "No gateway ready plugin list was found in current container logs."
}

if (Test-Path $pairedDevicesPath) {
    try {
        $pairedRaw = (Get-Content -Raw -Path $pairedDevicesPath).Trim()
        if ($pairedRaw -and $pairedRaw -ne "{}" -and $pairedRaw -ne "[]") {
            $pairedCount = Get-JsonCollectionCount -Value ($pairedRaw | ConvertFrom-Json)
            if ($pairedCount -gt 0) {
                Add-Warn "Found $pairedCount paired device record(s). Local-only plugin disabling should make these inert; clear runtime\config\devices\paired.json deliberately if they are no longer needed."
            } else {
                Add-Pass "No paired device records are present."
            }
        } else {
            Add-Pass "No paired device records are present."
        }
    } catch {
        Add-Warn "Paired device file exists but could not be parsed."
    }
} else {
    Add-Pass "No paired device file is present."
}

if ($UseSandboxOverlay) {
    Add-Line ""
    Add-Line "## Sandbox Docker Daemon Controls"
    Add-Line ""
    $sandboxInspectRaw = docker inspect openclaw-sandbox-docker 2>$null
    if ($LASTEXITCODE -eq 0 -and $sandboxInspectRaw) {
        $sandboxInspect = $sandboxInspectRaw | ConvertFrom-Json
        $sandbox = $sandboxInspect[0]
        $sandboxHostConfig = $sandbox.HostConfig
        $sandboxEnv = @($sandbox.Config.Env)
        $sandboxArgs = @($sandbox.Args)
        $sandboxMounts = @($sandbox.Mounts)
        $sandboxNetworks = @($sandbox.NetworkSettings.Networks.PSObject.Properties.Name)
        $sandboxPortBindings = $sandboxHostConfig.PortBindings
        $hasHostPortBinding = $false
        if ($sandboxPortBindings) {
            foreach ($binding in $sandboxPortBindings.PSObject.Properties) {
                if ($binding.Value) { $hasHostPortBinding = $true }
            }
        }
        $usesInsecure2375 = (($sandboxArgs -join " ") -match "2375") -or (Test-EnvValue -Env $sandboxEnv -Name "DOCKER_TLS_CERTDIR" -Value "")
        $hasTlsCertDir = Test-EnvValue -Env $sandboxEnv -Name "DOCKER_TLS_CERTDIR" -Value "/certs"
        $hasClientCertMount = $false
        foreach ($mount in $sandboxMounts) {
            if ($mount.Destination -eq "/certs/client") { $hasClientCertMount = $true }
        }
        $attachedToSharedNetwork = $false
        foreach ($network in $sandboxNetworks) {
            if ($network -match "openclaw_internal$") { $attachedToSharedNetwork = $true }
        }
        $attachedToControlNetwork = $false
        foreach ($network in $sandboxNetworks) {
            if ($network -match "openclaw_sandbox_control$") { $attachedToControlNetwork = $true }
        }

        Add-Line "- Command args: $($sandboxArgs -join ' ')"
        Add-Line "- DOCKER_TLS_CERTDIR=/certs: $hasTlsCertDir"
        Add-Line "- Client cert volume mounted: $hasClientCertMount"
        Add-Line "- Host port bindings: $($sandboxPortBindings | ConvertTo-Json -Compress)"
        Add-Line "- Networks: $($sandboxNetworks -join ', ')"

        if ($usesInsecure2375) {
            Add-Fail "Sandbox Docker daemon is configured for unauthenticated 2375 access."
        } else {
            Add-Pass "Sandbox Docker daemon is not configured for unauthenticated 2375 access."
        }
        if ($hasTlsCertDir -and $hasClientCertMount) {
            Add-Pass "Sandbox Docker daemon has TLS cert generation and client cert sharing configured."
        } else {
            Add-Fail "Sandbox Docker daemon is missing TLS cert generation or the client cert mount."
        }
        if ($hasHostPortBinding) {
            Add-Fail "Sandbox Docker daemon has host port bindings."
        } else {
            Add-Pass "Sandbox Docker daemon has no host port bindings."
        }
        if ($attachedToSharedNetwork) {
            Add-Fail "Sandbox Docker daemon is attached to the shared openclaw_internal network."
        } else {
            Add-Pass "Sandbox Docker daemon is not attached to the shared openclaw_internal network."
        }
        if ($attachedToControlNetwork) {
            Add-Pass "Sandbox Docker daemon is attached to the private control network."
        } else {
            Add-Fail "Sandbox Docker daemon is not attached to the private control network."
        }

        $probe2375 = docker compose @composeArgs run --rm --entrypoint sh openclaw-cli -c "DOCKER_TLS_VERIFY= DOCKER_CERT_PATH= docker -H tcp://docker:2375 version" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Fail "Unauthenticated Docker API on tcp://docker:2375 is reachable from the gateway network."
        } else {
            Add-Pass "Unauthenticated Docker API on tcp://docker:2375 is not reachable from the gateway network."
        }
    } else {
        Add-Line "- WARN: Sandbox Docker daemon container is not present; start it before runtime inspection."
    }

    Add-Line ""
    Add-Line "## Gateway Sandbox Docker Client"
    Add-Line ""
    if ($gatewayInspectAvailable) {
        $gatewayEnv = @($inspect[0].Config.Env)
        $gatewayMounts = @($inspect[0].Mounts)
        $gatewayUsesTls = (Test-EnvValue -Env $gatewayEnv -Name "DOCKER_HOST" -Value "tcp://docker:2376") -and
            (Test-EnvValue -Env $gatewayEnv -Name "DOCKER_TLS_VERIFY" -Value "1") -and
            (Test-EnvValue -Env $gatewayEnv -Name "DOCKER_CERT_PATH" -Value "/certs/client")
        $gatewayHasReadOnlyCertMount = $false
        foreach ($mount in $gatewayMounts) {
            if ($mount.Destination -eq "/certs/client" -and $mount.RW -eq $false) {
                $gatewayHasReadOnlyCertMount = $true
            }
        }
        if ($gatewayUsesTls -and $gatewayHasReadOnlyCertMount) {
            Add-Pass "Gateway Docker client uses TLS on 2376 with read-only client certs."
        } else {
            Add-Fail "Gateway Docker client is not fully configured for TLS on 2376."
        }
        $probe2376 = docker compose @composeArgs run --rm --entrypoint docker openclaw-cli info 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Pass "Gateway Docker client can reach the sandbox daemon over authenticated TLS on 2376."
        } else {
            Add-Fail "Gateway Docker client could not reach the sandbox daemon over authenticated TLS on 2376."
        }
    } else {
        Add-Line "- WARN: Gateway container is not present; cannot inspect Docker client TLS settings."
    }
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
    Add-Pass "Authenticated health command succeeded."
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
if ($image -match "@sha256:") {
    Add-Pass "OPENCLAW_IMAGE is pinned by digest."
} elseif ($image -match ":latest$") {
    Add-Warn "OPENCLAW_IMAGE uses a moving latest tag; pin to a reviewed tag or digest for repeatable deployments."
} else {
    Add-Pass "OPENCLAW_IMAGE is set to an explicit non-latest tag."
}

$scoutVersion = docker scout version 2>$null
if ($LASTEXITCODE -eq 0) {
    $scanResult = Invoke-NativeWithTimeout -FilePath "docker" -Arguments @("scout", "cves", "--platform", "linux/amd64", "--only-severity", "critical,high", $image) -TimeoutSeconds $ScanTimeoutSeconds
    Add-Line "- Docker Scout scan attempted for ``$image`` with timeout ${ScanTimeoutSeconds}s."
    if (-not $scanResult.Completed) {
        Add-Warn "Docker Scout scan timed out after ${ScanTimeoutSeconds}s; rerun with a larger -ScanTimeoutSeconds value or scan manually."
    }
    Add-Line '```text'
    Add-Line ($scanResult.Output -join "`n")
    Add-Line '```'
} elseif (Get-Command trivy -ErrorAction SilentlyContinue) {
    $scanResult = Invoke-NativeWithTimeout -FilePath "trivy" -Arguments @("image", "--severity", "CRITICAL,HIGH", $image) -TimeoutSeconds $ScanTimeoutSeconds
    Add-Line "- Trivy scan attempted for ``$image`` with timeout ${ScanTimeoutSeconds}s."
    if (-not $scanResult.Completed) {
        Add-Warn "Trivy scan timed out after ${ScanTimeoutSeconds}s; rerun with a larger -ScanTimeoutSeconds value or scan manually."
    }
    Add-Line '```text'
    Add-Line ($scanResult.Output -join "`n")
    Add-Line '```'
} else {
    Add-Line "- WARN: No supported local scanner found. Install Docker Scout or Trivy for CVE audit coverage."
}

Set-Content -Path $reportPath -Value $lines -Encoding ascii
Write-Host "Audit report written to $reportPath"
if ($failureCount -gt 0) {
    Write-Host "Audit completed with $failureCount failure(s)." -ForegroundColor Red
    exit 1
}
