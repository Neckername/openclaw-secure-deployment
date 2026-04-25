param(
    [switch]$AllowMessaging,
    [switch]$UseSandboxOverlay
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ComposeArgs = @("-f", (Join-Path $Root "compose.yaml"))
if ($UseSandboxOverlay) {
    $ComposeArgs += @("-f", (Join-Path $Root "compose.sandbox-dind.yaml"))
}

$deny = @("group:automation", "group:nodes")
$sandboxDeny = @("gateway", "cron", "nodes")
if (-not $AllowMessaging) {
    $deny += "group:messaging"
    $sandboxDeny += "message"
}

$batch = @(
    @{ path = "plugins.entries.codex.enabled"; value = $true },
    @{ path = "agents.defaults.model"; value = "codex/gpt-5.4" },
    @{ path = "agents.defaults.embeddedHarness.runtime"; value = "codex" },
    @{ path = "agents.defaults.embeddedHarness.fallback"; value = "none" },
    @{ path = "agents.defaults.sandbox.mode"; value = "all" },
    @{ path = "agents.defaults.sandbox.backend"; value = "docker" },
    @{ path = "agents.defaults.sandbox.scope"; value = "session" },
    @{ path = "agents.defaults.sandbox.workspaceAccess"; value = "none" },
    @{ path = "agents.defaults.sandbox.docker.network"; value = "none" },
    @{ path = "tools.profile"; value = "coding" },
    @{ path = "tools.deny"; value = $deny },
    @{ path = "tools.sandbox.tools.allow"; value = @("group:runtime", "group:fs", "group:web", "group:sessions", "group:memory", "group:ui", "group:media") },
    @{ path = "tools.sandbox.tools.deny"; value = $sandboxDeny },
    @{ path = "tools.elevated.enabled"; value = $false },
    @{ path = "commands.plugins"; value = $false }
)

$batchPath = Join-Path $Root "runtime\config\config-set.batch.json"
$batch | ConvertTo-Json -Depth 8 | Set-Content -Path $batchPath -Encoding ascii

docker compose @ComposeArgs run --rm openclaw-cli config set --batch-file /home/node/.openclaw/config-set.batch.json
if ($LASTEXITCODE -ne 0) { throw "OpenClaw config update failed." }

Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue

docker compose @ComposeArgs restart openclaw-gateway
if ($LASTEXITCODE -ne 0) { throw "OpenClaw gateway restart failed." }

Write-Host "Secure OpenClaw policy applied and gateway restarted."
Write-Host "Verify sandbox behavior with: docker compose $($ComposeArgs -join ' ') run --rm openclaw-cli sandbox explain --json"
