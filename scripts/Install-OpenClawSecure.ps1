param(
    [switch]$WithSandbox,
    [switch]$NoStart,
    [switch]$SkipPull
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$EnvPath = Join-Path $Root ".env"
$EnvExamplePath = Join-Path $Root ".env.example"
$ComposePath = Join-Path $Root "compose.yaml"
$SandboxComposePath = Join-Path $Root "compose.sandbox-dind.yaml"

& (Join-Path $PSScriptRoot "Test-OpenClawPrereqs.ps1")

New-Item -ItemType Directory -Force -Path (Join-Path $Root "runtime\config") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "runtime\workspace") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "runtime\codex") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "reports") | Out-Null

function New-HexToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

if (-not (Test-Path $EnvPath)) {
    $token = New-HexToken
    $envText = Get-Content -Raw -Path $EnvExamplePath
    $envText = $envText.Replace("replace-with-64-hex-chars", $token)
    Set-Content -Path $EnvPath -Value $envText -Encoding ascii
    Write-Host "Created .env with a generated gateway token."
} else {
    Write-Host ".env already exists; leaving it unchanged."
}

$composeArgs = @("-f", $ComposePath)

if ($WithSandbox) {
    Write-Host "Building OpenClaw gateway image with Docker CLI for sandbox orchestration."
    docker build -f (Join-Path $Root "Dockerfile.gateway") -t openclaw-gateway-secure:latest $Root
    if ($LASTEXITCODE -ne 0) { throw "Gateway image build failed." }
    $composeArgs += @("-f", $SandboxComposePath)
}

docker compose @composeArgs config 1>$null
if ($LASTEXITCODE -ne 0) { throw "Compose validation failed." }

if (-not $SkipPull) {
    if ($WithSandbox) {
        docker compose @composeArgs pull openclaw-sandbox-docker
    } else {
        docker compose @composeArgs pull openclaw-gateway
    }
    if ($LASTEXITCODE -ne 0) { throw "Image pull failed." }
}

if (-not $NoStart) {
    docker compose @composeArgs up -d openclaw-gateway
    if ($LASTEXITCODE -ne 0) { throw "OpenClaw gateway start failed." }
    Write-Host "OpenClaw gateway started at http://127.0.0.1:18789/"
    Write-Host "Run scripts\Apply-OpenClawSecureConfig.ps1 after onboarding to enforce the secure policy."
} else {
    Write-Host "Install assets are ready. Start later with:"
    if ($WithSandbox) {
        Write-Host "docker compose -f compose.yaml -f compose.sandbox-dind.yaml up -d openclaw-gateway"
    } else {
        Write-Host "docker compose -f compose.yaml up -d openclaw-gateway"
    }
}
