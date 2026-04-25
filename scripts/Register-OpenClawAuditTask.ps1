param(
    [string]$TaskName = "OpenClaw Secure Audit",
    [string]$At = "03:30",
    [switch]$UseSandboxOverlay
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$AuditScript = Join-Path $PSScriptRoot "Audit-OpenClawSecure.ps1"
$PowerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source

$args = "-NoProfile -ExecutionPolicy Bypass -File `"$AuditScript`""
if ($UseSandboxOverlay) {
    $args += " -UseSandboxOverlay"
}

$action = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $args -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Daily -At ([DateTime]::Parse($At))
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Runs the OpenClaw secure deployment audit and writes reports locally." -Force | Out-Null
Write-Host "Registered scheduled audit task '$TaskName' for daily execution at $At."

