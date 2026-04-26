param(
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [ValidateSet("open", "closed", "dismissed", "fixed")]
    [string]$State = "open",
    [string]$PolicyPath,
    [string]$TrivyJsonPath,
    [string]$TrivySarifPath,
    [string]$PSScriptAnalyzerSarifPath,
    [string]$OutputMarkdown,
    [string]$OutputJson,
    [switch]$SkipGitHub
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $PolicyPath) {
    $PolicyPath = Join-Path $Root "security\triage-policy.json"
}
if (-not $OutputMarkdown) {
    $OutputMarkdown = Join-Path $Root "reports\security-triage.md"
}
if (-not $OutputJson) {
    $OutputJson = Join-Path $Root "reports\security-triage.json"
}

function ConvertTo-AbsolutePath {
    param([string]$Path)
    if (-not $Path) { return $null }
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return Join-Path $Root $Path
}

function Read-JsonFile {
    param([string]$Path)
    $resolved = ConvertTo-AbsolutePath -Path $Path
    if (-not $resolved -or -not (Test-Path $resolved)) { return $null }
    return Get-Content -Raw -Path $resolved | ConvertFrom-Json
}

function Get-RegexValue {
    param(
        [string]$Text,
        [string]$Pattern
    )
    if (-not $Text) { return "" }
    $match = [regex]::Match($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if (-not $match.Success) { return "" }
    return $match.Groups[1].Value.Trim()
}

function Test-StringPattern {
    param(
        [string]$Value,
        [object[]]$Patterns
    )
    if (-not $Value -or -not $Patterns) { return $false }
    foreach ($pattern in $Patterns) {
        if ($Value -like [string]$pattern) { return $true }
    }
    return $false
}

function Group-Count {
    param(
        [object[]]$Items,
        [scriptblock]$Key
    )
    return @($Items |
        Group-Object $Key |
        Sort-Object -Property Count, Name -Descending |
        ForEach-Object {
            [ordered]@{
                name = if ($_.Name) { $_.Name } else { "(none)" }
                count = $_.Count
            }
        })
}

function Get-CodeScanningAlerts {
    param(
        [string]$Repo,
        [string]$AlertState
    )

    if (-not $Repo) {
        throw "Repository was not provided and GITHUB_REPOSITORY is not set."
    }
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI is not installed or is not on PATH."
    }

    $endpoint = "repos/$Repo/code-scanning/alerts?state=$AlertState&per_page=100"
    $raw = & gh api --paginate --slurp $endpoint
    if ($LASTEXITCODE -ne 0) {
        throw "gh api failed while reading code scanning alerts."
    }

    $pages = $raw | ConvertFrom-Json
    $alerts = @()
    foreach ($page in @($pages)) {
        $alerts += @($page)
    }
    return $alerts
}

function Convert-Alert {
    param(
        [object]$Alert,
        [object]$Policy
    )

    $instance = $Alert.most_recent_instance
    $message = [string]$instance.message.text
    $fixedVersion = Get-RegexValue -Text $message -Pattern "Fixed Version:[ \t]*([^\r\n]*)"
    $package = Get-RegexValue -Text $message -Pattern "Package:[ \t]*([^\r\n]+)"
    $installed = Get-RegexValue -Text $message -Pattern "Installed Version:[ \t]*([^\r\n]+)"
    $tool = [string]$Alert.tool.name
    $ruleId = [string]$Alert.rule.id
    $severity = [string]$Alert.rule.security_severity_level
    if (-not $severity) { $severity = [string]$Alert.rule.severity }
    $path = [string]$instance.location.path
    $hasFixedVersion = -not [string]::IsNullOrWhiteSpace($fixedVersion)
    $category = "monitor"
    $likelyAction = "Review exposure and keep tracking."

    if ($tool -eq "PSScriptAnalyzer") {
        if ($Policy.psscriptanalyzer.risk_rules -contains $ruleId) {
            $category = "monitor"
            $likelyAction = "Review as a script-risk finding."
        } else {
            $category = "hygiene"
            $likelyAction = "Treat as script hygiene unless it blocks maintainability."
        }
    } elseif ($hasFixedVersion -and (@("critical", "high") -contains $severity.ToLowerInvariant())) {
        $category = "fix_now"
        $likelyAction = "Fixed version is available; evaluate image or dependency update."
    } elseif (Test-StringPattern -Value $path -Patterns @($Policy.matchers.upstream_path_patterns)) {
        $category = "upstream"
        $likelyAction = "Inherited from the upstream/base image; monitor for upstream rebuild or pin change."
    } elseif (-not $hasFixedVersion -and (@("critical", "high") -contains $severity.ToLowerInvariant())) {
        $category = "monitor"
        $likelyAction = "No fixed version was reported; monitor vendor and upstream image state."
    }

    return [ordered]@{
        number = $Alert.number
        html_url = $Alert.html_url
        state = $Alert.state
        tool = $tool
        rule_id = $ruleId
        rule_name = $Alert.rule.name
        severity = $severity
        security_severity = $Alert.rule.security_severity_level
        category = $category
        likely_action = $likelyAction
        package = $package
        installed_version = $installed
        fixed_version = $fixedVersion
        has_fixed_version = $hasFixedVersion
        path = $path
        start_line = $instance.location.start_line
        commit_sha = $instance.commit_sha
        message = $message
    }
}

function Get-TrivyJsonSummary {
    param([string]$Path)
    $scan = Read-JsonFile -Path $Path
    if (-not $scan) { return $null }

    $vulnerabilities = @()
    foreach ($result in @($scan.Results)) {
        foreach ($vuln in @($result.Vulnerabilities)) {
            if (-not $vuln) { continue }
            $vulnerabilities += [ordered]@{
                id = $vuln.VulnerabilityID
                package = $vuln.PkgName
                installed_version = $vuln.InstalledVersion
                fixed_version = $vuln.FixedVersion
                severity = $vuln.Severity
                target = $result.Target
                type = $result.Type
            }
        }
    }

    return [ordered]@{
        path = $Path
        count = $vulnerabilities.Count
        with_fixed_version = @($vulnerabilities | Where-Object { -not [string]::IsNullOrWhiteSpace($_.fixed_version) }).Count
        by_severity = Group-Count -Items $vulnerabilities -Key { $_.severity }
        top_packages = @(Group-Count -Items $vulnerabilities -Key { $_.package } | Select-Object -First 20)
    }
}

function Get-SarifSummary {
    param(
        [string]$Path,
        [string]$Name
    )
    $sarif = Read-JsonFile -Path $Path
    if (-not $sarif) { return $null }

    $results = @()
    foreach ($run in @($sarif.runs)) {
        $toolName = $run.tool.driver.name
        foreach ($result in @($run.results)) {
            if (-not $result) { continue }
            $location = @($result.locations)[0]
            $artifactUri = $null
            if ($location) {
                $artifactUri = $location.physicalLocation.artifactLocation.uri
            }
            $results += [ordered]@{
                tool = $toolName
                rule_id = $result.ruleId
                level = $result.level
                path = $artifactUri
                message = $result.message.text
            }
        }
    }

    return [ordered]@{
        name = $Name
        path = $Path
        count = $results.Count
        by_rule = @(Group-Count -Items $results -Key { $_.rule_id } | Select-Object -First 30)
        by_path = @(Group-Count -Items $results -Key { $_.path } | Select-Object -First 30)
    }
}

$policy = Read-JsonFile -Path $PolicyPath
if (-not $policy) {
    throw "Triage policy was not found at $PolicyPath."
}

$githubSource = [ordered]@{
    attempted = -not $SkipGitHub
    succeeded = $false
    error = $null
}
$rawAlerts = @()
if (-not $SkipGitHub) {
    try {
        $rawAlerts = @(Get-CodeScanningAlerts -Repo $Repository -AlertState $State)
        $githubSource.succeeded = $true
    } catch {
        $githubSource.error = $_.Exception.Message
        Write-Warning $githubSource.error
    }
}

$alerts = @()
foreach ($alert in $rawAlerts) {
    $alerts += Convert-Alert -Alert $alert -Policy $policy
}

$summary = [ordered]@{
    total_alerts = $alerts.Count
    by_tool = Group-Count -Items $alerts -Key { $_.tool }
    by_category = Group-Count -Items $alerts -Key { $_.category }
    by_severity = Group-Count -Items $alerts -Key { $_.severity }
    top_packages = @(Group-Count -Items ($alerts | Where-Object { $_.package }) -Key { $_.package } | Select-Object -First 20)
    top_paths = @(Group-Count -Items $alerts -Key { $_.path } | Select-Object -First 20)
    fixed_version_alerts = @($alerts | Where-Object { $_.has_fixed_version }).Count
}

$localScans = [ordered]@{
    trivy_json = Get-TrivyJsonSummary -Path $TrivyJsonPath
    trivy_sarif = Get-SarifSummary -Path $TrivySarifPath -Name "Trivy SARIF"
    psscriptanalyzer_sarif = Get-SarifSummary -Path $PSScriptAnalyzerSarifPath -Name "PSScriptAnalyzer SARIF"
}

$result = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    repository = $Repository
    state = $State
    enforcement = $policy.enforcement
    github_source = $githubSource
    summary = $summary
    categories = $policy.categories
    local_scans = $localScans
    alerts = $alerts
}

$markdown = New-Object System.Collections.Generic.List[string]
function Add-Markdown {
    param([string]$Line = "")
    $markdown.Add($Line) | Out-Null
}
function Add-Table {
    param(
        [string[]]$Headers,
        [object[]]$Rows
    )
    Add-Markdown ("| " + ($Headers -join " | ") + " |")
    Add-Markdown ("| " + (($Headers | ForEach-Object { "---" }) -join " | ") + " |")
    foreach ($row in @($Rows)) {
        $values = foreach ($header in $Headers) {
            $value = $row[$header]
            if ($null -eq $value -or $value -eq "") { "-" } else { ([string]$value).Replace("|", "\|") }
        }
        Add-Markdown ("| " + ($values -join " | ") + " |")
    }
    if (-not $Rows -or $Rows.Count -eq 0) {
        Add-Markdown ("| " + (($Headers | ForEach-Object { "-" }) -join " | ") + " |")
    }
}

Add-Markdown "# Security Triage Report"
Add-Markdown ""
Add-Markdown "- Generated: $($result.generated_at)"
Add-Markdown "- Repository: $Repository"
Add-Markdown "- Alert state: $State"
Add-Markdown "- Enforcement: $($policy.enforcement)"
if ($githubSource.succeeded) {
    Add-Markdown "- GitHub code scanning alerts: read successfully"
} elseif ($githubSource.attempted) {
    Add-Markdown "- GitHub code scanning alerts: unavailable ($($githubSource.error))"
} else {
    Add-Markdown "- GitHub code scanning alerts: skipped"
}
Add-Markdown ""
Add-Markdown "## Summary"
Add-Markdown ""
Add-Markdown "- Total GitHub alerts: $($summary.total_alerts)"
Add-Markdown "- Alerts with fixed versions: $($summary.fixed_version_alerts)"
Add-Markdown ""
Add-Table -Headers @("name", "count") -Rows $summary.by_tool
Add-Markdown ""
Add-Table -Headers @("name", "count") -Rows $summary.by_category
Add-Markdown ""
Add-Markdown "## Top Packages"
Add-Markdown ""
Add-Table -Headers @("name", "count") -Rows $summary.top_packages
Add-Markdown ""
Add-Markdown "## Top Paths"
Add-Markdown ""
Add-Table -Headers @("name", "count") -Rows $summary.top_paths
Add-Markdown ""
Add-Markdown "## Fix-Now Alerts"
Add-Markdown ""
$fixRows = @($alerts | Where-Object { $_.category -eq "fix_now" } | Select-Object -First 25 | ForEach-Object {
    [ordered]@{
        number = $_.number
        severity = $_.severity
        package = $_.package
        installed = $_.installed_version
        fixed = $_.fixed_version
        path = $_.path
    }
})
Add-Table -Headers @("number", "severity", "package", "installed", "fixed", "path") -Rows $fixRows
Add-Markdown ""
Add-Markdown "## PSScriptAnalyzer Rules"
Add-Markdown ""
$psRows = @($alerts | Where-Object { $_.tool -eq "PSScriptAnalyzer" } | Group-Object { $_.rule_id } | Sort-Object -Property Count, Name -Descending | ForEach-Object {
    [ordered]@{ rule = $_.Name; count = $_.Count }
})
Add-Table -Headers @("rule", "count") -Rows $psRows
Add-Markdown ""
Add-Markdown "## Local Scan Artifacts"
Add-Markdown ""
if ($localScans.trivy_json) {
    Add-Markdown "- Trivy JSON findings: $($localScans.trivy_json.count)"
    Add-Markdown "- Trivy JSON findings with fixed versions: $($localScans.trivy_json.with_fixed_version)"
} else {
    Add-Markdown "- Trivy JSON findings: not provided"
}
if ($localScans.trivy_sarif) {
    Add-Markdown "- Trivy SARIF findings: $($localScans.trivy_sarif.count)"
} else {
    Add-Markdown "- Trivy SARIF findings: not provided"
}
if ($localScans.psscriptanalyzer_sarif) {
    Add-Markdown "- PSScriptAnalyzer SARIF findings: $($localScans.psscriptanalyzer_sarif.count)"
} else {
    Add-Markdown "- PSScriptAnalyzer SARIF findings: not provided"
}
Add-Markdown ""
Add-Markdown "Report-only mode does not fail CI, dismiss alerts, or suppress Security tab findings."

$markdownPath = ConvertTo-AbsolutePath -Path $OutputMarkdown
$jsonPath = ConvertTo-AbsolutePath -Path $OutputJson
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $markdownPath) | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $jsonPath) | Out-Null

Set-Content -Path $markdownPath -Value $markdown -Encoding ascii
Set-Content -Path $jsonPath -Value ($result | ConvertTo-Json -Depth 20) -Encoding ascii

Write-Output "Security triage report written to $markdownPath"
Write-Output "Security triage JSON written to $jsonPath"
