<#
================================================================================
 Repo Health Checker (PowerShell Module)
================================================================================

GOAL:
    Provide an automated, repeatable way to evaluate the overall health of a 
    GitHub repository by analyzing structure, documentation, automation, and 
    security hygiene. The module produces a weighted score, category breakdown, 
    and optional HTML report suitable for CI pipelines or manual reviews.

AUTHOR:
    Scott M

AUDIENCE:
    • Security engineers
    • Automation engineers
    • DevOps practitioners
    • Developers maintaining multiple repositories
    • Anyone performing repo audits or enforcing engineering standards

REQUIREMENTS:
    • PowerShell 7.x recommended
    • Local clone of the repository to analyze
    • No external modules required (v1)
    • Optional: GitHub Actions runner for CI integration

INSTRUCTIONS:
    1. Import the module:
           Import-Module ./RepoHealthChecker.psm1 -Force

    2. Run a health check:
           Invoke-RhcRepoHealthCheck -Path "C:\Repo"

    3. Generate an HTML report:
           Invoke-RhcRepoHealthCheck -Path "C:\Repo" `
                                     -HtmlReportPath "C:\Repo\reports\health.html"

    4. Review the output:
           • Console summary
           • Detailed object with all checks
           • Optional HTML report

SCORING MODEL:
    Structure      – 25%
    Security       – 30%
    Documentation  – 20%
    Automation     – 25%

    Each check is scored as:
        Pass = 2 points
        Warn = 1 point
        Fail = 0 points

CHANGELOG:
    v1.0.0 – Initial release
        • Repo structure checks
        • Documentation quality checks
        • Automation (GitHub Actions) checks
        • Local heuristic security scan
        • Weighted scoring engine
        • HTML report generator
        • CI workflow for self‑evaluation

================================================================================
#>

function Get-RhcRepoInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Path '$Path' does not exist."
    }

    $repoRoot = Resolve-Path $Path
    $files = Get-ChildItem -Path $repoRoot -Recurse -File | Select-Object -ExpandProperty FullName

    [pscustomobject]@{
        RepoRoot = $repoRoot
        Files    = $files
    }
}

function Test-RhcRepoStructure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$RepoInfo)

    $root = $RepoInfo.RepoRoot
    $files = $RepoInfo.Files
    $checks = @()

    $structureChecks = @(
        @{ Name='README.md';       Type='File';   Required=$true  }
        @{ Name='LICENSE';         Type='File';   Required=$true  }
        @{ Name='.gitignore';      Type='File';   Required=$false }
        @{ Name='CHANGELOG.md';    Type='File';   Required=$false }
        @{ Name='CONTRIBUTING.md'; Type='File';   Required=$false }
        @{ Name='CODEOWNERS';      Type='File';   Required=$false }
        @{ Name='docs';            Type='Folder'; Required=$false }
        @{ Name='tests';           Type='Folder'; Required=$false }
    )

    foreach ($check in $structureChecks) {
        $exists = switch ($check.Type) {
            'File'   { $files -match [regex]::Escape($check.Name) }
            'Folder' { Test-Path (Join-Path $root $check.Name) }
        }

        if (-not $exists) {
            $status = if ($check.Required) { 'Fail' } else { 'Warn' }
            $note   = if ($check.Required) { "Required $($check.Type) missing." } else { "Optional $($check.Type) missing." }
        }
        else {
            $status = 'Pass'
            $note   = "$($check.Type) found."
        }

        $checks += [pscustomobject]@{
            Category='Structure'
            Item=$check.Name
            Status=$status
            Notes=$note
        }
    }

    $checks
}

function Test-RhcRepoDocumentation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$RepoInfo)

    $root = $RepoInfo.RepoRoot
    $readmePath = Join-Path $root 'README.md'
    $checks = @()

    if (-not (Test-Path $readmePath)) {
        return @([pscustomobject]@{
            Category='Documentation'
            Item='README.md'
            Status='Fail'
            Notes='README.md missing.'
        })
    }

    $content = Get-Content -Path $readmePath -Raw
    $lines = ($content -split "`n").Count

    $checks += [pscustomobject]@{
        Category='Documentation'
        Item='README length'
        Status=if ($lines -ge 20) { 'Pass' } else { 'Warn' }
        Notes="README has $lines lines."
    }

    $sections = @{
        'Description'  = 'description|overview|about'
        'Installation' = 'install|getting started'
        'Usage'        = 'usage|examples'
        'License'      = 'license'
    }

    foreach ($section in $sections.GetEnumerator()) {
        $found = $content -match "(?im)^.*$($section.Value).*"
        $checks += [pscustomobject]@{
            Category='Documentation'
            Item=$section.Key
            Status=if ($found) { 'Pass' } else { 'Warn' }
            Notes=if ($found) { "$($section.Key) section found." } else { "$($section.Key) section missing." }
        }
    }

    $checks
}

function Test-RhcRepoAutomation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$RepoInfo)

    $root = $RepoInfo.RepoRoot
    $workflowPath = Join-Path $root '.github\workflows'
    $checks = @()

    if (-not (Test-Path $workflowPath)) {
        return @([pscustomobject]@{
            Category='Automation'
            Item='GitHub Actions'
            Status='Warn'
            Notes='No workflows directory.'
        })
    }

    $workflows = Get-ChildItem -Path $workflowPath -Filter '*.yml' -File

    $checks += [pscustomobject]@{
        Category='Automation'
        Item='GitHub Actions'
        Status=if ($workflows) { 'Pass' } else { 'Warn' }
        Notes=if ($workflows) { "$($workflows.Count) workflow(s) found." } else { "Workflows directory empty." }
    }

    $checks
}

function Test-RhcRepoSecurity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$RepoInfo)

    $files = $RepoInfo.Files
    $checks = @()

    $patterns = @('password\s*=', 'apikey', 'api_key', 'secret\s*=', 'connectionstring')
    $suspectFiles = $files | Where-Object { $_ -match '\.(json|yml|config|env)$' }

    $hits = @()

    foreach ($file in $suspectFiles) {
        try { $content = Get-Content $file } catch { continue }

        foreach ($line in $content) {
            foreach ($pattern in $patterns) {
                if ($line -match $pattern) {
                    $hits += [pscustomobject]@{
                        File=$file
                        Pattern=$pattern
                        Line=$line.Trim()
                    }
                }
            }
        }
    }

    if ($hits) {
        $checks += [pscustomobject]@{
            Category='Security'
            Item='Potential secrets'
            Status='Warn'
            Notes="Potential secrets detected in $($hits.File | Select-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count) file(s)."
            Details=$hits
        }
    }
    else {
        $checks += [pscustomobject]@{
            Category='Security'
            Item='Potential secrets'
            Status='Pass'
            Notes='No obvious secrets detected.'
        }
    }

    $checks
}

function Get-RhcRepoHealthScore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject[]]$Checks)

    $weights = @{
        Structure=0.25
        Security=0.30
        Documentation=0.20
        Automation=0.25
    }

    $categoryScores = @{}

    foreach ($category in $weights.Keys) {
        $catChecks = $Checks | Where-Object { $_.Category -eq $category }
        if (-not $catChecks) { $categoryScores[$category] = 0; continue }

        $max = $catChecks.Count * 2
        $score = ($catChecks | ForEach-Object {
            switch ($_.Status) {
                'Pass' { 2 }
                'Warn' { 1 }
                default { 0 }
            }
        } | Measure-Object -Sum).Sum

        $categoryScores[$category] = [math]::Round(($score / $max) * 100, 2)
    }

    $total = 0
    foreach ($category in $weights.Keys) {
        $total += $categoryScores[$category] * $weights[$category]
    }

    $letter = switch ($total) {
        {$_ -ge 90} { 'A' }
        {$_ -ge 80} { 'B' }
        {$_ -ge 70} { 'C' }
        {$_ -ge 60} { 'D' }
        default     { 'F' }
    }

    [pscustomobject]@{
        TotalScore=[math]::Round($total, 2)
        LetterGrade=$letter
        CategoryScores=$categoryScores
    }
}

function Export-RhcHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject[]]$Checks,
        [Parameter(Mandatory)][pscustomobject]$Score,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$Title='GitHub Repo Health Report'
    )

    $rows = $Checks | ForEach-Object {
        $color = switch ($_.Status) {
            'Pass' { '#2e7d32' }
            'Warn' { '#f9a825' }
            'Fail' { '#c62828' }
            default { '#424242' }
        }

        "<tr><td>$($_.Category)</td><td>$($_.Item)</td><td style='color:$color;font-weight:bold;'>$($_.Status)</td><td>$($_.Notes)</td></tr>"
    }

    $categoryRows = $Score.CategoryScores.GetEnumerator() | ForEach-Object {
        "<tr><td>$($_.Key)</td><td>$($_.Value)%</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>$Title</title>
<style>
body { font-family: Segoe UI, sans-serif; margin: 20px; background: #fafafa; }
h1, h2 { color: #263238; }
.summary { padding: 10px; background: #eceff1; border-radius: 4px; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
th, td { border: 1px solid #cfd8dc; padding: 8px; }
th { background: #eceff1; }
.score { font-size: 1.4em; font-weight: bold; }
</style>
</head>
<body>
<h1>$Title</h1>
<div class="summary">
    <div class="score">Overall Score: $($Score.TotalScore)% ($($Score.LetterGrade))</div>
</div>

<h2>Category Scores</h2>
<table>
<thead><tr><th>Category</th><th>Score</th></tr></thead>
<tbody>$($categoryRows -join "`n")</tbody>
</table>

<h2>Checks</h2>
<table>
<thead><tr><th>Category</th><th>Item</th><th>Status</th><th>Notes</th></tr></thead>
<tbody>$($rows -join "`n")</tbody>
</table>
</body>
</html>
"@

    $dir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory | Out-Null }

    $html | Set-Content -Path $OutputPath -Encoding UTF8
}

function Invoke-RhcRepoHealthCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$HtmlReportPath
    )

    $repoInfo = Get-RhcRepoInfo -Path $Path

    $checks = @()
    $checks += Test-RhcRepoStructure     -RepoInfo $repoInfo
    $checks += Test-RhcRepoDocumentation -RepoInfo $repoInfo
    $checks += Test-RhcRepoAutomation    -RepoInfo $repoInfo
    $checks += Test-RhcRepoSecurity      -RepoInfo $repoInfo

    $score = Get-RhcRepoHealthScore -Checks $checks

    if ($HtmlReportPath) {
        Export-RhcHtmlReport -Checks $checks -Score $score -OutputPath $HtmlReportPath
    }

    [pscustomobject]@{
        Checks=$checks
        Score=$score
    }
}
