Import-Module "$PSScriptRoot/../RepoHealthChecker.psm1" -Force

$repoPath = Resolve-Path "$PSScriptRoot/.."
$report   = Join-Path $repoPath 'reports/RepoHealthReport.html'

$result = Invoke-RhcRepoHealthCheck -Path $repoPath -HtmlReportPath $report

$result.Score
$result.Checks | Format-Table -AutoSize

Write-Host "HTML report generated at: $report"
