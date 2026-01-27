<#
.SYNOPSIS
    AD Privilege Drift & Shadow Admin Analyzer

.DESCRIPTION
    A comprehensive Active Directory security analysis tool that:
      • Captures privileged group membership baselines
      • Detects privilege drift between baselines
      • Identifies shadow admin candidates via ACL analysis
      • Generates CSV and HTML executive reports
      • Applies a weighted severity and scoring model

    This tool is designed for enterprise security teams, auditors, and
    administrators who need visibility into privilege changes and hidden
    escalation paths inside Active Directory.

.PARAMETER Mode
    Capture  – Captures a privileged membership baseline
    Analyze  – Compares current state to a baseline and detects drift

.PARAMETER BaselinePath
    Capture mode:
        Optional path to save the baseline CSV.
    Analyze mode:
        Required path to a previously captured baseline CSV.

.PARAMETER HtmlReportPath
    Optional. If provided, generates an HTML executive summary report.

.EXAMPLE
    Capture a baseline:
        .\AD-PrivilegeAnalyzer.ps1 -Mode Capture

.EXAMPLE
    Analyze drift:
        .\AD-PrivilegeAnalyzer.ps1 -Mode Analyze -BaselinePath .\Baseline.csv

.EXAMPLE
    Analyze and generate HTML report:
        .\AD-PrivilegeAnalyzer.ps1 -Mode Analyze -BaselinePath .\Baseline.csv -HtmlReportPath .\Report.html

.NOTES
    Author: Scott M
    Version: 0.3

.CHANGELOG
    0.3 - Added:
          • Weighted severity model
          • Scoring engine
          • HTML executive summary report
          • Improved shadow admin detection
          • Enhanced documentation and structure

    0.2 - Added:
          • Shadow admin detection via ACL analysis
          • Severity scoring for drift and shadow admin findings

    0.1 - Initial version:
          • Capture mode
          • Analyze mode
          • Privilege drift detection
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Capture", "Analyze")]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [string]$HtmlReportPath
)

Import-Module ActiveDirectory -ErrorAction Stop

# -----------------------------
# Configuration
# -----------------------------

$PrivilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators"
)

# Weighted severity model
$SeverityModel = @{
    "Info"     = @{ Base = 10;  CategoryWeight = 1 }
    "Low"      = @{ Base = 25;  CategoryWeight = 1.2 }
    "Medium"   = @{ Base = 50;  CategoryWeight = 1.5 }
    "High"     = @{ Base = 75;  CategoryWeight = 2 }
    "Critical" = @{ Base = 90;  CategoryWeight = 2.5 }
}

function Get-SeverityScore {
    param(
        [string]$Severity,
        [int]$ImpactScore = 0,
        [int]$ExploitabilityScore = 0
    )

    if (-not $SeverityModel.ContainsKey($Severity)) { return 0 }

    $base = $SeverityModel[$Severity].Base
    $weight = $SeverityModel[$Severity].CategoryWeight

    return [math]::Min(100, ($base * $weight) + $ImpactScore + $ExploitabilityScore)
}

# -----------------------------
# Helper Functions
# -----------------------------

function Add-Finding {
    param(
        [string]$Type,
        [string]$Identity,
        [string]$DistinguishedName,
        [string]$Details,
        [string]$Severity,
        [int]$ImpactScore = 0,
        [int]$ExploitabilityScore = 0
    )

    $script:Findings += [pscustomobject]@{
        Type              = $Type
        Identity          = $Identity
        DistinguishedName = $DistinguishedName
        Details           = $Details
        Severity          = $Severity
        Score             = Get-SeverityScore -Severity $Severity -ImpactScore $ImpactScore -ExploitabilityScore $ExploitabilityScore
    }
}

function Get-UserPrivilegedGroups {
    param([Microsoft.ActiveDirectory.Management.ADUser]$User)

    $groups = Get-ADPrincipalGroupMembership -Identity $User -ErrorAction SilentlyContinue
    if (-not $groups) { return @() }

    return $groups | Where-Object { $PrivilegedGroupNames -contains $_.Name } | Select-Object -ExpandProperty Name
}

function Resolve-Identity {
    param([string]$Identity)

    $parts = $Identity.Split("\", 2)
    if ($parts.Count -ne 2) { return $null }

    $sam = $parts[1]

    $user = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if ($user) { return $user }

    $group = Get-ADGroup -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if ($group) { return $group }

    return $null
}

# -----------------------------
# Mode: Capture
# -----------------------------

if ($Mode -eq "Capture") {

    if (-not $BaselinePath) {
        $BaselinePath = "AD_PrivilegeBaseline_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    }

    Write-Host "[*] Capturing privileged membership baseline..." -ForegroundColor Cyan

    $users = Get-ADUser -Filter * -Properties *
    $baseline = foreach ($user in $users) {
        $priv = Get-UserPrivilegedGroups -User $user
        [pscustomobject]@{
            SamAccountName    = $user.SamAccountName
            DistinguishedName = $user.DistinguishedName
            PrivilegedGroups  = ($priv -join ";")
        }
    }

    $baseline | Export-Csv -Path $BaselinePath -NoTypeInformation -Encoding UTF8

    Write-Host "[+] Baseline saved to $BaselinePath" -ForegroundColor Green
    return
}

# -----------------------------
# Mode: Analyze
# -----------------------------

if ($Mode -eq "Analyze") {

    if (-not $BaselinePath) {
        throw "BaselinePath is required in Analyze mode."
    }

    if (-not (Test-Path $BaselinePath)) {
        throw "Baseline file not found: $BaselinePath"
    }

    Write-Host "[*] Loading baseline..." -ForegroundColor Cyan
    $baseline = Import-Csv $BaselinePath

    $baselineMap = @{}
    foreach ($row in $baseline) { $baselineMap[$row.SamAccountName] = $row }

    $Findings = @()

    Write-Host "[*] Detecting privilege drift..." -ForegroundColor Cyan

    $currentUsers = Get-ADUser -Filter * -Properties *
    foreach ($user in $currentUsers) {

        $currentPriv = Get-UserPrivilegedGroups -User $user
        $baselinePriv = @()

        if ($baselineMap.ContainsKey($user.SamAccountName)) {
            $baselinePriv = $baselineMap[$user.SamAccountName].PrivilegedGroups -split ";" | Where-Object { $_ }
            $baselineMap.Remove($user.SamAccountName) | Out-Null
        }

        $gained = $currentPriv | Where-Object { $baselinePriv -notcontains $_ }
        $lost   = $baselinePriv | Where-Object { $currentPriv -notcontains $_ }

        if ($gained.Count -gt 0) {
            Add-Finding -Type "PrivilegeDrift" `
                        -Identity $user.SamAccountName `
                        -DistinguishedName $user.DistinguishedName `
                        -Details ("Gained privileged groups: " + ($gained -join "; ")) `
                        -Severity "High" -ImpactScore 20 -ExploitabilityScore 20
        }

        if ($lost.Count -gt 0) {
            Add-Finding -Type "PrivilegeDrift" `
                        -Identity $user.SamAccountName `
                        -DistinguishedName $user.DistinguishedName `
                        -Details ("Lost privileged groups: " + ($lost -join "; ")) `
                        -Severity "Info"
        }
    }

    foreach ($remaining in $baselineMap.Values) {
        if ($remaining.PrivilegedGroups) {
            Add-Finding -Type "PrivilegeDrift" `
                        -Identity $remaining.SamAccountName `
                        -DistinguishedName $remaining.DistinguishedName `
                        -Details ("User missing but had privileged access: " + $remaining.PrivilegedGroups) `
                        -Severity "Medium" -ImpactScore 10
        }
    }

    # -----------------------------
    # Shadow Admin Detection
    # -----------------------------

    Write-Host "[*] Detecting shadow admin candidates..." -ForegroundColor Cyan

    $privGroups = Get-ADGroup -Filter * | Where-Object { $PrivilegedGroupNames -contains $_.Name }

    foreach ($group in $privGroups) {

        $acl = Get-Acl ("AD:\" + $group.DistinguishedName)

        foreach ($ace in $acl.Access) {

            $rights = $ace.ActiveDirectoryRights

            $isPowerful =
                ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or
                ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or
                ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or
                ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)

            if (-not $isPowerful) { continue }

            $identity = $ace.IdentityReference.Value
            $obj = Resolve-Identity -Identity $identity

            if (-not $obj) {
                Add-Finding -Type "ShadowAdmin" `
                            -Identity $identity `
                            -DistinguishedName "" `
                            -Details ("Unresolved identity with powerful rights on " + $group.Name) `
                            -Severity "Medium" -ImpactScore 10 -ExploitabilityScore 20
                continue
            }

            $isPrivileged = $false
            if ($obj.ObjectClass -eq "user") {
                $priv = Get-UserPrivilegedGroups -User $obj
                if ($priv.Count -gt 0) { $isPrivileged = $true }
            }
            elseif ($obj.ObjectClass -eq "group") {
                if ($PrivilegedGroupNames -contains $obj.Name) { $isPrivileged = $true }
            }

            if (-not $isPrivileged) {
                Add-Finding -Type "ShadowAdmin" `
                            -Identity $identity `
                            -DistinguishedName $obj.DistinguishedName `
                            -Details ("Shadow admin rights on " + $group.Name + ": " + $rights) `
                            -Severity "Critical" -ImpactScore 30 -ExploitabilityScore 30
            }
        }
    }

    # -----------------------------
    # Export CSV
    # -----------------------------

    $timestamp = Get-Date -Format yyyyMMdd_HHmmss
    $csvPath = "AD_PrivilegeAnalysis_$timestamp.csv"

    $Findings | Sort-Object Score -Descending |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "[+] Analysis exported to $csvPath" -ForegroundColor Green

    # -----------------------------
    # HTML Report
    # -----------------------------

    if ($HtmlReportPath) {

        Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan

        $html = @"
<html>
<head>
<title>AD Privilege Drift & Shadow Admin Report</title>
<style>
body { font-family: Arial; margin: 20px; }
h1 { color: #2a4b8d; }
h2 { color: #3c3c3c; }
table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
th, td { border: 1px solid #ccc; padding: 8px; }
th { background-color: #f2f2f2; }
.sev-Critical { background-color: #ffcccc; }
.sev-High     { background-color: #ffe0cc; }
.sev-Medium   { background-color: #fff2cc; }
.sev-Low      { background-color: #e6f7ff; }
.sev-Info     { background-color: #f0f0f0; }
</style>
</head>
<body>
<h1>AD Privilege Drift & Shadow Admin Report</h1>
<p>Generated: $(Get-Date)</p>
<h2>Summary</h2>
<ul>
<li>Total Findings: $($Findings.Count)</li>
<li>Critical: $((($Findings | Where-Object Severity -eq "Critical").Count))</li>
<li>High: $((($Findings | Where-Object Severity -eq "High").Count))</li>
<li>Medium: $((($Findings | Where-Object Severity -eq "Medium").Count))</li>
<li>Low: $((($Findings | Where-Object Severity -eq "Low").Count))</li>
<li>Info: $((($Findings | Where-Object Severity -eq "Info").Count))</li>
</ul>
<h2>Detailed Findings</h2>
<table>
<tr><th>Type</th><th>Identity</th><th>Details</th><th>Severity</th><th>Score</th></tr>
"@

        foreach ($f in $Findings) {
            $sevClass = "sev-$($f.Severity)"
            $html += "<tr class='$sevClass'><td>$($f.Type)</td><td>$($f.Identity)</td><td>$($f.Details)</td><td>$($f.Severity)</td><td>$($f.Score)</td></tr>"
        }

        $html += "</table></body></html>"

        $html | Out-File -FilePath $HtmlReportPath -Encoding UTF8

        Write-Host "[+] HTML report saved to $HtmlReportPath" -ForegroundColor Green
    }

    return
}
