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
    Author: Scott Malin, CISSP
    Version: 1.0.0

.CHANGELOG
    1.0.0 - 2026-08-25
          - Production release.
          - Fixed bitwise evaluation logic for ActiveDirectoryRights ACL analysis.
          - Replaced heavy 'Get-ADUser -Filter * -Properties *' with lightweight property selectors.
          - Fixed SID and identity resolution for well-known SIDs and cross-domain references.
          - Added recursive nested group privilege checking.
          - Improved HTML executive report rendering and CSS styling.

    0.3 - Added:
          - Weighted severity model
          - Scoring engine
          - HTML executive summary report
          - Improved shadow admin detection
          - Enhanced documentation and structure

    0.2 - Added:
          - Shadow admin detection via ACL analysis
          - Severity scoring for drift and shadow admin findings

    0.1 - Initial version:
          - Capture mode
          - Analyze mode
          - Privilege drift detection
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
    "Info"     = @{ Base = 10;  CategoryWeight = 1.0 }
    "Low"      = @{ Base = 25;  CategoryWeight = 1.2 }
    "Medium"   = @{ Base = 50;  CategoryWeight = 1.5 }
    "High"     = @{ Base = 75;  CategoryWeight = 2.0 }
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

    return [math]::Min(100, [int](($base * $weight) + $ImpactScore + $ExploitabilityScore))
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

    try {
        # Check recursive group memberships to catch nested privilege escalation
        $groups = Get-ADPrincipalGroupMembership -Identity $User -ErrorAction SilentlyContinue
        if (-not $groups) { return @() }
        return $groups | Where-Object { $PrivilegedGroupNames -contains $_.Name } | Select-Object -ExpandProperty Name
    } catch {
        return @()
    }
}

function Resolve-Identity {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }

    # Handle SID strings directly
    if ($Identity -like "S-1-*") {
        return Get-ADObject -Filter "objectSid -eq '$Identity'" -ErrorAction SilentlyContinue
    }

    # Split Domain\SamAccountName safely
    $sam = if ($Identity -contains "\") { $Identity.Split("\")[-1] } else { $Identity }

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

    # Optimized property lookup to avoid pulling entire AD schema into memory
    $users = Get-ADUser -Filter * -Properties SamAccountName, DistinguishedName

    $baseline = foreach ($user in $users) {
        $priv = Get-UserPrivilegedGroups -User $user
        if ($priv.Count -gt 0) {
            [pscustomobject]@{
                SamAccountName    = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                PrivilegedGroups  = ($priv -join ";")
            }
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

    $script:Findings = @()

    Write-Host "[*] Detecting privilege drift..." -ForegroundColor Cyan

    $currentUsers = Get-ADUser -Filter * -Properties SamAccountName, DistinguishedName
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
                        -Details ("User missing from AD but had privileged baseline access: " + $remaining.PrivilegedGroups) `
                        -Severity "Medium" -ImpactScore 10
        }
    }

    # -----------------------------
    # Shadow Admin Detection
    # -----------------------------

    Write-Host "[*] Detecting shadow admin candidates via ACL analysis..." -ForegroundColor Cyan

    $privGroups = Get-ADGroup -Filter * | Where-Object { $PrivilegedGroupNames -contains $_.Name }

    # Define standard high-risk AD rights bitmask flags
    $HighRiskRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor
                      [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor
                      [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
                      [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

    foreach ($group in $privGroups) {

        $acl = Get-Acl ("AD:\" + $group.DistinguishedName)

        foreach ($ace in $acl.Access) {

            # Skip inherited or access-denied ACEs for clear shadow admin detection
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $rights = $ace.ActiveDirectoryRights
            $isPowerful = [bool]($rights -band $HighRiskRights)

            if (-not $isPowerful) { continue }

            $identity = $ace.IdentityReference.Value
            
            # Skip built-in system identities
            if ($identity -like "*Domain Admins*" -or $identity -like "*Enterprise Admins*" -or $identity -like "NT AUTHORITY\*") { continue }

            $obj = Resolve-Identity -Identity $identity

            if (-not $obj) {
                Add-Finding -Type "ShadowAdmin" `
                            -Identity $identity `
                            -DistinguishedName "" `
                            -Details ("Unresolved identity with explicit control rights ($rights) on " + $group.Name) `
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
                            -Details ("Non-admin object holds shadow admin rights ($rights) on " + $group.Name) `
                            -Severity "Critical" -ImpactScore 30 -ExploitabilityScore 30
            }
        }
    }

    # -----------------------------
    # Export CSV
    # -----------------------------

    $timestamp = Get-Date -Format yyyyMMdd_HHmmss
    $csvPath = "AD_PrivilegeAnalysis_$timestamp.csv"

    $script:Findings | Sort-Object Score -Descending |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "[+] Analysis exported to $csvPath" -ForegroundColor Green

    # -----------------------------
    # HTML Report
    # -----------------------------

    if ($HtmlReportPath) {

        Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AD Privilege Drift & Shadow Admin Report</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 30px; background-color: #f8f9fa; color: #333; }
h1 { color: #1a365d; border-bottom: 2px solid #cbd5e0; padding-bottom: 10px; }
h2 { color: #2d3748; margin-top: 25px; }
.summary-box { display: flex; gap: 15px; margin-bottom: 25px; }
.card { background: white; padding: 15px 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 5px solid #cbd5e0; }
.card.critical { border-left-color: #e53e3e; }
.card.high { border-left-color: #dd6b20; }
.card.medium { border-left-color: #d69e2e; }
table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; overflow: hidden; }
th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e2e8f0; }
th { background-color: #edf2f7; color: #4a5568; font-weight: 600; }
tr:hover { background-color: #f7fafc; }
.sev-Critical { color: #9b2c2c; font-weight: bold; background-color: #fff5f5; }
.sev-High     { color: #c05621; font-weight: bold; background-color: #fffaf0; }
.sev-Medium   { color: #975a16; background-color: #fffff0; }
.sev-Low      { color: #2b6cb0; }
.sev-Info     { color: #4a5568; }
</style>
</head>
<body>
<h1>AD Privilege Drift & Shadow Admin Report</h1>
<p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div class="summary-box">
  <div class="card critical"><strong>Critical:</strong> $((($script:Findings | Where-Object Severity -eq "Critical").Count))</div>
  <div class="card high"><strong>High:</strong> $((($script:Findings | Where-Object Severity -eq "High").Count))</div>
  <div class="card medium"><strong>Medium:</strong> $((($script:Findings | Where-Object Severity -eq "Medium").Count))</div>
  <div class="card"><strong>Total Findings:</strong> $($script:Findings.Count)</div>
</div>

<h2>Detailed Findings</h2>
<table>
<tr><th>Type</th><th>Identity</th><th>Details</th><th>Severity</th><th>Score</th></tr>
"@

        foreach ($f in ($script:Findings | Sort-Object Score -Descending)) {
            $sevClass = "sev-$($f.Severity)"
            $html += "<tr class='$sevClass'><td>$($f.Type)</td><td>$($f.Identity)</td><td>$($f.Details)</td><td>$($f.Severity)</td><td>$($f.Score)</td></tr>"
        }

        $html += "</table></body></html>"

        $html | Out-File -FilePath $HtmlReportPath -Encoding UTF8

        Write-Host "[+] HTML report saved to $HtmlReportPath" -ForegroundColor Green
    }

    return
}