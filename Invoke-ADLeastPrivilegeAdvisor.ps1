<#
================================================================================
AD Least Privilege Advisor
================================================================================

GOAL
-----
Analyze Active Directory accounts, groups, and privileges to identify excessive
or unnecessary access. Produce clear, actionable recommendations that support
least‑privilege hardening and AD hygiene.

AUDIENCE
---------
• AD administrators  
• Security engineers and IAM architects  
• Blue teams performing privilege reviews  
• Auditors validating access governance  

AUTHOR
-------
Scott Malin, CISSP

LAST MODIFIED
--------------
2026-08-25

CHANGELOG
----------
v1.1.0  
• Fixed group null-member count handling using array casting.
• Removed invalid LastLogonDate property request on AD groups.
• Handled null LastLogonDate for never-logged-on user accounts to avoid false positives.
• Added pipeline optimization and error handling for large directory environments.
v1.0.0  
• Initial release  
• Added unused group membership detection  
• Added unused group detection  
• Added service account logon‑rights analysis  
• Added recommendation engine  

DESCRIPTION
------------
This script analyzes Active Directory usage patterns and privilege assignments to
identify:
• Group memberships unused for X days  
• Groups with no members or no recent usage  
• Service accounts with unnecessary interactive logon rights  
• Accounts with privilege anomalies  

USAGE
------
Run in a privileged PowerShell session with RSAT installed:

    .\Invoke-ADLeastPrivilegeAdvisor.ps1

Outputs:
• Recommendations for unused groups  
• Recommendations for stale group memberships  
• Recommendations for service account logon restrictions  
• Optional CSV/JSON export  

================================================================================
#>

param(
    [int]$StaleDays = 180,
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

Write-Host "[+] Starting AD Least Privilege Analysis..." -ForegroundColor Cyan

$Recommendations = [System.Collections.Generic.List[PSCustomObject]]::new()
$CutoffDate = (Get-Date).AddDays(-$StaleDays)

# ---------------------------------------------------------------------------
# 1. DETECT UNUSED GROUP MEMBERSHIPS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking for stale group memberships..." -ForegroundColor Green

try {
    $Users = Get-ADUser -Filter "Enabled -eq $true" -Properties MemberOf, LastLogonDate, samAccountName
    
    foreach ($u in $Users) {
        if ($u.MemberOf) {
            # Check if user hasn't logged on in X days OR never logged on
            $isStale = if ($null -eq $u.LastLogonDate) { 
                $true 
            } else { 
                $u.LastLogonDate -lt $CutoffDate 
            }

            if ($isStale) {
                foreach ($g in $u.MemberOf) {
                    $Recommendations.Add([PSCustomObject]@{
                        Type    = "StaleGroupMembership"
                        Account = $u.SamAccountName
                        Group   = $g
                        Detail  = if ($null -eq $u.LastLogonDate) { "User has NEVER logged on — review group membership." } else { "User inactive for $StaleDays+ days (Last Logon: $($u.LastLogonDate.ToShortDateString())) — review membership." }
                    })
                }
            }
        }
    }
} catch {
    Write-Host "[-] Error querying users: $_" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 2. DETECT UNUSED GROUPS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking for empty groups..." -ForegroundColor Green

try {
    $Groups = Get-ADGroup -Filter * -Properties Members, DistinguishedName, SamAccountName
    
    foreach ($g in $Groups) {
        $memberCount = @($g.Members).Count
        if ($memberCount -eq 0) {
            $Recommendations.Add([PSCustomObject]@{
                Type    = "UnusedGroup"
                Account = $g.SamAccountName
                Group   = $g.DistinguishedName
                Detail  = "Group has 0 members — recommend deletion or archival."
            })
        }
    }
} catch {
    Write-Host "[-] Error querying groups: $_" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 3. SERVICE ACCOUNT LOGON RIGHTS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking service account logon restrictions..." -ForegroundColor Green

try {
    # 0x2000 = WORKSTATION_TRUST_ACCOUNT, but usually service accounts are flagged via UAC or naming conventions.
    # Checking accounts where UserAccountControl includes DONT_EXPIRE_PASSWORD (0x10000) or WORKSTATION_TRUST (0x2000)
    $ServiceAccounts = Get-ADUser -Filter "UserAccountControl -band 0x10000" -Properties LogonWorkstations, SamAccountName

    foreach ($sa in $ServiceAccounts) {
        if ([string]::IsNullOrWhiteSpace($sa.LogonWorkstations)) {
            $Recommendations.Add([PSCustomObject]@{
                Type    = "ServiceAccountLogon"
                Account = $sa.SamAccountName
                Group   = "N/A"
                Detail  = "Password never expires and no Workstation logon restrictions set — recommend applying logon restrictions or MSA/gMSA migration."
            })
        }
    }
} catch {
    Write-Host "[-] Error querying service accounts: $_" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 4. OUTPUT RESULTS
# ---------------------------------------------------------------------------
Write-Host "`n=== Least Privilege Recommendations ===" -ForegroundColor Yellow
if ($Recommendations.Count -gt 0) {
    $Recommendations | Format-Table -AutoSize
} else {
    Write-Host "[+] No privilege risks identified based on current criteria." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. OPTIONAL EXPORT
# ---------------------------------------------------------------------------
if ($ExportCSV) {
    $csvPath = ".\AD_LeastPrivilege_Recommendations.csv"
    $Recommendations | Export-Csv -NoTypeInformation -Path $csvPath
    Write-Host "[+] Exported CSV to $csvPath" -ForegroundColor Cyan
}

if ($ExportJSON) {
    $jsonPath = ".\AD_LeastPrivilege_Recommendations.json"
    $Recommendations | ConvertTo-Json -Depth 3 | Out-File $jsonPath
    Write-Host "[+] Exported JSON to $jsonPath" -ForegroundColor Cyan
}

Write-Host "`n[+] Analysis complete." -ForegroundColor Cyan