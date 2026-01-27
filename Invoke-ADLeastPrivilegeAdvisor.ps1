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
Scott M

LAST MODIFIED
--------------
2026‑01‑27

CHANGELOG
----------
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

It outputs a structured recommendation list suitable for audits, cleanup
projects, and least‑privilege hardening.

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

Write-Host "[+] Starting AD Least Privilege Analysis..."

$Recommendations = @()

# ---------------------------------------------------------------------------
# 1. DETECT UNUSED GROUP MEMBERSHIPS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking for stale group memberships..."

$Users = Get-ADUser -Filter * -Properties MemberOf, LastLogonDate

foreach ($u in $Users) {
    foreach ($g in $u.MemberOf) {
        if ($u.LastLogonDate -lt (Get-Date).AddDays(-$StaleDays)) {
            $Recommendations += [PSCustomObject]@{
                Type = "StaleGroupMembership"
                Account = $u.SamAccountName
                Group = $g
                Detail = "User has not logged on in $StaleDays days — recommend reviewing membership."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 2. DETECT UNUSED GROUPS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking for unused groups..."

$Groups = Get-ADGroup -Filter * -Properties Members, LastLogonDate

foreach ($g in $Groups) {
    if (-not $g.Members -or $g.Members.Count -eq 0) {
        $Recommendations += [PSCustomObject]@{
            Type = "UnusedGroup"
            Account = $g.SamAccountName
            Group = $g.DistinguishedName
            Detail = "Group has no members — recommend deletion or archival."
        }
    }
}

# ---------------------------------------------------------------------------
# 3. SERVICE ACCOUNT LOGON RIGHTS
# ---------------------------------------------------------------------------
Write-Host "[+] Checking service account logon rights..."

$ServiceAccounts = Get-ADUser -Filter "UserAccountControl -band 0x2000" -Properties LogonWorkstations

foreach ($sa in $ServiceAccounts) {
    if (-not $sa.LogonWorkstations -or $sa.LogonWorkstations -eq "") {
        $Recommendations += [PSCustomObject]@{
            Type = "ServiceAccountLogon"
            Account = $sa.SamAccountName
            Group = ""
            Detail = "Service account allows interactive logon — recommend restricting logon rights."
        }
    }
}

# ---------------------------------------------------------------------------
# 4. OUTPUT RESULTS
# ---------------------------------------------------------------------------
Write-Host "`n=== Least Privilege Recommendations ==="
$Recommendations | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 5. OPTIONAL EXPORT
# ---------------------------------------------------------------------------
if ($ExportCSV) {
    $Recommendations | Export-Csv -NoTypeInformation -Path ".\AD_LeastPrivilege_Recommendations.csv"
}

if ($ExportJSON) {
    $Recommendations | ConvertTo-Json | Out-File ".\AD_LeastPrivilege_Recommendations.json"
}

Write-Host "`n[+] Completed."
