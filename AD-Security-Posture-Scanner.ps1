<#
.SYNOPSIS
    Active Directory Anomaly & Security Posture Scanner

.DESCRIPTION
    Scans AD users and groups for:
      - Hygiene anomalies (stale accounts, empty groups, etc.)
      - Privilege escalation risks (direct/indirect privileged memberships)
      - Security posture issues (delegation, password policies, etc.)
    Outputs results to a CSV for further investigation, including severity and score.

.NOTES
    Author: Scott M
    Version: 1.1

.CHANGELOG
    1.1 - Added:
          - Privilege escalation detection
          - Security posture checks
          - Severity scoring (Low/Medium/High/Critical + numeric score)
    1.0 - Initial release with basic anomaly detection and CSV export
#>

Import-Module ActiveDirectory

# -----------------------------
# Configuration
# -----------------------------

# Stale account threshold (days)
$StaleDays = 90

# Privileged groups to watch (by name)
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

# Severity scoring map
$SeverityScoreMap = @{
    "Low"      = 10
    "Medium"   = 40
    "High"     = 70
    "Critical" = 90
}

# -----------------------------
# Helper functions
# -----------------------------

function Add-Finding {
    param(
        [string]$ObjectType,
        [string]$Name,
        [string]$Issue,
        [string]$Severity,
        [string]$Category,
        [string]$DistinguishedName = $null,
        [string]$Extra = $null
    )

    $score = if ($SeverityScoreMap.ContainsKey($Severity)) {
        $SeverityScoreMap[$Severity]
    } else {
        0
    }

    $script:Results += [pscustomobject]@{
        ObjectType        = $ObjectType
        Name              = $Name
        DistinguishedName = $DistinguishedName
        Issue             = $Issue
        Category          = $Category
        Severity          = $Severity
        Score             = $score
        Extra             = $Extra
    }
}

function Get-PrivilegedGroups {
    param(
        [System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADGroup]]$AllGroups
    )

    return $AllGroups | Where-Object { $PrivilegedGroupNames -contains $_.Name }
}

# -----------------------------
# Data collection
# -----------------------------

$Results = @()

Write-Host "Loading Active Directory objects..." -ForegroundColor Cyan

$users  = Get-ADUser  -Filter * -Properties * 
$groups = Get-ADGroup -Filter * -Properties *

# Pre-resolve privileged groups
$privilegedGroups = Get-PrivilegedGroups -AllGroups ([System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADGroup]]$groups)

$total   = $users.Count + $groups.Count
$counter = 0

Write-Host "Scanning Active Directory for anomalies and security posture issues..." -ForegroundColor Cyan

# -----------------------------
# User analysis
# -----------------------------

foreach ($user in $users) {
    $counter++
    Write-Progress -Activity "Scanning Users" -Status $user.SamAccountName -PercentComplete (($counter / $total) * 100)

    $dn   = $user.DistinguishedName
    $name = $user.SamAccountName

    # --- Hygiene: Stale account ---
    if ($user.LastLogonDate -and $user.LastLogonDate -lt (Get-Date).AddDays(-$StaleDays)) {
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Stale account (no logon in $StaleDays+ days)" `
            -Severity "Medium" -Category "Hygiene"
    }

    # --- Hygiene: Password never expires ---
    if ($user.PasswordNeverExpires -eq $true) {
        $sev = if ($user.Enabled -and $user.adminCount -eq 1) { "High" } else { "Medium" }
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Password never expires" `
            -Severity $sev -Category "Hygiene"
    }

    # --- Hygiene: Disabled but still in groups ---
    if ($user.Enabled -eq $false) {
        $groupsForUser = Get-ADPrincipalGroupMembership -Identity $user -ErrorAction SilentlyContinue
        if ($groupsForUser.Count -gt 0) {
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Disabled account still has group memberships" `
                -Severity "Medium" -Category "Hygiene" `
                -Extra ("Groups: " + ($groupsForUser.Name -join "; "))
        }
    }

    # -----------------------------
    # Privilege escalation detection
    # -----------------------------

    $userGroups = Get-ADPrincipalGroupMembership -Identity $user -ErrorAction SilentlyContinue
    if ($userGroups) {
        # Direct/indirect membership in privileged groups
        $privGroupsForUser = $userGroups | Where-Object { $PrivilegedGroupNames -contains $_.Name }
        foreach ($pg in $privGroupsForUser) {
            $sev = if ($user.Enabled) { "Critical" } else { "High" }
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Member of privileged group" `
                -Severity $sev -Category "PrivilegeEscalation" `
                -Extra ("Privileged group: " + $pg.Name)
        }
    }

    # -----------------------------
    # Security posture checks
    # -----------------------------

    # Admin-like account with risky password policy
    if ($user.adminCount -eq 1 -and $user.PasswordNeverExpires -eq $true) {
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Privileged account with non-expiring password" `
            -Severity "Critical" -Category "SecurityPosture"
    }

    # Delegation risks (userAccountControl flags)
    # TRUSTED_FOR_DELEGATION (0x80000), SENSITIVE_AND_NOT_DELEGATED (0x100000)
    $uac = $user.userAccountControl
    $trustedForDelegation      = [bool]($uac -band 0x80000)
    $sensitiveAndNotDelegated  = [bool]($uac -band 0x100000)

    if ($trustedForDelegation -and -not $sensitiveAndNotDelegated) {
        $sev = if ($user.adminCount -eq 1) { "Critical" } else { "High" }
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Account trusted for delegation without 'sensitive and not delegated' protection" `
            -Severity $sev -Category "SecurityPosture"
    }

    # Password not required (PASSWD_NOTREQD 0x20)
    $passwordNotRequired = [bool]($uac -band 0x20)
    if ($passwordNotRequired) {
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Password not required flag set" `
            -Severity "High" -Category "SecurityPosture"
    }

    # Pre-authentication not required (DONT_REQ_PREAUTH 0x400000)
    $noPreAuth = [bool]($uac -band 0x400000)
    if ($noPreAuth) {
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Kerberos pre-authentication not required" `
            -Severity "High" -Category "SecurityPosture"
    }
}

# -----------------------------
# Group analysis
# -----------------------------

foreach ($group in $groups) {
    $counter++
    Write-Progress -Activity "Scanning Groups" -Status $group.Name -PercentComplete (($counter / $total) * 100)

    $dn   = $group.DistinguishedName
    $name = $group.Name

    # --- Hygiene: Empty group ---
    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
    if (-not $members -or $members.Count -eq 0) {
        Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
            -Issue "Empty group" `
            -Severity "Low" -Category "Hygiene"
    }

    # --- Hygiene: No group owner ---
    if (-not $group.ManagedBy) {
        Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
            -Issue "Group has no owner (ManagedBy not set)" `
            -Severity "Medium" -Category "Hygiene"
    }

    # -----------------------------
    # Privilege escalation: privileged groups posture
    # -----------------------------

    $isPrivilegedGroup = $PrivilegedGroupNames -contains $name
    if ($isPrivilegedGroup) {
        # Large privileged group
        if ($members -and $members.Count -gt 10) {
            Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
                -Issue "Privileged group with large membership" `
                -Severity "High" -Category "PrivilegeEscalation" `
                -Extra ("Member count: " + $members.Count)
        }

        # Nested groups inside privileged groups
        $nestedGroups = $members | Where-Object { $_.objectClass -eq "group" }
        if ($nestedGroups.Count -gt 0) {
            Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
                -Issue "Privileged group contains nested groups (potential indirect privilege escalation)" `
                -Severity "High" -Category "PrivilegeEscalation" `
                -Extra ("Nested groups: " + ($nestedGroups.Name -join "; "))
        }
    }
}

# -----------------------------
# Export
# -----------------------------

$timestamp  = (Get-Date -Format "yyyyMMdd_HHmmss")
$outputPath = "AD_Anomalies_Security_$timestamp.csv"

$Results | Sort-Object -Property Severity, Category, ObjectType, Name |
    Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete. Results exported to $outputPath" -ForegroundColor Green
