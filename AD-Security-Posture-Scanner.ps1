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
    Author: Scott Malin, CISSP
    Version: 1.2.0

.CHANGELOG
    1.2.0 - Performance & Scale Optimization:
            - Replaced `Get-ADUser -Properties *` with explicitly targeted properties to prevent memory exhaustion.
            - Eliminated repeated `Get-ADPrincipalGroupMembership` calls inside loops by resolving memberDNs locally.
            - Fixed `Get-ADGroupMember` ADWS 5,000-member limits by reading raw `Members` property collections.
            - Deduplicated redundant finding evaluations across Hygiene and SecurityPosture logic block boundaries.
    1.1.0 - Added:
            - Privilege escalation detection
            - Security posture checks
            - Severity scoring (Low/Medium/High/Critical + numeric score)
    1.0.0 - Initial release with basic anomaly detection and CSV export
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

    $script:Results.Add([pscustomobject]@{
        ObjectType        = $ObjectType
        Name              = $Name
        DistinguishedName = $DistinguishedName
        Issue             = $Issue
        Category          = $Category
        Severity          = $Severity
        Score             = $score
        Extra             = $Extra
    })
}

# -----------------------------
# Data collection
# -----------------------------

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "Loading Active Directory objects..." -ForegroundColor Cyan

# Explicit property targeted fetching to save memory and network overhead
$userProperties = @(
    'SamAccountName', 'DistinguishedName', 'Enabled', 'LastLogonDate',
    'PasswordNeverExpires', 'adminCount', 'userAccountControl', 'MemberOf'
)
$users = Get-ADUser -Filter * -Properties $userProperties

$groupProperties = @('Name', 'DistinguishedName', 'ManagedBy', 'Members')
$groups = Get-ADGroup -Filter * -Properties $groupProperties

# Pre-map group DNs and names for fast local lookup
$GroupDNMap = @{}
foreach ($g in $groups) {
    $GroupDNMap[$g.DistinguishedName] = $g
}

# Pre-resolve privileged group DistinguishedNames
$PrivilegedGroupDNs = $groups | Where-Object { $PrivilegedGroupNames -contains $_.Name } | Select-Object -ExpandProperty DistinguishedName

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
    if ($user.Enabled -eq $false -and $user.MemberOf.Count -gt 0) {
        $groupNames = foreach ($gDN in $user.MemberOf) {
            if ($GroupDNMap.ContainsKey($gDN)) { $GroupDNMap[$gDN].Name } else { $gDN }
        }
        Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
            -Issue "Disabled account still has group memberships" `
            -Severity "Medium" -Category "Hygiene" `
            -Extra ("Groups: " + ($groupNames -join "; "))
    }

    # -----------------------------
    # Privilege escalation detection
    # -----------------------------

    if ($user.MemberOf) {
        $matchedPrivGroups = $user.MemberOf | Where-Object { $PrivilegedGroupDNs -contains $_ }
        foreach ($pgDN in $matchedPrivGroups) {
            $pgName = if ($GroupDNMap.ContainsKey($pgDN)) { $GroupDNMap[$pgDN].Name } else { $pgDN }
            $sev = if ($user.Enabled) { "Critical" } else { "High" }
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Member of privileged group" `
                -Severity $sev -Category "PrivilegeEscalation" `
                -Extra ("Privileged group: " + $pgName)
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

    # Delegation risks (userAccountControl bitwise flags)
    $uac = $user.userAccountControl
    if ($uac) {
        $trustedForDelegation     = [bool]($uac -band 0x80000)
        $sensitiveAndNotDelegated = [bool]($uac -band 0x100000)

        if ($trustedForDelegation -and -not $sensitiveAndNotDelegated) {
            $sev = if ($user.adminCount -eq 1) { "Critical" } else { "High" }
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Account trusted for delegation without 'sensitive and not delegated' protection" `
                -Severity $sev -Category "SecurityPosture"
        }

        # Password not required (PASSWD_NOTREQD 0x20)
        if ([bool]($uac -band 0x20)) {
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Password not required flag set" `
                -Severity "High" -Category "SecurityPosture"
        }

        # Pre-authentication not required (DONT_REQ_PREAUTH 0x400000 - AS-REP Roasting risk)
        if ([bool]($uac -band 0x400000)) {
            Add-Finding -ObjectType "User" -Name $name -DistinguishedName $dn `
                -Issue "Kerberos pre-authentication not required (AS-REP Roasting risk)" `
                -Severity "High" -Category "SecurityPosture"
        }
    }
}

# -----------------------------
# Group analysis
# -----------------------------

foreach ($group in $groups) {
    $counter++
    Write-Progress -Activity "Scanning Groups" -Status $group.Name -PercentComplete (($counter / $total) * 100)

    $dn      = $group.DistinguishedName
    $name    = $group.Name
    $members = $group.Members

    # --- Hygiene: Empty group ---
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

    if ($PrivilegedGroupNames -contains $name) {
        # Large privileged group
        if ($members -and $members.Count -gt 10) {
            Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
                -Issue "Privileged group with large membership" `
                -Severity "High" -Category "PrivilegeEscalation" `
                -Extra ("Member count: " + $members.Count)
        }

        # Nested groups inside privileged groups
        if ($members) {
            $nestedGroupDNs = $members | Where-Object { $GroupDNMap.ContainsKey($_) }
            if ($nestedGroupDNs) {
                $nestedNames = foreach ($nDN in $nestedGroupDNs) { $GroupDNMap[$nDN].Name }
                Add-Finding -ObjectType "Group" -Name $name -DistinguishedName $dn `
                    -Issue "Privileged group contains nested groups (potential indirect privilege escalation)" `
                    -Severity "High" -Category "PrivilegeEscalation" `
                    -Extra ("Nested groups: " + ($nestedNames -join "; "))
            }
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