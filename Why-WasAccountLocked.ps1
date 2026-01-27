<#
===============================================================================
Title:      Why-WasAccountLocked.ps1
Author:     Scott M
Version:    1.0.0
Date:       2026-01-27

GOAL
----
Analyze Active Directory account lockout events and produce a clear,
human-readable explanation of WHY a user account was locked, WHEN it happened,
and FROM WHERE the lockout originated.

This script is designed to eliminate guesswork and manual event log correlation
when responding to account lockout tickets.

INSTRUCTIONS
------------
1. Run this script from a domain-joined machine with permission to read:
   - Security Event Logs
   - Active Directory user objects
2. PowerShell 5.1+ recommended
3. Run as Administrator for best results
4. Provide a username when prompted

OUTPUT
------
- Lockout time
- Source computer(s)
- Domain controller(s) involved
- Plain-English explanation suitable for a ticket or email
- Optional raw event details for deeper analysis

CHANGELOG
---------
1.0.0 - Initial release
       - Correlates Event IDs 4740 and 4625
       - Identifies source host and DC
       - Generates natural-language explanation
===============================================================================
#>

# ----------------------------
# PARAMETERS
# ----------------------------
param (
    [Parameter(Mandatory = $false)]
    [string]$Username
)

# ----------------------------
# PRE-CHECKS
# ----------------------------
if (-not $Username) {
    $Username = Read-Host "Enter the username to analyze"
}

Write-Host "`n[+] Analyzing lockout events for user: $Username`n" -ForegroundColor Cyan

# ----------------------------
# EVENT IDS USED
# ----------------------------
$LockoutEventID = 4740   # Account locked out
$FailedLogonID  = 4625   # Failed logon

# ----------------------------
# COLLECT LOCKOUT EVENTS
# ----------------------------
$lockoutEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = $LockoutEventID
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[0].Value -eq $Username
}

if (-not $lockoutEvents) {
    Write-Host "[-] No lockout events found for $Username" -ForegroundColor Yellow
    return
}

# Take most recent lockout
$latestLockout = $lockoutEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1

$lockoutTime = $latestLockout.TimeCreated
$callingComputer = $latestLockout.Properties[1].Value
$domainController = $latestLockout.MachineName

# ----------------------------
# COLLECT FAILED LOGONS
# ----------------------------
$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $FailedLogonID
    StartTime = $lockoutTime.AddMinutes(-30)
    EndTime   = $lockoutTime
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[5].Value -eq $Username
}

# Group failures by source workstation
$failureSources = $failedLogons | Group-Object {
    $_.Properties[11].Value
} | Sort-Object Count -Descending

# ----------------------------
# BUILD EXPLANATION
# ----------------------------
$explanation = @()
$explanation += "Account '$Username' was locked out on $lockoutTime."
$explanation += "The lockout was processed by domain controller '$domainController'."

if ($callingComputer -and $callingComputer -ne '-') {
    $explanation += "The lockout request originated from computer '$callingComputer'."
}

if ($failureSources) {
    $topSource = $failureSources[0].Name
    $attempts  = $failureSources[0].Count
    $explanation += "Most failed authentication attempts came from '$topSource' ($attempts attempts)."
}

$explanation += "This is typically caused by one of the following:"
$explanation += "- Cached credentials on a workstation or laptop"
$explanation += "- A service or scheduled task running under old credentials"
$explanation += "- A mobile device or VPN client using an outdated password"

# ----------------------------
# OUTPUT SUMMARY
# ----------------------------
Write-Host "================ LOCKOUT SUMMARY ================" -ForegroundColor Green
$explanation | ForEach-Object { Write-Host $_ }

Write-Host "`n================ TECHNICAL DETAILS ================" -ForegroundColor DarkGray
Write-Host "Lockout Time     : $lockoutTime"
Write-Host "Domain Controller: $domainController"
Write-Host "Calling Computer : $callingComputer"

if ($failureSources) {
    Write-Host "`nFailed Logon Sources:"
    foreach ($source in $failureSources) {
        Write-Host (" - {0} : {1} attempts" -f $source.Name, $source.Count)
    }
}

Write-Host "`n[+] Analysis complete.`n" -ForegroundColor Cyan
