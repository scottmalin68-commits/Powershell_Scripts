<#
===============================================================================
Title:      Why-WasAccountLocked.ps1
Author:     Scott Malin, CISSP
Version:    1.1.0
Date:       2026-08-25

GOAL
----
Analyze Active Directory account lockout events across domain controllers and
produce a clear explanation of WHY a user account was locked, WHEN it happened,
and FROM WHERE the lockout originated.

INSTRUCTIONS
------------
1. Run this script from a domain-joined machine with permission to read:
   - Remote Security Event Logs across DCs
   - Active Directory module installed (Get-ADDomainController)
2. PowerShell 5.1+ required
3. Run as Administrator with Domain Admin or delegated Event Log Readers rights
4. Provide a username when prompted

OUTPUT
------
- Lockout time
- Originating computer/workstation
- Domain controller that processed the event
- Consolidated failed logon statistics across DCs

CHANGELOG
---------
1.1.0 - 2026-08-25
        - Replaced hardcoded array property indexes with robust XML node parsing.
        - Added multi-DC discovery via Get-ADDomainController to scan all DCs.
        - Fixed missing log issues where 4740/4625 events occur remote to local host.
        - Added case-insensitive username matching.
1.0.0 - Initial release
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

Write-Host "`n[+] Discovering Domain Controllers and searching logs for: $Username`n" -ForegroundColor Cyan

# ----------------------------
# DC DISCOVERY
# ----------------------------
try {
    $DCs = (Get-ADDomainController -Filter *).HostName
} catch {
    Write-Host "[-] Failed to query Active Directory for Domain Controllers. Ensure RSAT/AD module is installed." -ForegroundColor Red
    return
}

$lockoutEvents = @()

# ----------------------------
# COLLECT 4740 LOCKOUT EVENTS
# ----------------------------
foreach ($dc in $DCs) {
    try {
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName = 'Security'
            Id      = 4740
        } -ErrorAction Stop

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $dataNodes = $xml.Event.EventData.Data
            
            $targetUser = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            
            if ($targetUser -and ($targetUser.ToLower() -eq $Username.ToLower())) {
                $caller = ($dataNodes | Where-Object { $_.Name -eq 'TargetDomainName' -or $_.Name -eq 'SubjectUserName' }).'#text'
                $callingComp = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' -or $_.Name -eq 'WorkstationName' -or $_.Name -eq 'SubjectMachineName' }).'#text'
                
                # Extract caller workstation specifically from EventData
                $workstationNode = ($dataNodes | Where-Object { $_.Name -eq 'CallerComputerName' -or $_.Name -eq 'WorkstationName' }).'#text'

                $lockoutEvents += [PSCustomObject]@{
                    TimeCreated     = $event.TimeCreated
                    DomainController= $dc
                    TargetUser      = $targetUser
                    CallingComputer = $workstationNode
                }
            }
        }
    } catch {
        # Skip unreachable DCs or DCs with no 4740 events
    }
}

if (-not $lockoutEvents) {
    Write-Host "[-] No lockout events found for '$Username' across any reachable DC." -ForegroundColor Yellow
    return
}

# Get most recent lockout event
$latestLockout = $lockoutEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1

$lockoutTime      = $latestLockout.TimeCreated
$callingComputer  = $latestLockout.CallingComputer
$domainController = $latestLockout.DomainController

# ----------------------------
# COLLECT 4625 FAILED LOGONS
# ----------------------------
$failedLogons = @()

foreach ($dc in $DCs) {
    try {
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $lockoutTime.AddMinutes(-30)
            EndTime   = $lockoutTime
        } -ErrorAction Stop

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $dataNodes = $xml.Event.EventData.Data
            
            $targetUser = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            
            if ($targetUser -and ($targetUser.ToLower() -eq $Username.ToLower())) {
                $workstation = ($dataNodes | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                $ipAddress   = ($dataNodes | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                
                $source = if ($workstation -and $workstation -ne '-') { $workstation } else { $ipAddress }
                
                $failedLogons += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    Source      = $source
                    DC          = $dc
                }
            }
        }
    } catch {
        # Skip DC logging errors
    }
}

# Group failed logons by source
$failureSources = $failedLogons | Group-Object Source | Sort-Object Count -Descending

# ----------------------------
# BUILD EXPLANATION
# ----------------------------
$explanation = @()
$explanation += "Account '$Username' was locked out on $lockoutTime."
$explanation += "Processed by Domain Controller '$domainController'."

if ($callingComputer -and $callingComputer -ne '-') {
    $explanation += "The lockout request originated from workstation '$callingComputer'."
}

if ($failureSources) {
    $topSource = $failureSources[0].Name
    $attempts  = $failureSources[0].Count
    $explanation += "Most failed authentication attempts came from '$topSource' ($attempts attempts)."
}

$explanation += "`nCommon root causes:"
$explanation += "- Stored credentials on a workstation or server (Credential Manager)"
$explanation += "- Service accounts or scheduled tasks running with old passwords"
$explanation += "- Mobile devices, Wi-Fi connections, or VPN clients using cached tokens"

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
    Write-Host "`nFailed Logon Sources (30 min window):"
    foreach ($source in $failureSources) {
        Write-Host (" - {0} : {1} attempts" -f $source.Name, $source.Count)
    }
}

Write-Host "`n[+] Analysis complete.`n" -ForegroundColor Cyan