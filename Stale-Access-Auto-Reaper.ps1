<#
================================================================================
 Script Name : Stale-Access-Auto-Reaper.ps1
 Author      : Scott Malin, CISSP
 Version     : 1.2.0
================================================================================

 GOAL
 ----
 Automatically reduce endpoint attack surface by identifying and remediating
 stale privileged access while respecting authority boundaries and system risk.

 The script disables unused LOCAL administrator accounts automatically,
 flags DOMAIN accounts for review, and pauses remediation on high-risk systems.

================================================================================
 INSTRUCTIONS
 ------------
 LOCAL:
   .\Stale-Access-Auto-Reaper.ps1

 REMOTE:
   .\Stale-Access-Auto-Reaper.ps1 -ComputerName HOSTNAME

 Optional Parameters:
   -StaleDays : Inactivity threshold (default: 90 days)
   -WhatIf    : Detection-only mode (no remediation)

 Requirements:
 - Administrator privileges
 - PowerShell Remoting enabled for remote execution

================================================================================
 AUTOMATION PRINCIPLES
 ---------------------
 - Never delete access automatically
 - Never modify domain identities
 - Never remediate high-risk systems without approval
 - Always log decisions, not just actions

================================================================================
 CHANGELOG
 ---------
 1.2.0
  - Fixed $null evaluation on $User.LastLogon preventing accidental disables
  - Replaced PS7 ternary operators with PS5.1 compatible conditional blocks
  - Protected built-in Administrator (SID *-500) from automated remediation
  - Added CmdletBinding support for native ShouldProcess behavior
 1.1.0
  - Added domain account handling (read-only)
  - Added high-risk system approval gate
  - Added central logging payload
  - Added confidence scoring
  - Hardened remote execution behavior

================================================================================
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$ComputerName = $env:COMPUTERNAME,
    [int]$StaleDays = 90,
    [switch]$WhatIf
)

# -------------------------------------------------------------------
# Execution Context
# -------------------------------------------------------------------
$IsRemote        = $ComputerName -ne $env:COMPUTERNAME
$CutoffDate      = (Get-Date).AddDays(-$StaleDays)
$ConfidenceScore = 100

if ($IsRemote) { $ConfidenceScore -= 20 }

# -------------------------------------------------------------------
# ScriptBlock (Local or Remote)
# -------------------------------------------------------------------
$SessionBlock = {
    param($CutoffDate, $WhatIf)

    $Result = @{
        DisabledLocalAdmins = @()
        DomainAdminsFound   = @()
        HighRiskDetected    = $false
        Warnings            = @()
    }

    # --------------------------------------------------------------
    # High-Risk System Classification
    # --------------------------------------------------------------
    try {
        $Role = Get-ItemProperty `
            -Path "HKLM:\Software\Company\SystemRole" `
            -ErrorAction Stop

        if ($Role.Role -in @("DomainController","SQL","EMR","Payment")) {
            $Result.HighRiskDetected = $true
            return $Result
        }
    } catch {
        # No role defined = normal system
    }

    # --------------------------------------------------------------
    # Enumerate Local Administrators
    # --------------------------------------------------------------
    try {
        $Admins = Get-LocalGroupMember Administrators |
            Where-Object { $_.ObjectClass -eq 'User' }

        foreach ($Admin in $Admins) {

            # DOMAIN ACCOUNT -> FLAG ONLY
            if ($Admin.Name -match "\\") {
                $Result.DomainAdminsFound += $Admin.Name
                continue
            }

            # LOCAL ACCOUNT -> EVALUATE
            $User = Get-LocalUser -Name $Admin.Name -ErrorAction SilentlyContinue
            if (-not $User) { continue }

            # SAFEGUARD: Skip built-in local Administrator account (SID ending in -500)
            if ($User.SID.Value -like "*-500") {
                continue
            }

            # SAFEGUARD: Validate LastLogon is not $null before date comparison
            if ($User.Enabled -and $null -ne $User.LastLogon -and $User.LastLogon -lt $CutoffDate) {
                if ($WhatIf) {
                    $Result.Warnings += "WHATIF: Would disable local admin [$($User.Name)]"
                } else {
                    Disable-LocalUser -Name $User.Name -ErrorAction Stop
                    $Result.DisabledLocalAdmins += $User.Name
                }
            }
        }
    } catch {
        $Result.Warnings += "Failed to enumerate or process local administrators: $_"
    }

    return $Result
}

# -------------------------------------------------------------------
# Execute
# -------------------------------------------------------------------
if ($IsRemote) {
    $Result = Invoke-Command `
        -ComputerName $ComputerName `
        -ScriptBlock $SessionBlock `
        -ArgumentList $CutoffDate, $WhatIf
} else {
    $Result = & $SessionBlock $CutoffDate $WhatIf
}

# -------------------------------------------------------------------
# Confidence Adjustments
# -------------------------------------------------------------------
if ($Result.Warnings.Count -gt 0)     { $ConfidenceScore -= 10 }
if ($Result.HighRiskDetected)         { $ConfidenceScore -= 30 }
if ($Result.DomainAdminsFound.Count)  { $ConfidenceScore -= 5 }

# PS 5.1 Compatible Conditional Syntax
$ExecModeText = if ($IsRemote) { "REMOTE" } else { "LOCAL" }

# -------------------------------------------------------------------
# Decision Logging Payload (Central SIEM Ready)
# -------------------------------------------------------------------
$LogEvent = @{
    Script        = "Stale-Access-Auto-Reaper"
    Version       = "1.2.0"
    ComputerName  = $ComputerName
    Timestamp     = (Get-Date).ToString("o")
    ExecutionMode = $ExecModeText
    WhatIf        = [bool]$WhatIf
    Confidence    = $ConfidenceScore
    Result        = $Result
}

# -------------------------------------------------------------------
# Output
# -------------------------------------------------------------------
Write-Host "`n================ STALE ACCESS AUTO-REAPER ================" -ForegroundColor Yellow
Write-Host "Target System : $ComputerName"
Write-Host "Execution     : " -NoNewline
Write-Host $ExecModeText -ForegroundColor Cyan
Write-Host "Confidence    : $ConfidenceScore%"

if ($Result.HighRiskDetected) {
    Write-Host "`n[!] High-risk system detected. No remediation performed." -ForegroundColor Red
}

Write-Host "`n--- Disabled Local Admin Accounts ---" -ForegroundColor Cyan
if ($Result.DisabledLocalAdmins.Count -eq 0) {
    Write-Host "None"
} else {
    $Result.DisabledLocalAdmins | ForEach-Object { Write-Host "- $_" }
}

Write-Host "`n--- Domain Admin Accounts (Review Required) ---" -ForegroundColor Cyan
if ($Result.DomainAdminsFound.Count -eq 0) {
    Write-Host "None"
} else {
    $Result.DomainAdminsFound | ForEach-Object { Write-Host "- $_" }
}

if ($Result.Warnings.Count -gt 0) {
    Write-Host "`n--- Warnings ---" -ForegroundColor DarkYellow
    $Result.Warnings | ForEach-Object { Write-Host "- $_" }
}

Write-Host "`n[+] Execution complete.`n"