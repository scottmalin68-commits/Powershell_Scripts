<#
================================================================================
 Script Name : Why-Is-This-Machine-Slow.ps1
 Author      : Scott M (with improvements)
 Version     : 1.2.0
================================================================================
 GOAL
 ----
 Quickly identify likely causes of performance degradation on Windows machines.
 Supports local and remote execution with clear limitation warnings.
================================================================================
 CHANGELOG (from 1.1.0)
 ---------
 1.2.0
  - Fixed CPU metric: now uses % Processor Time instead of lifetime seconds
  - Fixed disk I/O: now uses IO Data Bytes/sec (rate) with sampling
  - Improved Defender status check (more properties)
  - Expanded recent human activity detection (more event IDs, time-based)
  - Added disk queue length and paging rate checks
  - Better output formatting with tables
  - Basic error handling for remote invocation
================================================================================
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int]$SampleIntervalSec = 5,   # Time between perf samples (local only)

    [Parameter()]
    [int]$SampleCount = 2          # Number of samples to average (local only)
)

$IsRemote = $ComputerName -ne $env:COMPUTERNAME
$ConfidenceScore = 100
$Findings = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()

Write-Host "`n[+] Target: $ComputerName" -ForegroundColor Cyan
Write-Host "[+] Mode:   " -NoNewline
Write-Host $(if ($IsRemote) { "REMOTE" } else { "LOCAL" }) -ForegroundColor $(if ($IsRemote) { "Yellow" } else { "Green" })

if ($IsRemote) {
    $ConfidenceScore -= 25
    $Warnings.Add("Remote mode: reduced sampling accuracy, no real-time loop, limited session info")
}

# =============================================================================
# Data Collection Block (runs locally or via Invoke-Command)
# =============================================================================
$Session = {
    param($IsRemote, $SampleIntervalSec, $SampleCount)

    $ErrorActionPreference = 'SilentlyContinue'

    # -------------------------------------------------------------------------
    # CPU - % Processor Time (much better than lifetime seconds)
    # -------------------------------------------------------------------------
    $cpuCounter = '\Process(*)\% Processor Time'
    $topCpu = @()
    try {
        if (-not $IsRemote -and $SampleCount -gt 1) {
            $samples = Get-Counter $cpuCounter -SampleInterval $SampleIntervalSec -MaxSamples $SampleCount
            $avg = $samples.CounterSamples | Group-Object InstanceName | ForEach-Object {
                $sum = ($_.Group | Measure-Object CookedValue -Sum).Sum
                [pscustomobject]@{
                    InstanceName = $_.Name
                    AvgPercent   = [math]::Round($sum / $_.Count / $env:NUMBER_OF_PROCESSORS, 1)
                }
            }
            $topCpu = $avg | Where-Object InstanceName -notin '_total','idle' |
                      Sort-Object AvgPercent -Descending | Select-Object -First 5
        } else {
            # Single snapshot (remote or quick local)
            $snapshot = Get-Counter $cpuCounter
            $topCpu = $snapshot.CounterSamples | Where-Object InstanceName -notin '_total','idle' |
                      Sort-Object CookedValue -Descending | Select-Object -First 5 @{
                          Name='Process'; Expression={$_.InstanceName}
                          Name='CPU%';    Expression={[math]::Round($_.CookedValue / $env:NUMBER_OF_PROCESSORS, 1)}
                      }
        }
    } catch {
        $topCpu = "Error collecting CPU data"
    }

    # -------------------------------------------------------------------------
    # Disk I/O rate (bytes/sec)
    # -------------------------------------------------------------------------
    $ioCounters = '\Process(*)\IO Data Bytes/sec'
    $topDiskIo = @()
    try {
        if (-not $IsRemote -and $SampleCount -gt 1) {
            $samples = Get-Counter $ioCounters -SampleInterval $SampleIntervalSec -MaxSamples $SampleCount
            $avgIo = $samples.CounterSamples | Group-Object InstanceName | ForEach-Object {
                $sum = ($_.Group | Measure-Object CookedValue -Sum).Sum
                [pscustomobject]@{
                    InstanceName = $_.Name
                    AvgBytesSec  = [math]::Round($sum / $_.Count, 0)
                }
            }
            $topDiskIo = $avgIo | Where-Object InstanceName -notin '_total','idle' |
                         Sort-Object AvgBytesSec -Descending | Select-Object -First 5
        } else {
            $snapshot = Get-Counter $ioCounters
            $topDiskIo = $snapshot.CounterSamples | Where-Object InstanceName -notin '_total','idle' |
                         Sort-Object CookedValue -Descending | Select-Object -First 5 @{
                             Name='Process';     Expression={$_.InstanceName}
                             Name='IO Bytes/sec';Expression={[math]::Round($_.CookedValue, 0)}
                         }
        }
    } catch {
        $topDiskIo = "Error collecting disk I/O data"
    }

    # -------------------------------------------------------------------------
    # Physical Disk Queue Length (important for storage bottleneck)
    # -------------------------------------------------------------------------
    $diskQueue = "Unknown"
    try {
        $q = Get-Counter '\PhysicalDisk(_Total)\Avg. Disk Queue Length' -ErrorAction Stop
        $diskQueue = [math]::Round($q.CounterSamples.CookedValue, 2)
    } catch {}

    # -------------------------------------------------------------------------
    # Memory & Paging
    # -------------------------------------------------------------------------
    $mem = Get-CimInstance Win32_OperatingSystem
    $memUsedPct = [math]::Round( (100 - ($mem.FreePhysicalMemory / $mem.TotalVisibleMemorySize * 100)), 1)

    $pagesSec = "Unknown"
    try {
        $p = Get-Counter '\Memory\Pages/sec'
        $pagesSec = [math]::Round($p.CounterSamples.CookedValue, 1)
    } catch {}

    # -------------------------------------------------------------------------
    # Windows Defender
    # -------------------------------------------------------------------------
    $defenderStatus = "Unknown"
    try {
        $mp = Get-MpComputerStatus
        $defenderStatus = [ordered]@{
            Enabled           = $mp.AntivirusEnabled
            RealTime          = $mp.RealTimeProtectionEnabled
            FullScanRunning   = $mp.FullScanRunning
            QuickScanRunning  = $mp.QuickScanRunning
            BehaviorEnabled   = $mp.BehaviorMonitorEnabled
            IOAVEnabled       = $mp.IoavProtectionEnabled
            LastUpdate        = $mp.AntivirusSignatureLastUpdated
        }
    } catch {
        $defenderStatus = "Access denied or module not available"
    }

    # -------------------------------------------------------------------------
    # Windows Update service
    # -------------------------------------------------------------------------
    $wuRunning = $false
    try {
        $wuRunning = (Get-Service wuauserv -ErrorAction Stop).Status -eq 'Running'
    } catch {}

    # -------------------------------------------------------------------------
    # Logged-on users (best effort)
    # -------------------------------------------------------------------------
    $users = try { quser 2>$null } catch { "quser failed" }

    # -------------------------------------------------------------------------
    # Recent human / admin activity (last 30 min)
    # -------------------------------------------------------------------------
    $humanActivityCount = 0
    try {
        $startTime = (Get-Date).AddMinutes(-30)
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4624,4634,4647,4648,4672,4688,4800,4801,5140
            StartTime = $startTime
        } -MaxEvents 300 -ErrorAction Stop
        $humanActivityCount = $events.Count
    } catch {
        $humanActivityCount = "Event log access failed"
    }

    # Return structured data
    return @{
        TopCpu          = $topCpu
        TopDiskIo       = $topDiskIo
        DiskQueue       = $diskQueue
        MemoryUsedPct   = $memUsedPct
        PagesPerSec     = $pagesSec
        Defender        = $defenderStatus
        WindowsUpdate   = $wuRunning
        LoggedOnUsers   = $users
        RecentActivity  = $humanActivityCount
    }
}

# =============================================================================
# Execute collection
# =============================================================================
try {
    if ($IsRemote) {
        $Data = Invoke-Command -ComputerName $ComputerName -ScriptBlock $Session -ArgumentList $IsRemote, $SampleIntervalSec, $SampleCount -ErrorAction Stop
    } else {
        $Data = & $Session -IsRemote $IsRemote -SampleIntervalSec $SampleIntervalSec -SampleCount $SampleCount
    }
} catch {
    Write-Host "ERROR: Failed to collect data from $ComputerName" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

# =============================================================================
# Analysis & Findings
# =============================================================================
if ($Data.TopCpu -is [array] -and $Data.TopCpu.Count -gt 0) {
    $topProc = $Data.TopCpu[0]
    if ($topProc.CPU% -gt 70 -or $topProc.AvgPercent -gt 70) {
        $Findings.Add("High CPU usage detected (Top: $($topProc.Process ?? $topProc.Name) @ ~$($topProc.CPU% ?? $topProc.AvgPercent)% )")
    }
}

if ($Data.TopDiskIo -is [array] -and $Data.TopDiskIo.Count -gt 0) {
    $topIo = $Data.TopDiskIo[0]
    if (($topIo.'IO Bytes/sec' -gt 20MB) -or ($topIo.AvgBytesSec -gt 20MB)) {
        $Findings.Add("Heavy disk I/O (Top: $($topIo.Process ?? $topIo.Name) @ ~$([math]::Round(($topIo.'IO Bytes/sec' ?? $topIo.AvgBytesSec')/1MB,1)) MB/s)")
    }
}

if ($Data.DiskQueue -is [double] -and $Data.DiskQueue -gt 2.0) {
    $Findings.Add("Disk queue length high ($($Data.DiskQueue)) → storage bottleneck likely")
}

if ($Data.MemoryUsedPct -gt 88) {
    $Findings.Add("High memory usage ($($Data.MemoryUsedPct)% used)")
}

if ($Data.PagesPerSec -is [double] -and $Data.PagesPerSec -gt 50) {
    $Findings.Add("Excessive paging ($($Data.PagesPerSec) pages/sec) → possible memory pressure")
}

if ($Data.Defender -is [object] -and ($Data.Defender.FullScanRunning -or $Data.Defender.QuickScanRunning)) {
    $Findings.Add("Windows Defender scan in progress")
}

if ($Data.WindowsUpdate) {
    $Findings.Add("Windows Update service is currently running")
}

if ($Data.RecentActivity -is [int] -and $Data.RecentActivity -gt 15) {
    $Findings.Add("Significant recent user/admin activity detected ($($Data.RecentActivity) relevant events in last 30 min)")
}

# Confidence adjustments
if ($Data.Defender -eq "Unknown" -or $Data.Defender -like "*denied*") { $ConfidenceScore -= 15 }
if ($Data.DiskQueue -eq "Unknown") { $ConfidenceScore -= 10 }
if ($Data.PagesPerSec -eq "Unknown") { $ConfidenceScore -= 5 }

# =============================================================================
# Output
# =============================================================================
Write-Host "`n================= ANALYSIS RESULTS =================" -ForegroundColor Yellow
Write-Host "Confidence Score    : $ConfidenceScore%" -ForegroundColor $(if ($ConfidenceScore -ge 80) {"Green"} elseif ($ConfidenceScore -ge 50) {"Yellow"} else {"Red"})
Write-Host ""

Write-Host "--- Top CPU Consumers ---" -ForegroundColor Cyan
if ($Data.TopCpu -is [array]) { $Data.TopCpu | Format-Table -AutoSize }
else { Write-Host $Data.TopCpu -ForegroundColor DarkGray }

Write-Host "`n--- Top Disk I/O Consumers ---" -ForegroundColor Cyan
if ($Data.TopDiskIo -is [array]) { $Data.TopDiskIo | Format-Table -AutoSize }
else { Write-Host $Data.TopDiskIo -ForegroundColor DarkGray }

Write-Host "`n--- Key Indicators ---" -ForegroundColor Cyan
"Disk Queue Length     : $($Data.DiskQueue)"
"Memory Used           : $($Data.MemoryUsedPct)%"
"Pages/sec             : $($Data.PagesPerSec)"
"Recent Security Events: $($Data.RecentActivity)"
"Windows Update Active : $($Data.WindowsUpdate)"
"" | Write-Host

if ($Data.Defender -is [object]) {
    Write-Host "--- Defender Status ---" -ForegroundColor Cyan
    $Data.Defender | Format-Table -AutoSize
}

Write-Host "`n--- Root Cause Summary ---" -ForegroundColor Green
if ($Findings.Count -eq 0) {
    Write-Host "No clear performance bottleneck identified in this snapshot." -ForegroundColor DarkGreen
} else {
    $Findings | ForEach-Object { Write-Host "• $_" }
}

if ($Warnings.Count -gt 0) {
    Write-Host "`nWarnings:" -ForegroundColor Yellow
    $Warnings | ForEach-Object { Write-Host "⚠ $_" }
}

Write-Host "`n[+] Analysis complete." -ForegroundColor Cyan