<#
.SYNOPSIS
    System Health Check Script

.DESCRIPTION
    Performs a system health check on local or remote systems (CPU, Memory, Disk, Processes, Registry, Defender Hash).
    Generates reports and alerts on metric failures.

.NOTES
    Author: Scott Malin, CISSP
    Version: 1.1.0
#>

param (
    [string]$ComputerName = '.',
    [PSCredential]$Credential,
    [string]$ReportDirectory = "C:\SystemHealthReports",
    [string]$EmailFrom = "monitoring@example.com",
    [string]$EmailTo = "admin@example.com",
    [string]$SmtpServer = "smtp.example.com",
    [int]$CpuThreshold = 80,
    [int]$MemoryThreshold = 80,
    [int]$DiskThreshold = 20,
    [string]$DiskDrive = 'C:',
    [string]$EndpointClientPath = 'C:\Program Files\Windows Defender\MsMpEng.exe',
    [ValidateSet('TXT', 'HTML')][string]$OutputFormat = 'TXT',
    [switch]$ComparePrevious
)

# Create report directory if missing
if (-not (Test-Path $ReportDirectory)) {
    New-Item -Path $ReportDirectory -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ext = if ($OutputFormat -eq 'HTML') { 'html' } else { 'txt' }
$ReportPath = Join-Path $ReportDirectory "$ComputerName-HealthReport-$timestamp.$ext"

# Updated remote executor with named argument support
function Invoke-Remote {
    param (
        [scriptblock]$ScriptBlock,
        [array]$ArgumentList = @()
    )
    if ($ComputerName -eq '.' -or $ComputerName -eq 'localhost') {
        & $ScriptBlock @ArgumentList
    } else {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $ScriptBlock
            ArgumentList = $ArgumentList
        }
        if ($Credential) { $params['Credential'] = $Credential }
        Invoke-Command @params
    }
}

# 1. CPU Usage (CIM based)
function Check-CPU {
    param ([int]$Threshold)
    Invoke-Remote -ScriptBlock {
        param ($Thresh)
        try {
            $cpuList = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty LoadPercentage
            $cpu = ($cpuList | Measure-Object -Average).Average
            $res = "CPU Usage: $cpu%"
            if ($cpu -ge $Thresh) { $res += "`nALERT: CPU exceeds threshold!" }
            return $res
        } catch { return "ERROR: $_" }
    } -ArgumentList $Threshold
}

# 2. Memory Usage (CIM based)
function Check-Memory {
    param ([int]$Threshold)
    Invoke-Remote -ScriptBlock {
        param ($Thresh)
        try {
            $mem = Get-CimInstance -ClassName Win32_OperatingSystem
            $totalMem = [math]::Round($mem.TotalVisibleMemorySize / 1KB, 2) # CIM reports in KB
            $freeMem = [math]::Round($mem.FreePhysicalMemory / 1KB, 2)
            $usedPct = [math]::Round((1 - ($freeMem / $totalMem)) * 100, 2)
            $res = "Memory Usage: $usedPct%"
            if ($usedPct -ge $Thresh) { $res += "`nALERT: Memory exceeds threshold!" }
            return $res
        } catch { return "ERROR: $_" }
    } -ArgumentList $Threshold
}

# 3. Disk Space Check
function Check-DiskSpace {
    param ([string]$Drive, [int]$Threshold)
    Invoke-Remote -ScriptBlock {
        param ($Drv, $Thresh)
        try {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drv'"
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $res = "Free Disk Space on $Drv : $freeGB GB"
            if ($freeGB -le $Thresh) { $res += "`nALERT: Low disk space! May prevent system updates." }
            return $res
        } catch { return "ERROR: $_" }
    } -ArgumentList $Drive, $Threshold
}

# 4. Top 5 CPU Processes
function Check-Processes {
    Invoke-Remote -ScriptBlock {
        try {
            $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Id, ProcessName, CPU | Out-String
            return "Top Processes:`n$procs"
        } catch { return "ERROR: $_" }
    }
}

# 5. Registry Check
function Check-Registry {
    Invoke-Remote -ScriptBlock {
        try {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            if (Test-Path $key) {
                $val = (Get-ItemProperty -Path $key -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate
                if ($val -eq 1) { return "Registry: AutoUpdate disabled." }
            }
            return "Registry: AutoUpdate enabled (or default settings)."
        } catch { return "ERROR: $_" }
    }
}

# 6. Endpoint Client Location & Hash
function Check-EndpointClient {
    param ([string]$Path)
    Invoke-Remote -ScriptBlock {
        param ($Pth)
        try {
            if (Test-Path $Pth) {
                $hash = (Get-FileHash -Path $Pth -Algorithm SHA256).Hash
                return "Endpoint Client ($Pth) SHA256: $hash"
            } else { return "WARNING: Endpoint client not found at $Pth." }
        } catch { return "ERROR: $_" }
    } -ArgumentList $Path
}

# 7. Modernized Email Alert (.NET native to avoid Send-MailMessage deprecation)
function Send-Alert {
    param ([string]$Subject, [string]$Body)
    try {
        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer)
        $msg = New-Object System.Net.Mail.MailMessage($EmailFrom, $EmailTo, $Subject, $Body)
        $smtp.Send($msg)
    } catch { Write-Warning "Email alert failed: $_" }
}

# Custom Checks Placeholder
$CustomChecks = @(
    # { try { (Get-Service -Name 'Spooler').Status } catch { "ERROR: $_" } }
)

function Run-CustomChecks {
    $results = @()
    foreach ($check in $CustomChecks) {
        $results += Invoke-Remote -ScriptBlock $check
    }
    return $results -join "`n"
}

# Report Generator
function Get-ReportContent {
    @"
System Health Report for $ComputerName - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
--------------------------------------------------------------------------------
$(Check-CPU -Threshold $CpuThreshold)
$(Check-Memory -Threshold $MemoryThreshold)
$(Check-DiskSpace -Drive $DiskDrive -Threshold $DiskThreshold)

$(Check-Processes)
$(Check-Registry)
$(Check-EndpointClient -Path $EndpointClientPath)

Custom Checks:
$(Run-CustomChecks)
"@
}

# Main Execution Flow
Write-Output "Starting health check on $ComputerName..."
$reportContent = Get-ReportContent

if ($OutputFormat -eq 'HTML') {
    $htmlHeader = '<html><body style="font-family:monospace;"><h1>System Health Report</h1><pre>'
    $htmlFooter = '</pre></body></html>'
    $reportContent = $htmlHeader + $reportContent + $htmlFooter
}

$reportContent | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Output "Report saved to $ReportPath"

if ($reportContent -match 'ALERT|WARNING|ERROR') {
    Send-Alert -Subject "Health Alert for $ComputerName" -Body $reportContent
}

if ($ComparePrevious) {
    $allReports = Get-ChildItem -Path $ReportDirectory -Filter "$ComputerName-HealthReport-*.$ext" | Sort-Object Name -Descending
    if ($allReports.Count -ge 2) {
        $previousPath = $allReports[1].FullName
        $diff = Compare-Object -ReferenceObject (Get-Content $previousPath) -DifferenceObject (Get-Content $ReportPath) -IncludeEqual:$false
        
        $diffReportPath = Join-Path $ReportDirectory "$ComputerName-HealthDiff-$timestamp.$ext"
        $diffText = ($diff | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join "`n"
        
        "Differences between $previousPath and $ReportPath:`n`n$diffText" | Out-File -FilePath $diffReportPath -Encoding UTF8
        Write-Output "Differences report saved to $diffReportPath"
    } else {
        Write-Output "No previous report found for comparison."
    }
}

Write-Output "Health check complete."