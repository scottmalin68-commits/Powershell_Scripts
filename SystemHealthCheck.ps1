<#
.SYNOPSIS
    System Health Check Script

.DESCRIPTION
    This PowerShell script performs a comprehensive system health check on local or remote systems. It includes checks for CPU usage, memory usage, disk space, running processes, key registry values, and locating/hashing an endpoint protection client (e.g., Windows Defender). It generates a timestamped report and supports email alerts for thresholds.

    The script is designed to run remotely using Invoke-Command, assuming proper permissions (e.g., WinRM enabled and admin credentials). It uses WMI/CIM for compatibility where possible.

    Goal: The goal of this script is to provide ongoing monitoring of system health, allowing administrators to detect issues early, ensure update readiness (e.g., via disk space checks), and compare changes over time through historical report comparisons.

    Key Features:
    - Threshold-based alerts for CPU, memory, and disk space.
    - Process monitoring (lists top processes by CPU).
    - Registry checks (e.g., for Windows Update settings).
    - Endpoint client location and hash (customizable path).
    - Report generation (TXT or HTML) with dynamic naming: ComputerName-HealthReport-YYYYMMDD-HHMMSS.ext
    - Optional comparison to the previous report for the same computer to highlight differences.
    - Custom checks section for environment-specific additions.

.PARAMETER ComputerName
    The name of the remote computer to check. Defaults to localhost ('.') for local execution.

.PARAMETER Credential
    PSCredential object for remote authentication. If not provided, uses current user credentials.

.PARAMETER ReportDirectory
    Directory to save the report files. Defaults to "C:\SystemHealthReports". Will be created if it doesn't exist.

.PARAMETER EmailFrom
    Sender email for alerts.

.PARAMETER EmailTo
    Recipient email for alerts.

.PARAMETER SmtpServer
    SMTP server for sending emails.

.PARAMETER CpuThreshold
    CPU usage alert threshold (%). Default: 80.

.PARAMETER MemoryThreshold
    Memory usage alert threshold (%). Default: 80.

.PARAMETER DiskThreshold
    Free disk space alert threshold (GB). Default: 20.

.PARAMETER DiskDrive
    Drive to check for disk space. Default: 'C:'.

.PARAMETER EndpointClientPath
    Path to the endpoint client executable for hashing. Default: 'C:\Program Files\Windows Defender\MSASCui.exe' (Windows Defender example).

.PARAMETER OutputFormat
    Report format: 'TXT' or 'HTML'. Default: 'TXT'.

.PARAMETER ComparePrevious
    Switch to compare the current report with the previous one for the same ComputerName and generate a differences report.

.EXAMPLE
    # Basic local run
    .\SystemHealthCheck.ps1

.EXAMPLE
    # Remote run with credentials and email alerts
    .\SystemHealthCheck.ps1 -ComputerName "RemoteServer" -Credential (Get-Credential) -EmailTo "admin@example.com" -SmtpServer "smtp.example.com"

.EXAMPLE
    # Run with comparison to previous report
    .\SystemHealthCheck.ps1 -ComputerName "RemoteServer" -ComparePrevious

.EXAMPLE
    # Custom output format and directory
    .\SystemHealthCheck.ps1 -OutputFormat 'HTML' -ReportDirectory 'D:\Reports'

.NOTES
    Author: Scott M
    Version: 1.0
    Date: January 2026

    Basic Instructions:
    1. Run the script with administrative privileges.
    2. For remote checks, ensure WinRM is enabled on the target: Run 'WinRM quickconfig' on the remote machine.
    3. Provide credentials if checking a remote system without trusted authentication.
    4. Customize thresholds, paths, and email settings via parameters.
    5. Add custom checks in the designated section below.
    6. Reports are saved in the specified directory with timestamped names for historical tracking.
    7. Use -ComparePrevious to generate a diff report if prior reports exist (compares line-by-line changes).
    8. For automation, schedule via Task Scheduler; avoid interactive prompts.

    Limitations: Pure PowerShell—no external tools. Hashing uses Get-FileHash (SHA256). WMI may have firewall issues remotely. Comparisons are simple text diffs; complex changes may need manual review.
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
    [string]$EndpointClientPath = 'C:\Program Files\Windows Defender\MSASCui.exe',
    [ValidateSet('TXT', 'HTML')][string]$OutputFormat = 'TXT',
    [switch]$ComparePrevious
)

# Create report directory if it doesn't exist
if (-not (Test-Path $ReportDirectory)) {
    New-Item -Path $ReportDirectory -ItemType Directory | Out-Null
}

# Generate dynamic report filename
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ext = if ($OutputFormat -eq 'HTML') { 'html' } else { 'txt' }
$ReportPath = Join-Path $ReportDirectory "$ComputerName-HealthReport-$timestamp.$ext"

# Function to run code remotely if ComputerName is not local
function Invoke-Remote {
    param (
        [scriptblock]$ScriptBlock,
        [hashtable]$Arguments = @{}
    )
    if ($ComputerName -eq '.' -or $ComputerName -eq 'localhost') {
        & $ScriptBlock @Arguments
    } else {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $ScriptBlock
            ArgumentList = $Arguments.Values
        }
        if ($Credential) { $params['Credential'] = $Credential }
        Invoke-Command @params
    }
}

# 1. CPU Usage Check
function Check-CPU {
    param ([int]$Threshold)
    $cpuUsage = Invoke-Remote -ScriptBlock {
        param ($Thresh)
        try {
            $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
            "CPU Usage: $cpu%"
            if ($cpu -ge $Thresh) { "ALERT: CPU exceeds threshold!" }
        } catch { "ERROR: $_" }
    } -Arguments @{Thresh = $Threshold}
    return $cpuUsage
}

# 2. Memory Usage Check
function Check-Memory {
    param ([int]$Threshold)
    $memoryUsage = Invoke-Remote -ScriptBlock {
        param ($Thresh)
        try {
            $mem = Get-WmiObject Win32_OperatingSystem
            $totalMem = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 2)
            $freeMem = [math]::Round($mem.FreePhysicalMemory / 1MB, 2)
            $usedPct = [math]::Round((1 - ($freeMem / $totalMem)) * 100, 2)
            "Memory Usage: $usedPct%"
            if ($usedPct -ge $Thresh) { "ALERT: Memory exceeds threshold!" }
        } catch { "ERROR: $_" }
    } -Arguments @{Thresh = $Threshold}
    return $memoryUsage
}

# 3. Disk Space Check (ties into update readiness: low space prevents updates)
function Check-DiskSpace {
    param ([string]$Drive, [int]$Threshold)
    $diskInfo = Invoke-Remote -ScriptBlock {
        param ($Drv, $Thresh)
        try {
            $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$Drv'"
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            "Free Disk Space on $Drv: $freeGB GB"
            if ($freeGB -le $Thresh) { "ALERT: Low disk space! May prevent system updates." }
        } catch { "ERROR: $_" }
    } -Arguments @{Drv = $Drive; Thresh = $Threshold}
    return $diskInfo
}

# 4. Process Check (top 5 by CPU)
function Check-Processes {
    $processes = Invoke-Remote -ScriptBlock {
        try {
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table Id, Name, CPU -AutoSize | Out-String
        } catch { "ERROR: $_" }
    }
    return "Top Processes:`n$processes"
}

# 5. Registry Values Check (example: Windows Update auto-update setting)
function Check-Registry {
    $regValues = Invoke-Remote -ScriptBlock {
        try {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            $value = Get-ItemProperty -Path $key -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue
            if ($value.NoAutoUpdate -eq 1) { "Registry: AutoUpdate disabled." } else { "Registry: AutoUpdate enabled." }
        } catch { "ERROR: $_" }
    }
    return $regValues
}

# 6. Endpoint Client Location and Hash
function Check-EndpointClient {
    param ([string]$Path)
    $endpointInfo = Invoke-Remote -ScriptBlock {
        param ($Pth)
        try {
            if (Test-Path $Pth) {
                $hash = Get-FileHash $Pth -Algorithm SHA256 | Select-Object -ExpandProperty Hash
                "Endpoint Client at $Pth: Hash $hash"
            } else { "WARNING: Endpoint client not found at $Pth." }
        } catch { "ERROR: $_" }
    } -Arguments @{Pth = $Path}
    return $endpointInfo
}

# 7. Send Alert Email
function Send-Alert {
    param ([string]$Subject, [string]$Body)
    try {
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body -SmtpServer $SmtpServer
    } catch { Write-Warning "Email alert failed: $_" }
}

# Custom Checks Section
# INSTRUCTIONS FOR ADMINS:
# This section allows you to add environment-specific checks without modifying the core script.
# 1. Define your custom checks as ScriptBlocks in the $CustomChecks array.
#    - Each ScriptBlock should return a string with the check result (e.g., "Custom Check: Result").
#    - Use try-catch for error handling.
#    - Access script parameters if needed (e.g., $ComputerName), but they are read-only here.
# 2. Examples:
#    - Check a specific service: { Get-Service -Name 'MyService' | Select-Object Status | Out-String }
#    - Query a custom registry key: { Get-ItemProperty -Path 'HKLM:\Path\To\Key' -Name 'Value' | Out-String }
#    - Run a command: { if (Test-Path 'C:\CustomFile.txt') { 'File exists.' } else { 'File missing.' } }
# 3. For remote execution: The ScriptBlocks will be invoked remotely via Invoke-Remote, so write them as if running on the target machine.
# 4. Add as many as needed; they will be executed sequentially and appended to the report.
# 5. To add checks, edit the array below directly in the script file.
# 6. Limitations: Keep ScriptBlocks simple; no external dependencies. Output strings only—no objects for simplicity.
$CustomChecks = @(
    # Add your custom ScriptBlocks here. Example:
    # { "Custom Example: Always passes." }
    # { try { Get-Service -Name 'Spooler' | Select-Object Status | Out-String } catch { "ERROR: $_" } }
)

# Run Custom Checks
function Run-CustomChecks {
    $results = @()
    foreach ($check in $CustomChecks) {
        $result = Invoke-Remote -ScriptBlock $check
        $results += $result
    }
    return $results -join "`n"
}

# Generate Report Content
function Get-ReportContent {
    @"
System Health Report for $ComputerName - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

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

# Generate and Save Report
function Generate-Report {
    $reportContent = Get-ReportContent

    if ($OutputFormat -eq 'HTML') {
        $htmlHeader = '<html><body><h1>System Health Report</h1><pre>'
        $htmlFooter = '</pre></body></html>'
        $reportContent = $htmlHeader + $reportContent.Replace("`n", '<br>') + $htmlFooter
    }

    $reportContent | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Output "Report saved to $ReportPath"

    # Check for alerts in content and send email if any
    if ($reportContent -match 'ALERT|WARNING|ERROR') {
        Send-Alert -Subject "Health Alert for $ComputerName" -Body $reportContent
    }
}

# Compare with Previous Report
function Compare-WithPrevious {
    # Find all reports for this ComputerName, sort descending by filename (timestamp)
    $allReports = Get-ChildItem -Path $ReportDirectory -Filter "$ComputerName-HealthReport-*.$ext" | Sort-Object Name -Descending

    if ($allReports.Count -lt 2) {
        Write-Output "No previous report found for comparison."
        return
    }

    $previousPath = $allReports[1].FullName  # [0] is current, [1] is previous

    $currentContent = Get-Content $ReportPath
    $previousContent = Get-Content $previousPath

    $diff = Compare-Object -ReferenceObject $previousContent -DifferenceObject $currentContent -IncludeEqual:$false

    $diffReportPath = Join-Path $ReportDirectory "$ComputerName-HealthDiff-$timestamp.$ext"
    $diffContent = "Differences between $previousPath and $ReportPath:`n`n"

    foreach ($item in $diff) {
        $side = if ($item.SideIndicator -eq '=>') { 'Current' } else { 'Previous' }
        $diffContent += "$side: $($item.InputObject)`n"
    }

    if ($OutputFormat -eq 'HTML') {
        $htmlHeader = '<html><body><h1>Health Differences Report</h1><pre>'
        $htmlFooter = '</pre></body></html>'
        $diffContent = $htmlHeader + $diffContent.Replace("`n", '<br>') + $htmlFooter
    }

    $diffContent | Out-File -FilePath $diffReportPath -Encoding UTF8
    Write-Output "Differences report saved to $diffReportPath"
}

# Main Execution
Write-Output "Starting health check on $ComputerName..."
Generate-Report
if ($ComparePrevious) {
    Compare-WithPrevious
}
Write-Output "Health check complete."