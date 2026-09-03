<#
.SYNOPSIS
    Lightweight, native PowerShell tool for hunting suspicious processes and network connections.
    Designed as an EDR-style demo showcasing cybersecurity monitoring and automation.

.DESCRIPTION
    This script enumerates running processes and established TCP connections, applies anomaly detection rules,
    computes file hashes, queries VirusTotal (for flagged items only), compares against a known-good baseline, 
    and generates reports (CSV + styled HTML). Supports optional process termination and quarantining.

.PARAMETER LogPath
    Path prefix for exported CSV log files.

.PARAMETER ReportPath
    Path to the generated HTML report.

.PARAMETER QuarantinePath
    Directory where flagged executables will be moved if -Quarantine is used.

.PARAMETER Quarantine
    If specified, stops flagged processes and moves their executables to quarantine.

.PARAMETER VtApiKey
    VirusTotal API key for querying flagged process hashes.

.PARAMETER SendEmail
    Enables email alerts if suspicious items are found.

.PARAMETER SmtpServer
    SMTP server hostname for email alerts.

.PARAMETER SmtpPort
    SMTP server port. Defaults to 587.

.PARAMETER EmailTo
    Recipient address for alerts.

.PARAMETER EmailFrom
    Sender address for alerts.

.PARAMETER SmtpCredential
    PSCredential object for SMTP authentication.

.PARAMETER BaselineJson
    Path to JSON file containing known-good {Path: Hash} pairs for baseline comparison.

.PARAMETER GenerateBaseline
    Generates/updates baseline JSON from current clean run.

.NOTES
    Author:     Scott Malin, CISSP
    Version:    1.3.0
    Created:    January 2026
    Requires:   PowerShell 5.1+
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$LogPath = ".\HuntLog_$(Get-Date -Format yyyyMMdd_HHmm)",
    [string]$ReportPath = ".\HuntReport_$(Get-Date -Format yyyyMMdd_HHmm).html",
    [string]$QuarantinePath = "$env:USERPROFILE\Desktop\Quarantine",
    [switch]$Quarantine,
    [string]$VtApiKey,
    [switch]$SendEmail,
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [string]$EmailTo,
    [string]$EmailFrom,
    [PSCredential]$SmtpCredential,
    [string]$BaselineJson = ".\KnownGoodBaseline.json",
    [switch]$GenerateBaseline
)

# Start transcript logging
Start-Transcript -Path ".\HuntTranscript_$(Get-Date -Format yyyyMMdd_HHmm).txt" -Append -Force

Write-Host "Suspicious Process/Network Hunter v1.3 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "Goal: Demonstrate defensive security automation & threat hunting" -ForegroundColor DarkCyan

# ────────────────────────────────────────────────────────────────────────────────
# Quarantine setup
if ($Quarantine -and -not (Test-Path $QuarantinePath)) {
    New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null
    Write-Host "Created quarantine folder: $QuarantinePath" -ForegroundColor DarkYellow
}

# ────────────────────────────────────────────────────────────────────────────────
# Baseline handling (Map Path -> Hash)
$baseline = @{}
if (Test-Path $BaselineJson) {
    try {
        $rawBaseline = Get-Content $BaselineJson -Raw | ConvertFrom-Json
        $rawBaseline.psobject.properties | ForEach-Object { $baseline[$_.Name] = $_.Value }
        Write-Host "Loaded baseline ($($baseline.Count) entries): $BaselineJson" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to parse baseline file: $($_.Exception.Message)"
    }
} elseif ($GenerateBaseline) {
    Write-Host "No baseline found -> will generate new baseline at end" -ForegroundColor Yellow
}

# ────────────────────────────────────────────────────────────────────────────────
# Process collection & parent resolution
$allCimProcs = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
$procMap = @{}
foreach ($cp in $allCimProcs) { $procMap[$cp.ProcessId] = $cp }

$processes = $allCimProcs | Where-Object { $_.ExecutablePath } | ForEach-Object {
    $proc = $_
    $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
    
    # Resolve parent process name via CIM map instead of Get-Process
    $parentName = "N/A"
    $parentPath = "N/A"
    if ($procMap.ContainsKey($proc.ParentProcessId)) {
        $parentName = $procMap[$proc.ParentProcessId].Name
        $parentPath = $procMap[$proc.ParentProcessId].ExecutablePath
    }

    $path = $proc.ExecutablePath
    $hash = if (Test-Path $path) { (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }

    $ownerString = if ($owner -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }

    [PSCustomObject]@{
        PID         = $proc.ProcessId
        Name        = $proc.Name
        Path        = $path
        Hash        = $hash
        CommandLine = $proc.CommandLine
        ParentPID   = $proc.ParentProcessId
        ParentName  = $parentName
        ParentPath  = $parentPath
        Owner       = $ownerString
        StartTime   = $proc.CreationDate
        VTResult    = $null
        Flags       = @()
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# Network connections (established outbound only, exclude loopback)
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$' } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# ────────────────────────────────────────────────────────────────────────────────
# Anomaly detection + baseline check
$flaggedProcs = @()
$flaggedConns = @()

foreach ($p in $processes) {
    $flags = @()

    # Rule: Unusual PowerShell parent
    if ($p.Name -match '(?i)powershell|pwsh') {
        $commonParents = @('explorer.exe','cmd.exe','powershell.exe','pwsh.exe','WindowsTerminal.exe','conhost.exe')
        if ($commonParents -notcontains $p.ParentName.ToLower()) {
            $flags += "Unusual PS parent: $($p.ParentName)"
        }
    }

    # Rule: Suspicious execution path (Properly expanded & escaped)
    $tempPath = [System.IO.Path]::GetTempPath()
    $appData = $env:APPDATA
    $localAppData = $env:LOCALAPPDATA
    $publicPath = $env:PUBLIC

    if ($p.Path -like "$tempPath*" -or 
        $p.Path -like "$appData\*" -or 
        $p.Path -like "$localAppData\Temp\*" -or 
        $p.Path -like "$publicPath\*") {
        $flags += "Suspicious path"
    }

    # Rule: Path-to-Hash mismatch vs baseline
    if ($baseline.ContainsKey($p.Path)) {
        if ($baseline[$p.Path] -ne $p.Hash) {
            $flags += "Hash mismatch vs baseline"
        }
    } elseif ($GenerateBaseline -and $p.Hash -ne "N/A") {
        $baseline[$p.Path] = $p.Hash
    }

    if ($flags.Count -gt 0) {
        $p.Flags = $flags -join '; '
        
        # VirusTotal Lookup ONLY on flagged binaries (respects rate limits)
        if ($VtApiKey -and $p.Hash -ne "N/A") {
            try {
                $headers = @{ "x-apikey" = $VtApiKey }
                $uri = "https://www.virustotal.com/api/v3/files/$($p.Hash)"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $stats = $response.data.attributes.last_analysis_stats
                $p.VTResult = "VT: Malicious=$($stats.malicious) Suspicious=$($stats.suspicious) Undetected=$($stats.undetected)"
                Write-Host "VT Match [$($p.Name)]: $($p.VTResult)" -ForegroundColor DarkCyan
                Start-Sleep -Seconds 15 # Free tier rate limit buffer (4 req/min)
            } catch {
                $p.VTResult = "VT Lookup Failed"
                Write-Warning "VT query error for $($p.Name): $($_.Exception.Message)"
            }
        }

        $flaggedProcs += $p
    }
}

# Suspicious outbound connections (Private IP regex includes 10/8, 172.16/12, 192.168/16, link-local 169.254/16, IPv6)
$privateRegex = '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|fc00:|fe80:|127\.|::1)'
$flaggedConns = $connections | Where-Object { $_.RemoteAddress -notmatch $privateRegex }

# Save/update baseline if requested
if ($GenerateBaseline -and $baseline.Count -gt 0) {
    $baseline | ConvertTo-Json -Depth 5 | Set-Content $BaselineJson -Force
    Write-Host "Baseline saved: $BaselineJson ($($baseline.Count) entries)" -ForegroundColor Green
}

# ────────────────────────────────────────────────────────────────────────────────
# Summary & Reporting
$timestamp = Get-Date
$summary = "Hunt Summary ($timestamp)`nFlagged Processes: $($flaggedProcs.Count)`nSuspicious Connections: $($flaggedConns.Count)"
Write-Host $summary -ForegroundColor Yellow

# Separate CSV Exports to avoid property collisions
$procCsvPath = "${LogPath}_Processes.csv"
$connCsvPath = "${LogPath}_Connections.csv"

if ($flaggedProcs.Count -gt 0) {
    $flaggedProcs | Export-Csv -Path $procCsvPath -NoTypeInformation -Force
    Write-Host "Process flags logged to: $procCsvPath" -ForegroundColor Green
}
if ($flaggedConns.Count -gt 0) {
    $flaggedConns | Export-Csv -Path $connCsvPath -NoTypeInformation -Force
    Write-Host "Connection flags logged to: $connCsvPath" -ForegroundColor Green
}

# Styled HTML report
$css = @"
<style>
    body { font-family: Segoe UI, Arial, sans-serif; background:#f8f9fa; color:#212529; padding:20px; }
    h1 { color:#dc3545; text-align:center; }
    h2 { color:#0d6efd; }
    table { width:100%; border-collapse:collapse; margin:15px 0; box-shadow:0 2px 5px rgba(0,0,0,0.1); }
    th, td { border:1px solid #dee2e6; padding:10px; text-align:left; }
    th { background:#0d6efd; color:white; }
    tr:nth-child(even) { background:#e7f1ff; }
    .flag { background:#fff3cd; color:#856404; font-weight:bold; }
    .high { background:#f8d7da; color:#721c24; }
    .summary { background:#d1e7dd; padding:15px; border-radius:8px; margin:20px 0; font-weight:bold; }
</style>
"@

$htmlBody = "<h1>Suspicious Activity Hunt Report</h1>"
$htmlBody += "<div class='summary'>$($summary -replace "`n", '<br>')</div>"

if ($flaggedProcs.Count -gt 0) {
    $htmlBody += "<h2>Flagged Processes</h2>"
    $htmlBody += $flaggedProcs | ConvertTo-Html -Property PID,Name,Path,Hash,ParentName,Flags,VTResult -Fragment |
        ForEach-Object { $_ -replace '<td>(.*?Unusual|Suspicious|Hash mismatch|VT: Malicious.*?)</td>', '<td class="flag high">$1</td>' }
}

if ($flaggedConns.Count -gt 0) {
    $htmlBody += "<h2>Suspicious Outbound Connections</h2>"
    $htmlBody += $flaggedConns | ConvertTo-Html -Property OwningProcess,RemoteAddress,RemotePort -Fragment
}

$html = ConvertTo-Html -Head $css -Body $htmlBody -Title "Hunt Report $timestamp" | Out-String
$html | Out-File $ReportPath -Encoding UTF8
Write-Host "HTML report generated: $ReportPath" -ForegroundColor Green

# ────────────────────────────────────────────────────────────────────────────────
# Email alert
if ($SendEmail -and ($flaggedProcs.Count -gt 0 -or $flaggedConns.Count -gt 0)) {
    if (-not $SmtpServer -or -not $EmailTo) {
        Write-Warning "Email alert skipped: -SmtpServer and -EmailTo parameters are required."
    } else {
        $mailParams = @{
            From       = if ($EmailFrom) { $EmailFrom } else { $EmailTo }
            To         = $EmailTo
            Subject    = "Security Hunt Alert - Suspicious Activity Detected ($timestamp)"
            Body       = "$summary`n`nReview attached HTML report."
            SmtpServer = $SmtpServer
            Port       = $SmtpPort
            UseSsl     = $true
            Attachments= @($ReportPath)
        }
        if ($SmtpCredential) { $mailParams["Credential"] = $SmtpCredential }

        try {
            Send-MailMessage @mailParams -ErrorAction Stop
            Write-Host "Email alert sent successfully to $EmailTo" -ForegroundColor Green
        } catch {
            Write-Warning "Email send failed: $($_.Exception.Message)"
        }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# Optional quarantine (Terminates process first to unlock binary)
if ($Quarantine -and $flaggedProcs.Count -gt 0) {
    Write-Host "`nQuarantining flagged executables..." -ForegroundColor Red
    foreach ($item in $flaggedProcs) {
        if ($PSCmdlet.ShouldProcess($item.Path, "Stop Process and Quarantine Executable")) {
            try {
                # Stop process to release file lock
                Stop-Process -Id $item.PID -Force -ErrorAction Stop
                Write-Host "Terminated process PID $($item.PID) ($($item.Name))" -ForegroundColor Yellow

                if (Test-Path $item.Path) {
                    $hashSub = if ($item.Hash -ne "N/A") { $item.Hash.Substring(0,8) } else { "NOHASH" }
                    $destName = "$($item.Name)_$hashSub.quar"
                    $dest = Join-Path $QuarantinePath $destName
                    Move-Item -Path $item.Path -Destination $dest -Force -ErrorAction Stop
                    Write-Host "Quarantined: $($item.Path) -> $dest" -ForegroundColor Red
                }
            } catch {
                Write-Warning "Quarantine failed for PID $($item.PID): $($_.Exception.Message)"
            }
        }
    }
}

Stop-Transcript
Write-Host "`nHunt complete. Review logs and report." -ForegroundColor Cyan