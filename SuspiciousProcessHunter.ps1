<#
.SYNOPSIS
    Lightweight, native PowerShell tool for hunting suspicious processes and network connections.
    Designed as an EDR-style demo showcasing cybersecurity monitoring and automation.

.DESCRIPTION
    This script enumerates running processes and established TCP connections, applies anomaly detection rules,
    computes file hashes, optionally queries VirusTotal, compares against a known-good baseline, and generates
    reports (CSV + styled HTML). It supports optional actions like quarantining flagged files and sending email alerts.

    Goal:
    Demonstrate practical defensive security automation using only built-in PowerShell capabilities (with optional
    external integrations). Ideal for threat hunting, endpoint monitoring demos, blue-team skill showcases, or
    lightweight incident response artifact collection on Windows systems.

    Key features:
    - Anomaly detection (unusual parents, suspicious paths, outbound connections)
    - SHA256 hashing of process images
    - Optional VirusTotal reputation lookup
    - Baseline comparison (known-good hashes/paths)
    - Color-coded HTML reporting
    - CSV logging
    - Optional quarantine move
    - Optional email notification

.PARAMETER LogPath
    Path to the CSV log file. Defaults to a timestamped file in the current directory.

.PARAMETER ReportPath
    Path to the generated HTML report. Defaults to a timestamped file in the current directory.

.PARAMETER QuarantinePath
    Directory where flagged executables will be moved if -Quarantine is used.

.PARAMETER Quarantine
    If specified, moves flagged process executables to the quarantine folder (use -WhatIf for dry-run).

.PARAMETER UseVirusTotal
    Enables VirusTotal API lookup for hashed executables. Will prompt for API key when enabled.

.PARAMETER SendEmail
    Enables email alert if suspicious items are found. Prompts for recipient, sender, SMTP server, port, and credentials.

.PARAMETER BaselineJson
    Path to JSON file containing known-good {hash: path} pairs for baseline comparison.

.PARAMETER GenerateBaseline
    If specified and baseline file is missing or needs update, generates/updates the baseline JSON from current clean run.

.PARAMETER WhatIf
    Shows what actions would be performed without making changes (applies to quarantine moves).

.EXAMPLE
    .\SuspiciousProcessHunter.ps1 -WhatIf
    Run a dry-run scan and view potential flags without changes.

.EXAMPLE
    .\SuspiciousProcessHunter.ps1 -UseVirusTotal -BaselineJson .\baseline.json
    Scan with VT lookup and baseline comparison.

.EXAMPLE
    .\SuspiciousProcessHunter.ps1 -SendEmail -Quarantine -GenerateBaseline
    Generate baseline, scan, quarantine suspicious files (dry-run first!), and email results.

.EXAMPLE
    Register as scheduled task (Task Scheduler):
    Action: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\SuspiciousProcessHunter.ps1" -UseVirusTotal -SendEmail -LogPath "C:\Logs\HuntLog.csv"
    Trigger: Every 30 minutes, run whether user is logged on or not.

.NOTES
    Author:     Scott M (Scott of Enfield) - @Thanos0000
    Version:    1.2
    Created:    January 2026
    Requires:   PowerShell 5.1+ (Windows built-in modules: Cim, NetTCPConnection, etc.)
    Security:   Use -WhatIf and test in a safe environment. Quarantine moves files—review flags carefully.
    Limitations:
      - VirusTotal free tier is rate-limited (~4 req/min).
      - Send-MailMessage uses legacy SMTP; consider modern alternatives (MailKit) for production.
      - No real-time monitoring—run via Task Scheduler for periodic checks.

.CHANGELOG
    v1.0 - Initial version: process + connection enumeration, basic flags, CSV logging, quarantine
    v1.1 - Added VirusTotal optional lookup, email alerts, baseline JSON comparison
    v1.2 - Improved HTML reporting with CSS styling and color-coded flags,
           expanded documentation, goal statement, author/changelog sections,
           better parameter descriptions and examples
#>

[CmdletBinding()]
param(
    [string]$LogPath = ".\HuntLog_$(Get-Date -Format yyyyMMdd_HHmm).csv",
    [string]$ReportPath = ".\HuntReport_$(Get-Date -Format yyyyMMdd_HHmm).html",
    [string]$QuarantinePath = "$env:USERPROFILE\Desktop\Quarantine",
    [switch]$Quarantine,
    [switch]$UseVirusTotal,
    [switch]$SendEmail,
    [string]$BaselineJson = ".\KnownGoodBaseline.json",
    [switch]$GenerateBaseline,
    [switch]$WhatIf
)

# ────────────────────────────────────────────────────────────────────────────────
# Start full transcript logging
Start-Transcript -Path ".\HuntTranscript_$(Get-Date -Format yyyyMMdd_HHmm).txt" -Append -Force

Write-Host "Suspicious Process/Network Hunter v1.2 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "Goal: Demonstrate defensive security automation & threat hunting" -ForegroundColor DarkCyan

# Create quarantine folder if needed
if ($Quarantine -and -not (Test-Path $QuarantinePath)) {
    New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null
    Write-Host "Created quarantine folder: $QuarantinePath" -ForegroundColor DarkYellow
}

# ────────────────────────────────────────────────────────────────────────────────
# Baseline handling
$baseline = @{}
if (Test-Path $BaselineJson) {
    $baseline = Get-Content $BaselineJson -Raw | ConvertFrom-Json -AsHashtable
    Write-Host "Loaded baseline ($($baseline.Count) entries): $BaselineJson" -ForegroundColor Green
} elseif ($GenerateBaseline) {
    Write-Host "No baseline found → will generate new one at end" -ForegroundColor Yellow
}

# ────────────────────────────────────────────────────────────────────────────────
# Process collection + hashing + optional VT
$processes = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate |
    Where-Object { $_.ExecutablePath } |
    ForEach-Object {
        $proc = $_
        $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner
        $parent = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue

        $path = $proc.ExecutablePath
        $hash = if (Test-Path $path) { (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }

        $vtResult = $null
        if ($UseVirusTotal -and $hash -ne "N/A") {
            $apiKey = Read-Host "VirusTotal API Key (leave blank to skip VT)" -MaskInput
            if ($apiKey) {
                try {
                    $headers = @{ "x-apikey" = $apiKey }
                    $uri = "https://www.virustotal.com/api/v3/files/$hash"
                    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                    $stats = $response.data.attributes.last_analysis_stats
                    $vtResult = "VT: Malicious=$($stats.malicious) Suspicious=$($stats.suspicious) Undetected=$($stats.undetected)"
                    Write-Host "VT: $($proc.Name) → $vtResult" -ForegroundColor DarkCyan
                } catch {
                    Write-Warning "VT query failed: $($_.Exception.Message)"
                }
            }
        }

        [PSCustomObject]@{
            PID         = $proc.ProcessId
            Name        = $proc.Name
            Path        = $path
            Hash        = $hash
            CommandLine = $proc.CommandLine
            ParentPID   = $proc.ParentProcessId
            ParentName  = $parent.Name ?? "N/A"
            ParentPath  = $parent.Path ?? "N/A"
            Owner       = "$($owner.Domain)\$($owner.User)"
            StartTime   = $proc.CreationDate
            VTResult    = $vtResult
            Flags       = @()
        }
    }

# ────────────────────────────────────────────────────────────────────────────────
# Network connections (established outbound only, exclude loopback)
$connections = Get-NetTCPConnection |
    Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$' } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# ────────────────────────────────────────────────────────────────────────────────
# Anomaly detection + baseline check
$flaggedProcs = @()
$flaggedConns = @()

foreach ($p in $processes) {
    $flags = @()

    # Rule: Unusual PowerShell parent
    if ($p.Name -match 'powershell|pwsh') {
        $commonParents = 'explorer.exe','cmd.exe','powershell.exe','pwsh.exe','WindowsTerminal.exe','conhost.exe'
        if ($commonParents -notcontains $p.ParentName) {
            $flags += "Unusual PS parent: $($p.ParentName)"
        }
    }

    # Rule: Suspicious execution path
    if ($p.Path -match '(?i)Temp|AppData\\Roaming|AppData\\Local\\Temp|Public|%TEMP%') {
        $flags += "Suspicious path"
    }

    # Rule: Hash/path deviation from baseline
    if ($baseline.ContainsKey($p.Hash) -and $baseline[$p.Hash] -ne $p.Path) {
        $flags += "Hash mismatch vs baseline"
    } elseif ($GenerateBaseline -and $p.Hash -ne "N/A") {
        $baseline[$p.Hash] = $p.Path
    }

    if ($flags.Count -gt 0) {
        $p.Flags = $flags -join '; '
        $flaggedProcs += $p
    }
}

# Suspicious outbound connections (basic non-private IP filter)
$privateRegex = '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|fc00:|fe80:|127\.|::1)'
$suspConn = $connections | Where-Object { $_.RemoteAddress -notmatch $privateRegex }
$flaggedConns += $suspConn

# Save/update baseline if requested
if ($GenerateBaseline -and $baseline.Count -gt 0) {
    $baseline | ConvertTo-Json -Depth 5 | Set-Content $BaselineJson -Force
    Write-Host "Baseline updated/saved: $BaselineJson ($($baseline.Count) entries)" -ForegroundColor Green
}

# ────────────────────────────────────────────────────────────────────────────────
# Summary & Reporting
$timestamp = Get-Date
$summary = "Hunt Summary ($timestamp)`nFlagged Processes: $($flaggedProcs.Count)`nSuspicious Connections: $($flaggedConns.Count)"

Write-Host $summary -ForegroundColor Yellow

# CSV export
$allFlagged = $flaggedProcs + $flaggedConns
$allFlagged | Export-Csv -Path $LogPath -NoTypeInformation -Append -Force
Write-Host "Results logged to CSV: $LogPath" -ForegroundColor Green

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
# Email alert (if enabled and findings exist)
if ($SendEmail -and ($flaggedProcs.Count -gt 0 -or $flaggedConns.Count -gt 0)) {
    $to      = Read-Host "Recipient email address"
    $from    = Read-Host "Sender email (press Enter to use recipient)"
    if (-not $from) { $from = $to }
    $smtp    = Read-Host "SMTP server (e.g. smtp.office365.com)"
    $port    = Read-Host "Port (default 587)"
    if (-not $port) { $port = 587 }
    $cred    = Get-Credential -Message "SMTP login (use app password for Gmail/365)"

    $subject = "Security Hunt Alert - Suspicious Activity Detected ($timestamp)"
    $body    = $summary + "`n`nReview attached CSV and HTML report.`n`nCSV: $LogPath`nHTML: $ReportPath"

    try {
        Send-MailMessage -From $from -To $to -Subject $subject -Body $body -SmtpServer $smtp -Port $port `
            -UseSsl -Credential $cred -Attachments $ReportPath,$LogPath -ErrorAction Stop
        Write-Host "Email alert sent successfully to $to" -ForegroundColor Green
    } catch {
        Write-Warning "Email send failed: $($_.Exception.Message)"
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# Optional quarantine
if ($Quarantine -and $flaggedProcs.Count -gt 0) {
    Write-Host "`nQuarantining flagged executables..." -ForegroundColor Red
    foreach ($item in $flaggedProcs) {
        if (Test-Path $item.Path) {
            $destName = "$($item.Name)_$($item.Hash.Substring(0,8)).quar"
            $dest = Join-Path $QuarantinePath $destName
            Move-Item -Path $item.Path -Destination $dest -WhatIf:$WhatIf -Force
            Write-Host "Quarantined: $($item.Path) → $dest"
        }
    }
}

Stop-Transcript
Write-Host "`nHunt complete. Review logs and report." -ForegroundColor Cyan