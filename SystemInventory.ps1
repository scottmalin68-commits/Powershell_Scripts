<#
.SYNOPSIS
    Master System State Capture (JSON Edition)
.DESCRIPTION
    Bundles Apps, PS Modules, Env Vars, Product Keys, and Shortcuts into 
    a single JSON file for easy AI ingestion and system restoration.
.AUTHOR
    Scott Malin, CISSP
.Companion file 
    System Rebuild Architect Engine.md at https://github.com/scottmalin68-commits/Misc-AI-Prompts/blob/main/System%20Rebuild%20Architect%20Engine.md
.NOTES
    Version: 1.7.0
    Changelog:
    v1.5 - Fixed OneDrive path issues.
    v1.6 - Added JSON bundling into Full_System_Profile.json.
    v1.7 - Replaced WMI with CIM, forced UTF-8 JSON output, hardened key & shortcut checks.
#>

# 1. Setup Path
$desktopPath = [Environment]::GetFolderPath("Desktop")
if ([string]::IsNullOrEmpty($desktopPath)) { $desktopPath = "$env:USERPROFILE\Desktop" }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$reportDir = "$desktopPath\System_Rebuild_Map_$timestamp"
if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }

Write-Host "--- MASTER SYSTEM CAPTURE v1.7 ---" -ForegroundColor Cyan

# Helper to safely grab OEM Key via CIM
$oemKey = try {
    (Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction SilentlyContinue).OA3xOriginalProductKey
} catch { $null }
if ([string]::IsNullOrWhiteSpace($oemKey)) { $oemKey = "N/A (Digital License, Volume, or Non-OEM)" }

# Helper to gather shortcuts without permission hangups
$shortcutPaths = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("StartMenu"),
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
) | Where-Object { Test-Path $_ }

$shortcuts = Get-ChildItem -Path $shortcutPaths -Include *.lnk, *.url -Recurse -ErrorAction SilentlyContinue | 
    Select-Object Name, FullName

# 2. Data Collection Object
$MasterProfile = [PSCustomObject]@{
    Metadata = @{
        Author    = "Scott M."
        Timestamp = $timestamp
        OS        = (Get-CimInstance Win32_OperatingSystem).Caption
    }
    License              = $oemKey
    EnvironmentVariables = Get-ChildItem Env: | Select-Object Name, Value
    NetworkDrives        = try { Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath, RemotePath } catch { @() }
    PSModules            = Get-Module -ListAvailable | Select-Object Name, Version
    Shortcuts            = $shortcuts
}

# 3. App Inventory Logic
$appResults = @()
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        $appResults += [PSCustomObject]@{
            Name      = $_.DisplayName
            Publisher = $_.Publisher
            Source    = "Registry"
        }
    }
}

$MasterProfile | Add-Member -MemberType NoteProperty -Name "InstalledApps" -Value ($appResults | Sort-Object Name -Unique)

# 4. Export to Single JSON (Explicit UTF-8)
$jsonPath = "$reportDir\Full_System_Profile_$timestamp.json"
$MasterProfile | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-Host "Success! Master JSON created at: $jsonPath" -ForegroundColor Green

# 5. Export Winget File Separately
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "Exporting Winget package manifest..." -ForegroundColor Yellow
    winget export -o "$reportDir\winget_packages_$timestamp.json" --accept-source-agreements | Out-Null
}

Write-Host "System capture complete." -ForegroundColor Cyan