<#
.SYNOPSIS
    Master System State Capture (JSON Edition)
.DESCRIPTION
    Bundles Apps, PS Modules, Env Vars, Product Keys, and Shortcuts into 
    a single JSON file for easy AI ingestion and system restoration.
.AUTHOR
    Scott M.
.NOTES
    Version: 1.6
    Changelog:
    v1.5 - Fixed OneDrive path issues.
    v1.6 - Added JSON bundling. Consolidates all data into one 'Full_System_Profile.json'.
#>

# 1. Setup Path
$desktopPath = [Environment]::GetFolderPath("Desktop")
if ([string]::IsNullOrEmpty($desktopPath)) { $desktopPath = "$env:USERPROFILE\Desktop" }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$reportDir = "$desktopPath\System_Rebuild_Map_$timestamp"
if (!(Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory | Out-Null }

Write-Host "--- MASTER SYSTEM CAPTURE v1.6 ---" -ForegroundColor Cyan

# 2. Data Collection Object
$MasterProfile = [PSCustomObject]@{
    Metadata = @{
        Author    = "Scott M."
        Timestamp = $timestamp
        OS        = (Get-WmiObject Win32_OperatingSystem).Caption
    }
    License = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
    EnvironmentVariables = Get-ChildItem Env: | Select-Object Name, Value
    NetworkDrives = Get-SmbMapping | Select-Object LocalPath, RemotePath
    PSModules = Get-Module -ListAvailable | Select-Object Name, Version
    Shortcuts = Get-ChildItem -Path @([Environment]::GetFolderPath("Desktop"), [Environment]::GetFolderPath("StartMenu")) -Include *.lnk, *.url -Recurse -ErrorAction SilentlyContinue | Select-Object Name, FullName
}

# 3. App Inventory logic
$appResults = @()
$regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        $appResults += [PSCustomObject]@{ Name = $_.DisplayName; Source = "Registry"; Publisher = $_.Publisher }
    }
}
$MasterProfile | Add-Member -MemberType NoteProperty -Name "InstalledApps" -Value ($appResults | Sort-Object Name -Unique)

# 4. Export to Single JSON
$jsonPath = "$reportDir\Full_System_Profile_$timestamp.json"
$MasterProfile | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath
Write-Host "Success! Master JSON created at: $jsonPath" -ForegroundColor Green

# 5. Keep the Winget file separate (it's needed for the 'import' command)
if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget export -o "$reportDir\winget_packages_$timestamp.json" --accept-source-agreements | Out-Null
}