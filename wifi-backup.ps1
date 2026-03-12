<#
.SYNOPSIS
Backup, restore, and inspect Windows Wi-Fi profiles.

.DESCRIPTION
Exports saved Wi-Fi profiles from a Windows system and allows them to
be restored later. Profiles are exported as XML files and compressed
into a ZIP archive.

A manifest file is generated during export containing metadata such as
computer name, OS version, export date, and number of profiles.

.PARAMETER Mode
Specifies the operation mode.

Export        -> Backup Wi-Fi profiles
Import        -> Restore Wi-Fi profiles from a backup folder
ShowManifest  -> Display manifest information from a backup

.PARAMETER Path
Path to the backup folder when using Import or ShowManifest mode.

.EXAMPLES

Export Wi-Fi profiles

    .\wifi-backup.ps1 -Mode Export

Import Wi-Fi profiles

    .\wifi-backup.ps1 -Mode Import -Path "C:\Users\<username>\WifiBackup_2026-03-12_19-15"

Display backup manifest

    .\wifi-backup.ps1 -Mode ShowManifest -Path "C:\Users\<username>\WifiBackup_2026-03-12_19-15"

.NOTES
Requires Administrator privileges for Export and Import.

Exports use 'key=clear', meaning Wi-Fi passwords may appear in plaintext
inside exported XML files.
#>

param(
    [ValidateSet("Export","Import","ShowManifest")]
    [string]$Mode,

    [string]$Path
)

# ---------------------------------------------------------
# Show help if no parameters are supplied
# ---------------------------------------------------------

if (-not $Mode) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit
}

# ---------------------------------------------------------
# Admin Check (only for Export / Import)
# ---------------------------------------------------------

if ($Mode -ne "ShowManifest") {

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: This mode requires Administrator privileges." -ForegroundColor Red
        exit
    }
}

# ---------------------------------------------------------
# EXPORT MODE
# ---------------------------------------------------------

if ($Mode -eq "Export") {

    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $backupFolder = "$env:USERPROFILE\WifiBackup_$timestamp"

    New-Item -ItemType Directory -Path $backupFolder | Out-Null

    Write-Host ""
    Write-Host "Exporting Wi-Fi profiles to:"
    Write-Host $backupFolder
    Write-Host ""

    netsh wlan export profile key=clear folder="$backupFolder" | Out-Null

    Write-Host "Profiles exported successfully."

    # Collect metadata
    $computerName = $env:COMPUTERNAME
    $exportDate = Get-Date
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $profiles = netsh wlan show profiles
    $profileCount = ($profiles | Select-String "All User Profile").Count

    $connectedSSID = (netsh wlan show interfaces |
        Select-String "^\s*SSID\s*:" |
        Select-Object -First 1).ToString().Split(":")[1].Trim()

    if (-not $connectedSSID) {
        $connectedSSID = "None"
    }

    $manifestPath = Join-Path $backupFolder "manifest.txt"

@"
WiFi Backup Manifest
====================

Computer Name : $computerName
Export Date   : $exportDate
Operating Sys : $os

Profile Count : $profileCount
Connected SSID: $connectedSSID

Backup Folder : $backupFolder

NOTE:
This backup may contain plaintext Wi-Fi passwords in the XML files.
Protect this archive appropriately.
"@ | Out-File $manifestPath

    Write-Host "Manifest file created."

    $zipFile = "$backupFolder.zip"
    Compress-Archive -Path "$backupFolder\*" -DestinationPath $zipFile

    Write-Host ""
    Write-Host "Backup ZIP created:"
    Write-Host $zipFile
}

# ---------------------------------------------------------
# IMPORT MODE
# ---------------------------------------------------------

if ($Mode -eq "Import") {

    if (-not $Path) {
        Write-Host "ERROR: Import mode requires -Path parameter."
        Get-Help $MyInvocation.MyCommand.Path -Examples
        exit
    }

    if (-not (Test-Path $Path)) {
        Write-Host "ERROR: Provided path does not exist."
        exit
    }

    Write-Host ""
    Write-Host "Importing Wi-Fi profiles from:"
    Write-Host $Path
    Write-Host ""

    $profiles = Get-ChildItem "$Path\*.xml"

    foreach ($profile in $profiles) {

        Write-Host "Importing profile:" $profile.Name
        netsh wlan add profile filename="$($profile.FullName)" | Out-Null
    }

    Write-Host ""
    Write-Host "Wi-Fi profile import complete."
}

# ---------------------------------------------------------
# SHOW MANIFEST MODE
# ---------------------------------------------------------

if ($Mode -eq "ShowManifest") {

    if (-not $Path) {
        Write-Host "ERROR: ShowManifest requires -Path parameter."
        exit
    }

    $manifestFile = Join-Path $Path "manifest.txt"

    if (-not (Test-Path $manifestFile)) {
        Write-Host "Manifest file not found in provided folder."
        exit
    }

    Write-Host ""
    Write-Host "Displaying backup manifest:"
    Write-Host "--------------------------------"
    Write-Host ""

    Get-Content $manifestFile
}