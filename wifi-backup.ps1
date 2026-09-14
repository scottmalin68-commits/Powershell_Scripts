<#
.SYNOPSIS
Backup, restore, and inspect Windows Wi-Fi profiles.

.DESCRIPTION
Exports saved Wi-Fi profiles from a Windows system and allows them to
be restored later. Profiles are exported as XML files and compressed
into a ZIP archive.

.AUTHOR
Scott Malin, CISSP

.CHANGELOG
v1.0.0 (2026-03-12) - Initial version
v1.1.0 (2026-03-12) - Added Error Handling, ZIP cleanup, and Switch logic
v1.1.1 (2026-03-14) - Added console path fallback, netsh zero-profile check, and zip support for ShowManifest
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="Pick a mode: Export, Import, or ShowManifest")]
    [ValidateSet("Export","Import","ShowManifest")]
    [string]$Mode,

    [Parameter(Mandatory=$false)]
    [string]$Path
)

# Fallback to current directory if run interactively in the console
if (-not $Path) {
    $Path = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

# ---------------------------------------------------------
# Admin Check
# ---------------------------------------------------------
if ($Mode -in "Export", "Import") {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "this script needs admin rights to touch wifi profiles."
        exit
    }
}

switch ($Mode) {

    "Export" {
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
            $tempFolder = Join-Path $env:TEMP "WifiBackup_$timestamp"
            $finalZip = Join-Path $Path "WifiBackup_$timestamp.zip"

            New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
            
            write-host "exporting profiles..." -ForegroundColor Cyan
            netsh wlan export profile key=clear folder="$tempFolder" | Out-Null

            $xmlFiles = Get-ChildItem "$tempFolder\*.xml"
            if ($xmlFiles.Count -eq 0) {
                write-warning "no wifi profiles found on this system to export."
                Remove-Item -Recurse -Force $tempFolder
                return
            }

            # metadata
            $manifestPath = Join-Path $tempFolder "manifest.txt"
            $count = $xmlFiles.Count
            
            @"
WiFi Backup Manifest
====================
Date: $(Get-Date)
PC: $env:COMPUTERNAME
Profiles: $count
"@ | Out-File $manifestPath

            Compress-Archive -Path "$tempFolder\*" -DestinationPath $finalZip -Force
            Remove-Item -Recurse -Force $tempFolder
            
            write-host "done! backup saved to: $finalZip" -ForegroundColor Green
        }
        catch {
            write-error "export failed: $($_.Exception.Message)"
        }
    }

    "Import" {
        if (-not (Test-Path $Path)) { write-error "path not found"; exit }

        try {
            $workPath = $Path
            $isZip = $Path.EndsWith(".zip", [System.StringComparison]::OrdinalIgnoreCase)

            if ($isZip) {
                $workPath = Join-Path $env:TEMP "WifiImport_Temp"
                if (Test-Path $workPath) { Remove-Item -Recurse -Force $workPath }
                Expand-Archive -Path $Path -DestinationPath $workPath
            }

            $files = Get-ChildItem "$workPath\*.xml"
            if ($files.Count -eq 0) { write-warning "no xml profiles found in $workPath"; return }

            foreach ($file in $files) {
                write-host "importing: $($file.Name)" -ForegroundColor Gray
                netsh wlan add profile filename="$($file.FullName)" | Out-Null
            }

            if ($isZip) { Remove-Item -Recurse -Force $workPath }
            write-host "import finished." -ForegroundColor Green
        }
        catch {
            write-error "import failed: $($_.Exception.Message)"
        }
    }

    "ShowManifest" {
        $manifestFile = ""
        $tempManifestDir = ""
        $isZip = $Path.EndsWith(".zip", [System.StringComparison]::OrdinalIgnoreCase)

        if ($isZip) {
            if (-not (Test-Path $Path)) {
                write-warning "zip file not found at $Path"
                return
            }
            $tempManifestDir = Join-Path $env:TEMP "WifiManifest_Temp"
            if (Test-Path $tempManifestDir) { Remove-Item -Recurse -Force $tempManifestDir }
            Expand-Archive -Path $Path -DestinationPath $tempManifestDir
            $manifestFile = Join-Path $tempManifestDir "manifest.txt"
        } else {
            $manifestFile = Join-Path $Path "manifest.txt"
        }

        if (Test-Path $manifestFile) {
            Get-Content $manifestFile
        } else {
            write-warning "no manifest.txt found."
        }

        if ($tempManifestDir -and (Test-Path $tempManifestDir)) {
            Remove-Item -Recurse -Force $tempManifestDir
        }
    }
}