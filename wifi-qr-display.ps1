<#
.SYNOPSIS
Display a Wi-Fi QR code for a network from a wifi-backup.ps1 backup.

.DESCRIPTION
Reads a Wi-Fi backup folder, parses the XML for credentials, 
and generates a QR code via Google Chart API.

.AUTHOR
Scott M.

.CHANGELOG
v1.0.0 (2026-03-12) - Initial version
v1.1.0 (2026-03-12) - Added internet check, fixed loop syntax, and added Changelog

.PARAMETER Path
Path to the backup folder or ZIP file.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

# ---------------------------------------------------------
# Validate Path & Internet
# ---------------------------------------------------------
if (-not (Test-Path $Path)) {
    Write-Error "folder not found: $Path"
    exit
}

# check for web access since we're using Google's API
if (-not (Test-Connection -ComputerName google.com -Count 1 -Quiet)) {
    Write-Error "this script needs internet to generate the QR code via Google API."
    exit
}

# ---------------------------------------------------------
# Get Profiles
# ---------------------------------------------------------
$profiles = Get-ChildItem -Path "$Path\*.xml"

if ($profiles.Count -eq 0) {
    Write-Warning "no wifi profiles found in $Path"
    exit
}

Write-Host "`nAvailable Networks:" -ForegroundColor Cyan
for ($i=0; $i -lt $profiles.Count; $i++) {
    Write-Host ("[{0}] {1}" -f ($i+1), $profiles[$i].BaseName)
}

# ---------------------------------------------------------
# Selection & Parsing
# ---------------------------------------------------------
$selection = Read-Host "`nPick a number"
if ($selection -lt 1 -or $selection -gt $profiles.Count) {
    Write-Error "invalid choice."
    exit
}

[xml]$xml = Get-Content $profiles[$selection-1].FullName

# drill down into the XML schema
$ns = @{ wlan = "http://www.microsoft.com/networking/WLAN/profile/v1" }
$ssid = $xml.WLANProfile.SSIDConfig.SSID.name
$auth = $xml.WLANProfile.MSM.security.authEncryption.authentication
$pass = $xml.WLANProfile.MSM.security.sharedKey.keyMaterial

# map auth for QR format
$type = "WPA"
if ($auth -eq "open") { $type = "nopass" }

$wifiString = "WIFI:T:$type;S:$ssid;P:$pass;;"

# ---------------------------------------------------------
# Build the UI
# ---------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$qrUrl = "https://chart.googleapis.com/chart?chs=350x350&cht=qr&chl=$([uri]::EscapeDataString($wifiString))"

$form = New-Object Windows.Forms.Form
$form.Text = "QR Code: $ssid"
$form.Size = "400,450"
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.Topmost = $true

$pb = New-Object Windows.Forms.PictureBox
$pb.Dock = "Fill"
$pb.SizeMode = "CenterImage"

try {
    $wc = New-Object System.Net.WebClient
    $imgData = $wc.DownloadData($qrUrl)
    $ms = New-Object System.IO.MemoryStream(,$imgData)
    $pb.Image = [System.Drawing.Image]::FromStream($ms)
}
catch {
    Write-Error "failed to download QR code: $($_.Exception.Message)"
    exit
}

$form.Controls.Add($pb)
$form.ShowDialog() | Out-Null