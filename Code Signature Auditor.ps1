<#
.SYNOPSIS
    Code Signature Auditor.

.DESCRIPTION
    Scans a target directory for signable files (.ps1, .exe, .dll, etc.) 
    and categorizes their cryptographic status into three definitive buckets: 
    No signing, Valid signature, or Invalid signature.

.PARAMETER Path
    The target directory to scan. Defaults to the current working directory.

.PARAMETER Recurse
    Includes subdirectories in the scan.

.NOTES
    Author: Scott Malin, CISSP
    Version: 1.0.1

============================================================
CHANGELOG
============================================================
v1.0.1 (2026-09-20)
· Added Path parameter and fixed -Include wildcard binding.
· Added optional -Recurse switch for subfolder scanning.
· Added directory path to output properties.

v1.0.0 (2026-05-25)
· Initial release.
· Implemented Get-AuthenticodeSignature tracking for core file extensions.
· Standardized output mapping to three target status buckets.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path =$PWD,

    [Parameter()]
    [switch]$Recurse
)

# --- CONFIGURATION ---
$targetExtensions = "*.ps1", "*.exe", "*.dll", "*.msi", "*.bat", "*.vbs"
# ---------------------

# 1. BUILD SCAN PARAMS
$gciParams = @{
    Path    = "$Path\*"
    Include = $targetExtensions
    File    = $true
}

if ($Recurse) {
    $gciParams['Recurse'] =$true
}

$files = Get-ChildItem @gciParams

if (-not $files) {
    Write-Host "`nNo matching signable files found in the target directory." -ForegroundColor Yellow
    return
}

# 2. AUDIT SIGNATURES
$report = foreach ($file in $files) {
    $sig = Get-AuthenticodeSignature -FilePath $file.FullName
    
    # Map execution status to strict target buckets
    $statusBucket = switch ($sig.Status) {
        "NotSigned" { "No signing" }
        "Valid"     { "Valid signature" }
        default     { "Invalid signature" } # Captures HashMismatch, NotTrusted, Expired, etc.
    }
    
    [PSCustomObject]@{
        "File Name" = $file.Name
        "Path"      = $file.DirectoryName
        "Status"    = $statusBucket
        "Detail"    = $sig.StatusMessage
    }
}

# 3. DISPLAY RESULTS
Write-Host "`nSignature Audit Results:" -ForegroundColor Cyan
$report | Format-Table -AutoSize