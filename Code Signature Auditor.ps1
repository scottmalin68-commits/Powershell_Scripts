<#
.SYNOPSIS
    Code Signature Auditor.

.DESCRIPTION
    Scans the current working directory for signable files (.ps1, .exe, .dll, etc.) 
    and categorizes their cryptographic status into three definitive buckets: 
    No signing, Valid signature, or Invalid signature.

.NOTES
    Author: Scott M.
    Version: 1.0.0

============================================================
CHANGELOG
============================================================
v1.0.0 (2026-05-25)
· Initial release.
· Implemented Get-AuthenticodeSignature tracking for core file extensions.
· Standardized output mapping to three target status buckets.
#>

[CmdletBinding()]
param()

# --- CONFIGURATION ---
$targetExtensions = "*.ps1", "*.exe", "*.dll", "*.msi", "*.bat", "*.vbs"
# ---------------------

# 1. SCAN DIRECTORY
$files = Get-ChildItem -Path . -Include $targetExtensions -File

if (-not $files) {
    Write-Host "`nNo matching signable files found in the current directory." -ForegroundColor Yellow
    exit
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
        "Status"    = $statusBucket
        "Detail"    = $sig.StatusMessage
    }
}

# 3. DISPLAY RESULTS
Write-Host "`nSignature Audit Results:" -ForegroundColor Cyan
$report | Format-Table -AutoSize