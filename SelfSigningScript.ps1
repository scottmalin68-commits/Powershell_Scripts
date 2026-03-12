function Sign-Script {
    <#
    .SYNOPSIS
        Signs PowerShell scripts with a local code-signing certificate.
    .DESCRIPTION
        Automates cert creation, trusted root storage, and signing. 
        Uses a temp workspace to bypass OneDrive sync locks.
    .NOTES
        Author: Scott M.
        Updated: 2026-03-11
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [string]$Path
    )

    process {
        # --- ADMIN CHECK -------------------------------------------------------------
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host " [!] ERROR: This script must be run as Administrator to manage certificates." -ForegroundColor Yellow
            Write-Host " Please right-click your PowerShell icon and choose 'Run as Administrator'."
            Read-Host "`nPress Enter to exit"
            return
        }

        # --- SETTINGS ----------------------------------------------------------------
        $TimestampServer = "http://timestamp.digicert.com"
        $PCName = $env:COMPUTERNAME
        $SubjectName = "CN=$PCName-Signer"

        # --- FILE SELECTION ----------------------------------------------------------
        if (-not $Path) {
            Add-Type -AssemblyName System.Windows.Forms
            $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
                Filter = 'PowerShell Scripts (*.ps1)|*.ps1'
                Title = "Select a script to sign"
            }
            if ($FileBrowser.ShowDialog() -eq 'OK') { $Path = $FileBrowser.FileName } else { return }
        }

        if (-not (Test-Path $Path)) { 
            Write-Host "Error: File not found at $Path" -ForegroundColor Red
            return 
        }
        $FileName = Split-Path $Path -Leaf

        # --- CERTIFICATE HANDLING ----------------------------------------------------
        # Look specifically for the cert we created
        $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | 
                Where-Object { $_.Subject -eq $SubjectName } |
                Sort-Object NotAfter -Descending | Select-Object -First 1

        if (-not $Cert) {
            Write-Host "First-run setup: Creating '$PCName-Signer'..." -ForegroundColor Cyan
            
            # Create cert with specific Code Signing OID (1.3.6.1.5.5.7.3.3)
            $Cert = New-SelfSignedCertificate -Type CodeSigningCert `
                    -Subject $SubjectName `
                    -HashAlgorithm "SHA256" `
                    -KeyAlgorithm RSA -KeyLength 2048 `
                    -CertStoreLocation "Cert:\CurrentUser\My" `
                    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") `
                    -NotAfter (Get-Date).AddYears(5)

            # Move to Trusted Root so the PC trusts itself
            $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
            $rootStore.Open("ReadWrite")
            $rootStore.Add($Cert)
            $rootStore.Close()

            Write-Host "Success: Cert created and added to Trusted Roots.`n" -ForegroundColor Green
        }

        # --- WORKSPACE & SIGNING -----------------------------------------------------
        $Original = (Resolve-Path -LiteralPath $Path).ProviderPath
        $TempDir = Join-Path $env:TEMP "SigningWorkspace"
        if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

        $LocalCopy = Join-Path $TempDir $FileName
        
        try {
            Copy-Item -LiteralPath $Original -Destination $LocalCopy -Force
            Write-Host "Signing $FileName..." -ForegroundColor Gray
            
            $Signature = Set-AuthenticodeSignature -FilePath $LocalCopy -Certificate $Cert -TimestampServer $TimestampServer -HashAlgorithm SHA256

            if ($Signature.Status -eq 'Valid') {
                Move-Item -LiteralPath $LocalCopy -Destination $Original -Force
                Write-Host "Success! $FileName is now signed." -ForegroundColor Green
            } else {
                Write-Host "Signing failed. Status: $($Signature.Status)" -ForegroundColor Red
            }
        }
        finally {
            if (Test-Path $LocalCopy) { Remove-Item $LocalCopy -Force }
        }
    }
}

# Run it
Sign-Script