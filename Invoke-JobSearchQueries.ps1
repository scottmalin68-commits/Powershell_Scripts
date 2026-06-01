<#
.SYNOPSIS
    Auto-Hunt Protocol Execution Engine (PowerShell Edition)
.DESCRIPTION
    This script automates cyber-intelligence gathering for job targeting. 
    It opens a GUI File Explorer window filtered to 'Posting-*.md' files,
    extracts pure 'site:linkedin.com' search strings and their descriptive labels 
    under '#### 13. THE HUNT', runs them against Gemini with live search grounding, 
    logs the queries, and appends the findings to the file.
.CHANGELOG
    v1.4.4 - Added automatic 3-tier retry logic with exponential backoff for 503 high-demand server errors.
    v1.4.5 - Integrated dynamic exception handling to extract and display raw JSON error strings from Google backends.
    v1.4.6 - Hardened API payload structural integrity with high-depth JSON serialization for deep nested object tracking.
    v1.4.7 - Standardized OSINT report outputs with structured markdown tables for automated executive summaries.
    v1.4.8 - Added sequential tracking for target lead descriptive labels to contextualize report outputs.
    v1.4.9 - Abstracted retry, retry delay, and pacing limits into central configuration block for easier free-tier tuning.
    v1.5.0 - Updated default engine fallback with verified high-quota workspace API key.
    v1.5.1 - Sanitized credential keys for public GitHub repository safety and overhauled onboarding documentation.
.NOTES
    ============================================================================
    ACCOUNT SETUP & HIGH-QUOTA API KEY DEPLOYMENT
    ============================================================================
    1. INITIAL GOOGLE ACCOUNT REGISTRATION
       · Navigate to Google AI Studio (aistudio.google.com).
       · Sign in with your primary Google identity. 
       · Accept the platform Terms of Service to initialize the developer profile.
    
    2. DEPLOYING A HIGH-QUOTA WORKSPACE PROJECT (CRITICAL)
       · Do NOT simply generate a key immediately on the landing dashboard; this 
         frequently binds the key to a heavily throttled 'Default Gemini Project' 
         restricted to a tiny 20 Requests Per Day (RPD) trial cap.
       · Select "Get API key" from the left-hand navigation pane.
       · Click the "Create API key" button to open the configuration modal.
       · Locate the dropdown menu under "Choose an imported project".
       · Select "Create a new project" (or "Create new cloud project").
       · Click "Create key". This provisions a dedicated workspace that grants 
         the full standard Free Tier allocation (up to 250+ RPD for core models 
         and up to 1,500 RPD for search grounding tools).
    
    3. LOCAL SYSTEM ENVIRONMENT VARIABLE PERSISTENCE (RECOMMENDED)
       · To bypass hardcoding cleartext strings inside production scripts, bind 
         the key to an encrypted user-scope environment variable.
       · Open an elevated PowerShell terminal and execute the following line:
         [System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "YOUR_ACTUAL_API_KEY_HERE", "User")
       · Restart your terminal application to reload the environment block.
       · The engine will automatically intercept this variable at runtime.
    ============================================================================
#>

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$GeminiApiKey = [System.Environment]::GetEnvironmentVariable("GEMINI_API_KEY")
if (-not $GeminiApiKey) {
    $GeminiApiKey = "YOUR_GEMINI_API_KEY_HERE"
}

# Centralized Query Log File
$QueryLogFile = "C:\Users\Scott\OneDrive\Documents\Resumes\google_query_log.txt"

# Rate Limit & Throttling Adjustments (Optimized for Free Tier Quotas)
$PacingDelaySeconds = 30   # Time to wait between completely different queries
$MaxRetryAttempts   = 3    # Total times to try a failing request before giving up
$InitialRetryDelay  = 30   # Seconds to wait on first failure (doubles each time)

# ==============================================================================
# ENGINE CORE FUNCTIONS
# ==============================================================================

function Select-TargetMarkdownFile {
    Add-Type -AssemblyName System.Windows.Forms
    
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = (Get-Item .).FullName
        Title            = "Select Target Job Posting File"
        Filter           = "Target Postings (Posting-*.md)|Posting-*.md|All Markdown Files (*.md)|*.md"
    }
    
    $Result = $FileBrowser.ShowDialog()
    
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "Selected file via GUI: $($FileBrowser.SafeFileName)" -ForegroundColor Green
        return $FileBrowser.FileName
    } else {
        return $null
    }
}

function Get-SearchStrings {
    param (
        [string]$FilePath
    )

    Write-Host "Reading target file: $FilePath" -ForegroundColor Cyan
    $Content = Get-Content -Path $FilePath -Raw

    $Pattern = "(?s)####\s*13\.\s*THE\s*HUNT\s*\(AUTO-HUNT\s*PROTOCOL\).*?Part\s*A:\s*X-Ray\s*Blueprint(.*?)((?=####)|$)"
    $Match = [regex]::Match($Content, $Pattern)

    if (-not $Match.Success) {
        Write-Warning "Could not find the target 'Part A: X-Ray Blueprint' subsection."
        return @()
    }

    $SectionText = $Match.Groups[1].Value
    $Lines = $SectionText -split "`r?`n"
    $Queries = @()
    $CurrentLabel = "Unknown Vector"

    foreach ($Line in $Lines) {
        $Cleaned = $Line.Trim()

        # check if this line is a label heading (e.g., "1. Direct Lead...:")
        if ($Cleaned -match "^\d+\.\s*(.+):$") {
            $CurrentLabel = $Matches[1].Trim()
            continue
        }

        # clean up query line
        $CleanedQuery = $Cleaned -replace "^[\*\s•\-\d\.]+", ""
        $CleanedQuery = $CleanedQuery.Trim("'`"")

        if ($CleanedQuery -match "^\s*site:linkedin\.com\/\S+") {
            $Queries += [PSCustomObject]@{
                Label = $CurrentLabel
                Query = $CleanedQuery
            }
            # reset back to default for safety
            $CurrentLabel = "Unknown Vector"
        }
    }

    return $Queries
}

function Invoke-GroundedSearch {
    param (
        [string]$Query,
        [string]$ApiKey
    )

    $Uri = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=$ApiKey"
    
    $Body = @{
        contents = @(
            @{
                parts = @(
                    @{
                        text = "You are an elite cyber-intelligence and corporate OSINT analyst. Perform a comprehensive live search and analysis for the following target query. Provide a clean, structured intelligence summary with verified sources and links:`n`nQuery: $Query"
                    }
                )
            }
        )
        tools = @(
            @{
                google_search = @{}
            }
        )
    } | ConvertTo-Json -Depth 10

    $Attempt = 1
    $CurrentRetryDelay = $InitialRetryDelay

    while ($Attempt -le $MaxRetryAttempts) {
        try {
            Write-Host "Executing live search grounding (Attempt $Attempt/$MaxRetryAttempts) for: '$Query'" -ForegroundColor Yellow
            $Response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -TimeoutSec 45
            $ResultText = $Response.candidates[0].content.parts[0].text
            return $ResultText
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            
            # Modern PowerShell Error Content Handling (HttpClient Response parsing)
            if ($_.Exception.InnerException -and $_.Exception.InnerException.Response) {
                $ErrorResponse = $_.Exception.InnerException.Response
                $Task = $ErrorResponse.Content.ReadAsStringAsync()
                if ($Task.Wait(2000)) { $ErrorMessage = $Task.Result }
            }
            elseif ($_ -and $_.ErrorRecord -and $_.ErrorRecord.ErrorDetails) {
                $ErrorMessage = $_.ErrorRecord.ErrorDetails.Message
            }

            Write-Warning "Attempt $Attempt failed. Server response: $ErrorMessage"

            if ($Attempt -lt $MaxRetryAttempts) {
                Write-Host "Server overloaded or rate-limited. Backing off and retrying in $CurrentRetryDelay seconds..." -ForegroundColor Gray
                Start-Sleep -Seconds $CurrentRetryDelay
                $CurrentRetryDelay = $CurrentRetryDelay * 2 # Exponential backoff
            }
            $Attempt++
        }
    }

    return "Execution Error: Unable to retrieve live grounding data. Google API servers are currently overloaded (503) or rejecting requests."
}

function Add-QueryLog {
    param (
        [string]$LogPath,
        [string]$Query
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] EXECUTED: $Query"
    
    try {
        Add-Content -Path $LogPath -Value $LogEntry
        Write-Host "Logged query entry to: $LogPath" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Append-ResultsToMarkdown {
    param (
        [string]$FilePath,
        [array]$SearchResults
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FileName = Split-Path $FilePath -Leaf
    $QueryCount = $SearchResults.Count

    $OutputBlock = "`n`n---`n"
    $OutputBlock += "## 📊 OSINT INTELLIGENCE REPORT: LIVE GROUNDING`n`n"
    $OutputBlock += "| Metadata Field | Report Details |`n"
    $OutputBlock += "| :--- | :--- |`n"
    $OutputBlock += "| **Execution Timestamp** | $Timestamp |`n"
    $OutputBlock += "| **Target Source File** | $FileName |`n"
    $OutputBlock += "| **Total Queries Run** | $QueryCount Target Vectors |`n"
    $OutputBlock += "| **Engine Status** | Completed |`n`n"
    $OutputBlock += "---`n"

    foreach ($Result in $SearchResults) {
        $OutputBlock += "`n### 🔍 Target: $($Result.Label)`n"
        $OutputBlock += "**Query:** \`$($Result.Query)\`\n\n"
        $OutputBlock += "$($Result.Output)`n"
        $OutputBlock += "`n"
    }

    try {
        Add-Content -Path $FilePath -Value $OutputBlock
        Write-Host "Successfully appended the report summary and results to the bottom of '$FilePath'." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write results back to the markdown file. Details: $_"
    }
}

# ==============================================================================
# MAIN EXECUTION PIPELINE
# ==============================================================================
function Main {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "LAUNCHING AUTO-HUNT POWERSHELL ENGINE (v1.5.1)" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    if ($GeminiApiKey -eq "YOUR_GEMINI_API_KEY_HERE" -or -not $GeminiApiKey) {
        Write-Error "API Key is not configured properly. Please update the `$GeminiApiKey variable or your system environment variables."
        return
    }

    $TargetFile = Select-TargetMarkdownFile
    if (-not $TargetFile) {
        Write-Warning "No file selected or user canceled operation. Aborting."
        return
    }

    $Queries = Get-SearchStrings -FilePath $TargetFile
    
    if ($Queries.Count -eq 0) {
        Write-Warning "Process stopped: No valid site:linkedin search strings found inside the target section."
        return
    }

    Write-Host "Found $($Queries.Count) valid target queries to process." -ForegroundColor Green
    $Results = @()

    for ($i = 0; $i -lt $Queries.Count; $i++) {
        $CurrentTarget = $Queries[$i]
        Write-Host "`n[$($i + 1)/$($Queries.Count)] Processing: $($CurrentTarget.Label)..." -ForegroundColor Cyan
        
        Add-QueryLog -LogPath $QueryLogFile -Query $CurrentTarget.Query
        
        $ResultContent = Invoke-GroundedSearch -Query $CurrentTarget.Query -ApiKey $GeminiApiKey
        
        $Results += [PSCustomObject]@{
            Label  = $CurrentTarget.Label
            Query  = $CurrentTarget.Query
            Output = $ResultContent
        }

        if ($i -lt ($Queries.Count -1)) {
            Write-Host "Throttling execution for $PacingDelaySeconds seconds to manage API quota safety..." -ForegroundColor Gray
            Start-Sleep -Seconds $PacingDelaySeconds
        }
    }

    Write-Host "`nWriting results back to target document..." -ForegroundColor Cyan
    Append-ResultsToMarkdown -FilePath $TargetFile -SearchResults $Results
    
    Write-Host "`nEngine execution complete.`n" -ForegroundColor Green
}

Main