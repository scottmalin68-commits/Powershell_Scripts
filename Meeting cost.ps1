<#
.SYNOPSIS
    tracks meeting costs in real time based on headcount and hourly rates with color-coded display.

.DESCRIPTION
    interactive script that calculates running meeting costs every second.
    allows live controls to change participant counts, log tangent topics,
    and print a stylized summary report when the meeting ends.

.CHANGELOG
    v1.3.0 - 2026-08-08 - Scott Malin
    - updated live screen display to list tangent topics under the main subject

    v1.2.1 - 2026-08-08 - Scott Malin
    - fixed dollar sign variable expansion bug in setup cheat sheet
    - expanded cheat sheet range from $50k to $250k in $25k increments

    v1.2.0 - 2026-08-08 - Scott Malin
    - clarified hourly rate prompt during setup
    - added salary-to-hourly reference lookup table in setup screen

    v1.1.0 - 2026-08-07 - Scott Malin
    - added ANSI colors and formatted banners for better visual contrast
    - added color coding for cost thresholds and status alerts
    
    v1.0.0 - 2026-08-07 - Scott Malin
    - initial release
    - real-time cost calculation based on rate and participant count
    - live key controls for participant updates (A/R) and side topics (T)
    - end-of-meeting summary report with timeline event log

.INPUTS
    none. prompts for details interactively when launched.

.OUTPUTS
    displays live stats in console and prints a meeting summary log at the end.

.EXAMPLE
    PS C:\> .\Get-MeetingCost.ps1
    starts the interactive meeting cost tracking session.
#>

# clear screen and show start header
Clear-Host
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "     MEETING COST TRACKER SETUP        " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Magenta

# display hourly rate conversion table
Write-Host ' '
Write-Host 'Quick Salary -> Hourly Rate Cheat Sheet:' -ForegroundColor Yellow
Write-Host '  $50k/yr  = ~$25.00/hr' -ForegroundColor Gray
Write-Host '  $75k/yr  = ~$37.50/hr' -ForegroundColor Gray
Write-Host '  $100k/yr = ~$50.00/hr' -ForegroundColor Gray
Write-Host '  $125k/yr = ~$62.50/hr' -ForegroundColor Gray
Write-Host '  $150k/yr = ~$75.00/hr' -ForegroundColor Gray
Write-Host '  $175k/yr = ~$87.50/hr' -ForegroundColor Gray
Write-Host '  $200k/yr = ~$100.00/hr' -ForegroundColor Gray
Write-Host '  $225k/yr = ~$112.50/hr' -ForegroundColor Gray
Write-Host '  $250k/yr = ~$125.00/hr' -ForegroundColor Gray
Write-Host '  (formula: annual salary / 2000 hours)' -ForegroundColor DarkGray
Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host ' '

# prompt for initial meeting configuration
$subject = Read-Host "Enter meeting subject"
[int]$participants = Read-Host "Enter initial number of participants"
[double]$hourlyRate = Read-Host "Enter average HOURLY cost per person ($/hr)"

# initialize meeting state and log history
$startTime = Get-Date
$subjects = [System.Collections.Generic.List[string]]::new()
$subjects.Add($subject)

$history = [System.Collections.Generic.List[psobject]]::new()
$history.Add([PSCustomObject]@{
    Time = $startTime.ToString("HH:mm:ss")
    Event = "Meeting started with $participants participants"
})

$running = $true

# main display and tracking loop
while ($running) {
    $elapsed = (Get-Date) - $startTime
    $totalMinutes = [math]::Max(1, [math]::Floor($elapsed.TotalMinutes))
    
    # calculate total cost based on participant hours
    $perMinuteRate = ($hourlyRate / 60) * $participants
    $currentCost = $perMinuteRate * $totalMinutes

    # refresh screen with colorized stats
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "        LIVE MEETING COST TRACKER       " -ForegroundColor DarkCyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host " Subject:      " -NoNewline
    Write-Host "$subject" -ForegroundColor White
    
    # render side topics indented under main subject
    if ($subjects.Count -gt 1) {
        for ($i = 1; $i -lt $subjects.Count; $i++) {
            Write-Host "               - $($subjects[$i])" -ForegroundColor Magenta
        }
    }
    
    Write-Host " Duration:     " -NoNewline
    Write-Host "$($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    
    Write-Host " Participants: " -NoNewline
    Write-Host "$participants" -ForegroundColor Green
    
    Write-Host " Running Cost: " -NoNewline
    # shift color based on total cost spent
    if ($currentCost -gt 250) {
        Write-Host "`$$([math]::Round($currentCost, 2))" -ForegroundColor Red
    } elseif ($currentCost -gt 100) {
        Write-Host "`$$([math]::Round($currentCost, 2))" -ForegroundColor Yellow
    } else {
        Write-Host "`$$([math]::Round($currentCost, 2))" -ForegroundColor Green
    }
    
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " Controls: " -NoNewline
    Write-Host "[A]" -ForegroundColor Green -NoNewline
    Write-Host " Add | " -NoNewline
    Write-Host "[R]" -ForegroundColor Red -NoNewline
    Write-Host " Remove | " -NoNewline
    Write-Host "[T]" -ForegroundColor Magenta -NoNewline
    Write-Host " Tangent | " -NoNewline
    Write-Host "[E]" -ForegroundColor Yellow -NoNewline
    Write-Host " End"
    Write-Host " Press a key to trigger an action..." -ForegroundColor DarkGray

    # process user keystrokes non-blockingly
    if ([console]::KeyAvailable) {
        $key = [console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                $participants++
                $history.Add([PSCustomObject]@{
                    Time = (Get-Date).ToString("HH:mm:ss")
                    Event = "Added participant (Total: $participants)"
                })
            }
            'R' {
                if ($participants -gt 1) {
                    $participants--
                    $history.Add([PSCustomObject]@{
                        Time = (Get-Date).ToString("HH:mm:ss")
                        Event = "Removed participant (Total: $participants)"
                    })
                }
            }
            'T' {
                Write-Host "`n"
                Write-Host "Enter tangent subject: " -ForegroundColor Magenta -NoNewline
                $tangent = Read-Host
                if ($tangent) {
                    $subjects.Add("Tangent: $tangent")
                    $history.Add([PSCustomObject]@{
                        Time = (Get-Date).ToString("HH:mm:ss")
                        Event = "Side topic added: $tangent"
                    })
                }
            }
            'E' {
                $running = $false
            }
        }
    }

    Start-Sleep -Seconds 1
}

# generate and output final meeting summary report
$endTime = Get-Date
Clear-Host
Write-Host "==========================================" -ForegroundColor Green
Write-Host "             FINAL MEETING REPORT         " -ForegroundColor DarkGreen
Write-Host "==========================================" -ForegroundColor Green

Write-Host " Start Time:     " -NoNewline
Write-Host "$($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray

Write-Host " End Time:       " -NoNewline
Write-Host "$($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray

Write-Host " Total Duration: " -NoNewline
Write-Host "$(($endTime - $startTime).ToString('hh\:mm\:ss'))" -ForegroundColor White

Write-Host " Total Cost:     " -NoNewline
Write-Host "`$$([math]::Round($currentCost, 2))" -ForegroundColor Yellow

Write-Host "`n Subjects Covered:" -ForegroundColor Cyan
foreach ($s in $subjects) {
    if ($s.StartsWith("Tangent:")) {
        Write-Host "   - $s" -ForegroundColor Magenta
    } else {
        Write-Host "   - $s" -ForegroundColor White
    }
}

Write-Host "`n Timeline Log:" -ForegroundColor Cyan
foreach ($item in $history) {
    Write-Host "  [$($item.Time)] " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($item.Event)" -ForegroundColor White
}
Write-Host "==========================================" -ForegroundColor Green