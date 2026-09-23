<#
.SYNOPSIS
    Internet speed monitor and alert tool.
.DESCRIPTION
    Runs the Ookla speedtest, logs results to a CSV file, emails you if your speed drops too low, and pops up a 24-hour performance chart.
.AUTHOR
    Scott Malin, CISSP
.VERSION
    1.1
.CHANGELOG
    v1.1 - Added documentation header, removed personal info, added continuous monitoring loop.
    v1.0 - Initial draft.
.VARIABLES
    $minSpeedMbps  - Lowest acceptable download speed before sending an alert.$pauseDuration - Time in seconds to wait between speed tests.
    $logFile       - Path where past speed results are saved.$chartFile     - Path where the generated speed graph image is saved.
    $smtpServer    - Mail server used for sending alerts.$smtpPort      - Port used by the mail server (587 for TLS).
    $from          - Sender email address.$to            - Recipient email address.
    $subject       - Subject line for the warning email.$appPassword   - App password for your email account.
#>

# ==============================================================================
# 1. ASSEMBLY INITIALIZATION
# ==============================================================================
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

# ==============================================================================
# 2. GLOBAL CONFIGURATION & ENVIRONMENT SETUP
# ==============================================================================
$minSpeedMbps  = 100$pauseDuration = 300 # changed to 5 minutes so it runs regularly

$logFile   = "$PSScriptRoot\speed_history.csv"
$chartFile = "$PSScriptRoot\speed_graph.png"

# SMTP Mail Server Configuration
$smtpServer  = "smtp.gmail.com"
$smtpPort    = 587$from        = "your_email@gmail.com"
$to          = "your_email@gmail.com"
$subject     = "ALERT: Slow Internet Speed Detected!"
$appPassword = "your_app_password"

# ==============================================================================
# 3. MAIN MONITORING LOOP
# ==============================================================================
while ($true) {

    # ==============================================================================
    # SPEEDTEST EXECUTION & METRIC PARSING
    # ==============================================================================
    Write-Host "Finding fast local server & running speedtest..." -ForegroundColor Cyan

    try {
        $serverList = speedtest -L -f json \vert{} ConvertFrom-Json$bestServerId = $serverList.servers[0].id$jsonRaw = speedtest -s $bestServerId -f json -P 8     } catch {$jsonRaw = speedtest -f json -P 8
    }

    $jsonResult =$jsonRaw | ConvertFrom-Json

    $downloadMbps = [math]::Round(($jsonResult.download.bandwidth * 8 / 1000000), 2)$uploadMbps   = [math]::Round(($jsonResult.upload.bandwidth * 8 / 1000000), 2)$ping         = [math]::Round($jsonResult.ping.latency, 2)$timestamp    = Get-Date

    Write-Host ""
    Write-Host "===== Speedtest Results =====" -ForegroundColor Green
    Write-Host "Server   : $($jsonResult.server.name) ($($jsonResult.server.location))"
    Write-Host "Download : $downloadMbps Mbps"
    Write-Host "Upload   : $uploadMbps Mbps"
    Write-Host "Ping     : $ping ms"
    Write-Host "=============================" -ForegroundColor Green
    Write-Host ""

    # ==============================================================================
    # DATA PERSISTENCE (CSV LOGGING)
    # ==============================================================================
    if (-not (Test-Path $logFile)) {
        "Timestamp,DownloadMbps,UploadMbps,Ping" | Out-File -FilePath $logFile -Encoding utf8
    }

    "$($timestamp.ToString('g')),$downloadMbps,$uploadMbps,$ping" \vert{} Out-File -FilePath $logFile -Append -Encoding utf8

    # ==============================================================================
    # THRESHOLD AUDIT & EMAIL NOTIFICATION SYSTEM
    # ==============================================================================
    if ($downloadMbps -lt$minSpeedMbps) {
        Write-Host "Speed is below $minSpeedMbps Mbps - sending alert email..." -ForegroundColor Yellow
        
        $body = "Your download speed dropped to $downloadMbps Mbps. Time to reboot the cable modem!"

        $message = New-Object System.Net.Mail.MailMessage
        $message.From =$from
        $message.To.Add($to)
        $message.Subject =$subject
        $message.Body =$body

        $smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)$smtp.EnableSsl = $true$smtp.Credentials = New-Object System.Net.NetworkCredential($from,$appPassword)

        $smtp.Send($message)
        $message.Dispose()$smtp.Dispose()

        Write-Host "Alert email sent." -ForegroundColor Red
    }
    else {
        Write-Host "Speed acceptable (>= $minSpeedMbps Mbps). No email sent." -ForegroundColor Green
    }

    # ==============================================================================
    # GRAPH GENERATION & VISUALIZATION (24-HOUR WINDOW)
    # ==============================================================================
    Write-Host "Generating 24-hour speed chart..." -ForegroundColor Cyan
    $form =$null

    if (Test-Path $logFile) {
        $rawCsv = Import-Csv$logFile
        $cutoff = (Get-Date).AddHours(-24)$data = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($item in$rawCsv) {
            $itemTime = Get-Date$item.Timestamp
            if ($itemTime -ge$cutoff) {
                $data.Add($item)
            }
        }

        Write-Host "Found $($data.Count) data points in the last 24 hours." -ForegroundColor Gray

        if ($data.Count -gt 0) {$chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
            $chart.Width = 800
            $chart.Height = 400$chart.BackColor = [System.Drawing.Color]::White

            $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
            $chartArea.AxisX.Title = "Time"
            $chartArea.AxisY.Title = "Mbps"
            $chartArea.AxisY2.Title = "Ping (ms)"
            $chartArea.AxisY2.Enabled = [System.Windows.Forms.DataVisualization.Charting.AxisEnabled]::True$chartArea.AxisX.LabelStyle.Format = "HH:mm"
            $chart.ChartAreas.Add($chartArea)

            $legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend("Default")
            $legend.Docking = [System.Windows.Forms.DataVisualization.Charting.Docking]::Top$legend.Alignment = [System.Drawing.StringAlignment]::Center
            $chart.Legends.Add($legend)

            $seriesDown = New-Object System.Windows.Forms.DataVisualization.Charting.Series("Download (Mbps)")
            $seriesDown.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line$seriesDown.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime
            $seriesDown.BorderWidth = 3$seriesDown.Color = [System.Drawing.Color]::Blue

            $seriesUp = New-Object System.Windows.Forms.DataVisualization.Charting.Series("Upload (Mbps)")
            $seriesUp.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line$seriesUp.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime
            $seriesUp.BorderWidth = 3$seriesUp.Color = [System.Drawing.Color]::Green

            $seriesPing = New-Object System.Windows.Forms.DataVisualization.Charting.Series("Ping (ms)")
            $seriesPing.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
            $seriesPing.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime$seriesPing.BorderWidth = 2
            $seriesPing.Color = [System.Drawing.Color]::Orange$seriesPing.YAxisType = [System.Windows.Forms.DataVisualization.Charting.AxisType]::Secondary

            foreach ($row in $data) {$xVal = (Get-Date $row.Timestamp).ToOADate()$seriesDown.Points.AddXY($xVal, [double]$row.DownloadMbps) | Out-Null
                $seriesUp.Points.AddXY($xVal, [double]$row.UploadMbps)   \vert{} Out-Null$seriesPing.Points.AddXY($xVal, [double]$row.Ping)         | Out-Null
            }

            $chart.Series.Add($seriesDown)
            $chart.Series.Add($seriesUp)
            $chart.Series.Add($seriesPing)

            $chart.SaveImage($chartFile, [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png)

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Speedtest Results (24h)"
            $form.Size = New-Object System.Drawing.Size(820, 440)$form.StartPosition = "CenterScreen"
            $form.TopMost =$true

            $pictureBox = New-Object System.Windows.Forms.PictureBox
            $pictureBox.Dock = "Fill"
            $pictureBox.ImageLocation = $chartFile$pictureBox.SizeMode = "Zoom"
            $form.Controls.Add($pictureBox)

            $form.Show()
        }
    }

    # ==============================================================================
    # INTERACTIVE COUNTDOWN & TERMINAL PAUSE LOOP
    # ==============================================================================
    for ($i =$pauseDuration; $i -gt 0; $i--) {
        Write-Host "`rPausing for $i seconds (press any key to skip)... " -NoNewline -ForegroundColor Gray
        
        [System.Windows.Forms.Application]::DoEvents()
        
        if ([console]::KeyAvailable) {
            $null = [console]::ReadKey($true)
            Write-Host "`rPaused manually bypassed!                                     " -ForegroundColor Yellow
            break
        }
        
        Start-Sleep -Seconds 1
    }

    # ==============================================================================
    # CLEANUP WINDOW FOR NEXT LOOP
    # ==============================================================================
    if ($form) {
        $form.Close()$form.Dispose()
    }
}