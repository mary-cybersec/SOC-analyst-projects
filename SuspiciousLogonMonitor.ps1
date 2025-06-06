
# SuspiciousLogonMonitor.ps1
# Author: Mary
# Description: Monitors Windows Security Event Logs for suspicious logon activity (e.g., Logon Type 5) and maintains a rolling history.
# Optional: Sends alert emails for suspicious events

# === Configuration ===
$EventLogName = "Security"
$EventIDs = @(4624, 4625)  # Successful and failed logons
$DaysToScan = 1  # Scan events from the last 24 hours
$HistoryFile = "$env:USERPROFILE\Documents\LoginHistory.csv"
$MaxHistoryDays = 7  # Keep only the last 7 days of records

# === Optional Email Settings ===
$EnableEmail = $false  # Set to $true to enable email alerts
$SmtpServer = "smtp.example.com"
$SmtpFrom = "alerts@example.com"
$SmtpTo = "your.email@example.com"
$SmtpSubject = "⚠️ Suspicious Logon Detected"
$SmtpCredential = Get-Credential  # Only if email is enabled

# === Time Filter ===
$StartTime = (Get-Date).AddDays(-$DaysToScan)

# === Get Security Events ===
$Events = Get-WinEvent -FilterHashtable @{
    LogName = $EventLogName
    ID = $EventIDs
    StartTime = $StartTime
} | ForEach-Object {
    $Record = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID     = $_.Id
        User        = $Record.Event.EventData.Data |
                        Where-Object { $_.Name -eq "TargetUserName" } |
                        Select-Object -ExpandProperty '#text'
        LogonType   = $Record.Event.EventData.Data |
                        Where-Object { $_.Name -eq "LogonType" } |
                        Select-Object -ExpandProperty '#text'
        Workstation = $Record.Event.EventData.Data |
                        Where-Object { $_.Name -eq "WorkstationName" } |
                        Select-Object -ExpandProperty '#text'
        IPAddress   = $Record.Event.EventData.Data |
                        Where-Object { $_.Name -eq "IpAddress" } |
                        Select-Object -ExpandProperty '#text'
    }
}

# === Filter for Logon Type 5 (Service Logons) ===
$SuspiciousLogons = $Events | Where-Object { $_.LogonType -eq "5" }

# === Save to Rolling History CSV ===
if (-Not (Test-Path $HistoryFile)) {
    $SuspiciousLogons | Export-Csv -Path $HistoryFile -NoTypeInformation
} else {
    $AllLogons = Import-Csv $HistoryFile
    $Combined = $AllLogons + $SuspiciousLogons
    $Filtered = $Combined | Where-Object {
        (Get-Date $_.TimeCreated) -ge (Get-Date).AddDays(-$MaxHistoryDays)
    }
    $Filtered | Export-Csv -Path $HistoryFile -NoTypeInformation
}

# === Email Alert (optional) ===
if ($EnableEmail -and $SuspiciousLogons.Count -gt 0) {
    $Body = $SuspiciousLogons | Out-String
    Send-MailMessage -From $SmtpFrom -To $SmtpTo -Subject $SmtpSubject `
        -Body $Body -SmtpServer $SmtpServer -Credential $SmtpCredential
}

# === Output to Console ===
if ($SuspiciousLogons.Count -gt 0) {
    Write-Host "Suspicious Logons Detected:" -ForegroundColor Yellow
    $SuspiciousLogons | Format-Table
} else {
    Write-Host "No suspicious logons found in the last $DaysToScan day(s)." -ForegroundColor Green
}