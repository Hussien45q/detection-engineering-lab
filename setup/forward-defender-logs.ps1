# forward-defender-logs.ps1 - Week 3 setup for the Windows Victim
# Sends Microsoft Defender's own event log to Wazuh, so attacks that Defender
# BLOCKS still raise an alert (built-in Wazuh rule 62123, Defender event 1116).
# Run in an Administrator PowerShell window:
#   powershell -ExecutionPolicy Bypass -File .\forward-defender-logs.ps1

$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$channel = 'Microsoft-Windows-Windows Defender/Operational'
$block = "<localfile><location>$channel</location><log_format>eventchannel</log_format></localfile>"

$text = Get-Content $conf -Raw
if ($text -match [regex]::Escape($channel)) {
    Write-Host "Defender log is already forwarded - nothing to change." -ForegroundColor Yellow
} else {
    Copy-Item $conf "$conf.bak-week3" -Force
    $text = $text -replace '</ossec_config>\s*$', "$block`r`n</ossec_config>"
    Set-Content $conf $text -Encoding ASCII
    Restart-Service WazuhSvc
    Write-Host "Added Defender log to ossec.conf (backup: ossec.conf.bak-week3) and restarted the agent." -ForegroundColor Green
}

Start-Sleep -Seconds 15
Get-Service WazuhSvc | Format-Table -AutoSize Status, Name
Select-String -Path 'C:\Program Files (x86)\ossec-agent\ossec.log' -Pattern 'Defender|Connected to the server' |
    Select-Object -Last 4 | ForEach-Object { $_.Line }
