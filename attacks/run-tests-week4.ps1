# run-tests-week4.ps1 - Detection Engineering Lab, Week 4 simulations
# Run ONLY inside the Windows Victim VM, in an Administrator PowerShell window:
#   powershell -ExecutionPolicy Bypass -File .\run-tests-week4.ps1
# Every test is harmless: the commands only read information, and the Wazuh
# agent is started again 20 seconds after it is stopped.

$ErrorActionPreference = 'SilentlyContinue'

# 1. Discovery burst - several read-only discovery commands within a few seconds.
#    Each one alerts on its own (100107 / 100108); together they should also
#    trigger the correlation rule 100110.
Write-Host ""
Write-Host "[Burst] 4 discovery commands in quick succession  ->  expected 100107, 100108, then 100110" -ForegroundColor Cyan
whoami.exe /groups | Out-Null
Start-Sleep -Seconds 2
whoami.exe /priv | Out-Null
Start-Sleep -Seconds 2
whoami.exe /all | Out-Null
Start-Sleep -Seconds 2
net.exe localgroup administrators | Out-Null

# Give the agent time to send these events before it is stopped below.
Start-Sleep -Seconds 20

# 2. T1562.001 - the security agent is stopped (what an attacker does to go dark).
Write-Host ""
Write-Host "[T1562.001] Stop the Wazuh agent for 20 seconds  ->  expected 100112" -ForegroundColor Cyan
Stop-Service WazuhSvc -Force
Start-Sleep -Seconds 20
Start-Service WazuhSvc
Start-Sleep -Seconds 10
Get-Service WazuhSvc | Format-Table -AutoSize Status, Name

Write-Host ""
Write-Host "Done. In the Wazuh dashboard, search:  rule.id:(100110 or 100112)" -ForegroundColor Green
