# run-tests.ps1 - Detection Engineering Lab attack simulations
# Run ONLY inside the Windows Victim VM, in an Administrator PowerShell window:
#   powershell -ExecutionPolicy Bypass -File .\run-tests.ps1
# Every test is harmless: it reproduces the command line an attacker would use,
# and cleans up after itself. Nothing is actually stolen, hidden or destroyed.
# Windows Defender may block or flag some tests - that is expected in a lab.

$ErrorActionPreference = 'SilentlyContinue'

function Run-Test($id, $rule, $name, [scriptblock]$action) {
    Write-Host ""
    Write-Host "[$id] $name  ->  expected Wazuh rule $rule" -ForegroundColor Cyan
    & $action
    Start-Sleep -Seconds 3
}

# 1. T1059.001 - Encoded PowerShell (prints a message, nothing else)
Run-Test 'T1059.001' 100100 'Encoded PowerShell command' {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'T1059.001 lab test'"))
    powershell.exe -NoProfile -EncodedCommand $b64
}

# 2. T1105 - certutil download of a harmless web page, then delete it
Run-Test 'T1105' 100101 'certutil file download' {
    certutil.exe -urlcache -split -f https://www.example.com/ "$env:TEMP\labtest.txt" | Out-Null
    Remove-Item "$env:TEMP\labtest.txt" -Force
    certutil.exe -urlcache * delete | Out-Null
}

# 3. T1136.001 - create a local user, then delete it
Run-Test 'T1136.001' 100102 'Local account creation' {
    net.exe user labtest1 'Lab!Test2026x' /add | Out-Null
    net.exe user labtest1 /delete | Out-Null
}

# 4. T1053.005 - create a scheduled task, then delete it
Run-Test 'T1053.005' 100103 'Scheduled task creation' {
    schtasks.exe /create /tn LabTest /tr "cmd.exe /c echo lab" /sc once /st 23:59 /f | Out-Null
    schtasks.exe /delete /tn LabTest /f | Out-Null
}

# 5. T1003.001 - comsvcs MiniDump against a PID that does not exist (no dump is created)
Run-Test 'T1003.001' 100104 'LSASS dump via comsvcs (fake PID)' {
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 99999 "$env:TEMP\lab.dmp" full
    Remove-Item "$env:TEMP\lab.dmp" -Force
}

# 6. T1070.001 - try to clear a log that does not exist (no real logs are cleared)
Run-Test 'T1070.001' 100105 'Event log clearing' {
    wevtutil.exe cl LabFakeLog 2>$null
}

Write-Host ""
Write-Host "Done. In the Wazuh dashboard, search:  rule.groups:local_detections" -ForegroundColor Green
