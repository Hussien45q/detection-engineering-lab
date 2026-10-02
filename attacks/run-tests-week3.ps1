# run-tests-week3.ps1 - Detection Engineering Lab, Week 3 simulations
# Run ONLY inside the Windows Victim VM, in an Administrator PowerShell window:
#   powershell -ExecutionPolicy Bypass -File .\run-tests-week3.ps1
# Every test is harmless and cleans up after itself.

$ErrorActionPreference = 'SilentlyContinue'

function Run-Test($id, $rule, $name, [scriptblock]$action) {
    Write-Host ""
    Write-Host "[$id] $name  ->  expected Wazuh rule $rule" -ForegroundColor Cyan
    & $action
    Start-Sleep -Seconds 3
}

# 1. T1033 - account discovery (read-only)
Run-Test 'T1033' 100107 'whoami group listing' {
    whoami.exe /groups | Out-Null
}

# 2. T1069.001 - permission group discovery (read-only)
Run-Test 'T1069.001' 100108 'List local Administrators' {
    net.exe localgroup administrators | Out-Null
}

# 3. T1547.001 - Run key pointing to a file that does not exist, removed right away
Run-Test 'T1547.001' 100109 'Run key persistence (removed after 5s)' {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    New-ItemProperty -Path $key -Name 'LabTest' -Value 'C:\Users\Public\labtest.exe' -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 5
    Remove-ItemProperty -Path $key -Name 'LabTest' -Force
}

# 4. Defender visibility - repeat the Week 2 certutil test. Defender blocks it;
#    with Defender's log forwarded, the block itself should now alert.
Run-Test 'T1105' 62123 'certutil download (expect Defender block + alert)' {
    certutil.exe -urlcache -split -f https://www.example.com/ "$env:TEMP\labtest.txt" | Out-Null
    Remove-Item "$env:TEMP\labtest.txt" -Force
}

Write-Host ""
Write-Host "Done. In the Wazuh dashboard, search:  rule.id:(100107 or 100108 or 100109 or 62123)" -ForegroundColor Green
