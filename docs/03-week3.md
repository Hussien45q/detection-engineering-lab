# Week 3 – Defender visibility, discovery and persistence detections

Goal: close the Week 2 gap (attacks blocked by Defender raised no alert) and add three new techniques: T1033, T1069.001 and T1547.001.

## Step 1 – Forward Defender's event log (Windows Victim)

In an **Administrator** PowerShell on the Windows Victim:

```powershell
cd C:\lab
iwr -useb https://raw.githubusercontent.com/Hussien45q/detection-engineering-lab/main/setup/forward-defender-logs.ps1 -OutFile fdl.ps1
powershell -ExecutionPolicy Bypass -File .\fdl.ps1
```

The script backs up `ossec.conf`, adds the `Microsoft-Windows-Windows Defender/Operational` channel and restarts the agent. Check that the agent log shows `Analyzing event log: 'Microsoft-Windows-Windows Defender/Operational'`.

> If `Restart-Service WazuhSvc` reports that it cannot stop the service, run `Start-Service WazuhSvc` afterwards and check `Get-Service WazuhSvc` shows **Running**.

## Step 2 – Install the updated rules (Wazuh server)

```bash
sudo bash -c 'cd /var/ossec/etc/rules && \
  curl -sfLo detection_lab_rules.xml https://raw.githubusercontent.com/Hussien45q/detection-engineering-lab/main/rules/detection_lab_rules.xml && \
  /var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager && echo RULES-OK'
```

## Step 3 – Make sure the agent is connected

After a manager restart, check the agent before you run any test:

```bash
sudo /var/ossec/bin/agent_control -l
```

The Windows agent must be **Active**. If it shows **Pending** or **Disconnected**, restart it on the Windows Victim (`Stop-Service WazuhSvc -Force; Start-Service WazuhSvc`) and check again. Events that happen while the agent is disconnected can be lost (see finding 6 in the README).

## Step 4 – Run the Week 3 simulations (Windows Victim)

```powershell
cd C:\lab
iwr -useb https://raw.githubusercontent.com/Hussien45q/detection-engineering-lab/main/attacks/run-tests-week3.ps1 -OutFile w3.ps1
powershell -ExecutionPolicy Bypass -File .\w3.ps1
```

| Test | What it does | Expected alert |
|---|---|---|
| T1033 | `whoami /groups` | 100107 (level 6) |
| T1069.001 | `net localgroup administrators` | 100108 (level 8, twice: net + net1) |
| T1547.001 | HKCU Run value → `C:\Users\Public\labtest.exe`, removed after 5 s | 100109 (level 12) |
| T1105 | certutil download, blocked by Defender | 62123 (level 12) + 62124 |

## Step 5 – Check the alerts

Dashboard search:

```
rule.id:(100107 or 100108 or 100109 or 62123)
```

Or on the server:

```bash
sudo tail -n 4000 /var/ossec/logs/alerts/alerts.json | python3 -c 'import sys,json;[print(a["timestamp"][11:19],a["rule"]["id"],a["rule"]["level"],a["rule"]["description"][:70]) for a in map(json.loads,sys.stdin) if a["rule"]["id"].startswith(("1001","621"))]' | tail -n 12
```

## Results (4 Oct 2026)

```
13:04:30 100107  6 Discovery: whoami used to list groups or privileges
13:04:33 100108  8 Discovery: local Administrators group listed with net
13:04:33 100108  8 Discovery: local Administrators group listed with net
13:04:36 100109 12 Persistence: Run key entry points to a user-writable folder
13:18:58 62123  12 Windows Defender: Antimalware platform detected potentially unwanted software
13:18:58 62123  12 Windows Defender: Antimalware platform detected potentially unwanted software
13:19:40 62124   3 Windows Defender: Antimalware platform performed an action to protect
```

The Defender alerts come from the second certutil run, after the agent was reconnected.
