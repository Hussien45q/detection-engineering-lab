# Defender visibility – alerting on attacks the antivirus blocks

| Field | Value |
|---|---|
| MITRE ATT&CK | [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) (the blocked certutil download) |
| Wazuh rules | Built-in 62123 (level 12, Defender event 1116) and 62124 (level 3, event 1117) |
| Log source | `Microsoft-Windows-Windows Defender/Operational` event log |
| Status | ✅ Detected (after adding the log source) |

## The problem from Week 2
The `certutil -urlcache -f <url>` test never produced a Sysmon process-creation event: **Microsoft Defender blocked it at launch**, so my rule 100101 had nothing to match. The attack was stopped, but the SOC saw nothing. An analyst should still know that someone *tried* to use a LOLBin to download a file, because it often means a foothold or an active intruder.

## What I changed
Defender records its own detections in the `Microsoft-Windows-Windows Defender/Operational` channel, which the Wazuh agent does not collect by default. [`setup/forward-defender-logs.ps1`](../setup/forward-defender-logs.ps1) adds this block to the agent's `ossec.conf` and restarts the agent:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

No custom rule was needed: Wazuh's built-in ruleset already decodes Defender events (rules 62100–62199).

## How I tested it
The same harmless command as Week 2 (it fetches the example.com home page):
```powershell
certutil.exe -urlcache -split -f https://www.example.com/ "$env:TEMP\labtest.txt"
```
Defender blocked it ("Access is denied"); `Get-MpThreatDetection` recorded the detection.

## Result
✅ The manager raised:
- **62123, level 12** – "Antimalware platform detected potentially unwanted software" (event 1116, fired twice),
- **62124, level 3** – "Antimalware platform performed an action to protect" (event 1117).

So the blocked attempt is now a level-12 alert next to the custom detections.

## Lessons from the test
1. **Agent health is part of detection.** On the first Week 3 run, the Defender event was logged on the endpoint (event 1116 at 03:04:44) but **never reached Wazuh**, even though the Sysmon-based alerts from seconds earlier did. The agent log showed `Server unavailable` errors, and the manager listed the agent as **Pending** in `agent_control -l`. After restarting the agent service and re-running the test, the Defender alerts arrived. In production, agent-disconnected alerts need the same attention as security alerts, because a silent agent is a blind spot.
2. **Rule descriptions can lose fields.** The built-in 62123 description uses `$(win.eventdata.severityName)` and `$(win.eventdata.processName)`, but they came out empty with this Defender version. The alert still fires. A small local override of the description, using the fields Defender actually sends, would make triage faster.
