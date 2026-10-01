# Detection Engineering Home Lab

Hands-on SOC lab: I simulate real attacker techniques on a Windows endpoint, collect the telemetry with **Sysmon**, and write and tune my own **Wazuh** detection rules mapped to **MITRE ATT&CK**.

**Skills shown:** SIEM (Wazuh), endpoint telemetry (Sysmon), detection rule writing, MITRE ATT&CK mapping, attack simulation, log analysis, false-positive tuning, technical documentation.

## Architecture

```mermaid
flowchart LR
    A[Attack simulation<br/>run-tests.ps1] --> B[Windows 10 victim<br/>Sysmon]
    B -->|Wazuh agent<br/>TCP 1514| C[Wazuh manager<br/>custom rules 1001xx]
    C --> D[Wazuh dashboard<br/>alerts + MITRE view]
```

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox, isolated host-only network |
| SIEM | Wazuh 4.x (manager, indexer, dashboard) on Ubuntu |
| Endpoint | Windows 10 + Sysmon (SwiftOnSecurity config) + Wazuh agent |

## Detections

| # | MITRE ATT&CK | Technique | Wazuh rule | Level | Result |
|---|---|---|---|---|---|
| 1 | [T1059.001](detections/T1059.001-encoded-powershell.md) | Encoded PowerShell command | 100100 + 100106 | 12 | ✅ Detected (after tuning) |
| 2 | T1105 | certutil file download (LOLBin) | 100101 | 12 | 🛡️ Blocked by Defender before execution |
| 3 | T1136.001 | Local account creation | 100102 | 10 | ✅ Detected |
| 4 | T1053.005 | Scheduled task creation | 100103 | 8 | ✅ Detected |
| 5 | T1003.001 | LSASS dump via comsvcs.dll | 100104 | 14 | ✅ Detected |
| 6 | T1070.001 | Event log clearing | 100105 | 12 | ✅ Detected |

**Test run 1 (Oct 2026): 5 of 6 techniques detected by custom rules; the 6th was prevented by the endpoint's antivirus.**

## Findings from testing

1. **Rule precedence matters.** The first run, rule 100100 never fired. The alert log showed the event had been claimed by Wazuh's built-in rule **92057** ("Powershell.exe spawned a powershell process which executed a base64 encoded command"). Wazuh evaluates child rules in load order and only the first match continues, so built-in rules shadow later custom rules on the same parent. **Fix:** companion rule **100106**, chained to 92057 with `<if_sid>`, so the lab's detection fires whenever the built-in one does.
2. **Prevention before detection.** The certutil download never produced a Sysmon process-creation event. `Get-MpThreatDetection` showed Microsoft Defender blocked it at launch. The rule is still useful on hosts where Defender is disabled or bypassed. A follow-up is to forward Defender's own event log to Wazuh so the block itself raises an alert.
3. **Validated end to end.** Each alert was confirmed in `/var/ossec/logs/alerts/alerts.json` on the manager, not just in the endpoint's logs.

## Repository layout

```
rules/detection_lab_rules.xml   custom Wazuh rules
attacks/run-tests.ps1           safe attack simulations (with cleanup)
detections/                     one write-up per detection
docs/01-lab-setup.md            how the lab was built
docs/02-deploy-and-test.md      how to deploy the rules and run the tests
screenshots/                    alert evidence
```

## Roadmap

- [x] Week 1: Wazuh server, Windows victim, Sysmon, agent
- [x] Week 2: first 6 custom detections deployed and tested (5 detected, 1 prevented)
- [ ] Week 3: more techniques with Atomic Red Team (persistence, discovery, lateral movement)
- [ ] Week 4: tuning pass, false-positive notes, MITRE coverage summary, demo video

## Disclaimer

Everything here runs in an isolated lab. The attack simulations are harmless and clean up after themselves.
