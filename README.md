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

| # | MITRE ATT&CK | Technique | Wazuh rule | Level | Status |
|---|---|---|---|---|---|
| 1 | [T1059.001](detections/T1059.001-encoded-powershell.md) | Encoded PowerShell command | 100100 | 12 | ⬜ |
| 2 | T1105 | certutil file download (LOLBin) | 100101 | 12 | ⬜ |
| 3 | T1136.001 | Local account creation | 100102 | 10 | ⬜ |
| 4 | T1053.005 | Scheduled task creation | 100103 | 8 | ⬜ |
| 5 | T1003.001 | LSASS dump via comsvcs.dll | 100104 | 14 | ⬜ |
| 6 | T1070.001 | Event log clearing | 100105 | 12 | ⬜ |

✅ detected and documented · ⚠️ needs tuning · ⬜ not tested yet

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
- [ ] Week 2: first 6 custom detections, tested and documented
- [ ] Week 3: more techniques with Atomic Red Team (persistence, discovery, lateral movement)
- [ ] Week 4: tuning pass, false-positive notes, MITRE coverage summary, demo video

## Disclaimer

Everything here runs in an isolated lab. The attack simulations are harmless and clean up after themselves.
