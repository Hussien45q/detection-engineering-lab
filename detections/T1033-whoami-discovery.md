# T1033 – Account discovery with whoami

| Field | Value |
|---|---|
| MITRE ATT&CK | [T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) |
| Wazuh rule | 100107 (level 6) |
| Log source | Sysmon Event ID 1 – Process creation |
| Status | ✅ Detected |

## What the attacker does
After an attacker gets onto a machine, one of the first things they check is who they are and what rights they have. `whoami /groups`, `/priv` and `/all` show whether the account is an administrator and which privileges (such as SeDebugPrivilege) it holds. That tells the attacker whether they need to escalate privileges before going further.

## How I simulated it
```powershell
whoami.exe /groups | Out-Null
```
The command only reads information and changes nothing.

## What the logs showed
Sysmon Event ID 1 recorded `C:\Windows\System32\whoami.exe` with the command line `"C:\Windows\system32\whoami.exe" /groups`, started by `powershell.exe`.

## The detection logic
The rule fires when a Sysmon process-creation event has:
- `image` ending in `\whoami.exe`, **and**
- a command line that contains `/all`, `/priv` or `/groups`.

A bare `whoami` (just the user name) is common in scripts and support work, so it is left out on purpose. The flags that list groups and privileges are the ones attackers use when planning privilege escalation.

## Result
✅ Rule 100107 fired within seconds (confirmed in `/var/ossec/logs/alerts/alerts.json` on the manager, test run 2, 4 Oct 2026).

## False positives and tuning
Administrators and some inventory tools also run `whoami /groups`. That is why the level is kept low (6): one alert on its own is just context. In a real SOC this rule is most useful **correlated** with other discovery commands from the same host within a few minutes, for example 100107 followed by 100108. A Wazuh `frequency`/`if_matched_sid` rule could raise a single higher-severity "discovery burst" alert.
