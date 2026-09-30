# <Technique ID> – <Detection name>

| Field | Value |
|---|---|
| MITRE ATT&CK | [<ID>](https://attack.mitre.org/techniques/<ID>/) |
| Wazuh rule | <rule id> (level <n>) |
| Log source | Sysmon Event ID 1 – Process creation |
| Status | ⬜ Not tested / ✅ Detected / ⚠️ Needs tuning |

## What the attacker does
One or two sentences, in your own words.

## How I simulated it
```powershell
<command from attacks/run-tests.ps1>
```

## What the logs showed
The key fields from the Sysmon event (image, commandLine, parentImage, user).

## The detection logic
Explain the rule in plain words: what it matches and why.

## Result
![alert](../screenshots/<file>.png)

## False positives and tuning
What legitimate activity could trigger this rule, and what you changed (or would change) to reduce the noise.
