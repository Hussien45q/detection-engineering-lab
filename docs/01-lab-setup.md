# Week 1 – Lab setup

## Virtual machines (VirtualBox, host-only network 192.168.56.0/24)

| VM | Role | Details |
|---|---|---|
| Wazuh_Server | SIEM | Ubuntu, Wazuh manager + indexer + dashboard, 192.168.56.101 |
| Windows Victim | Monitored endpoint | Windows 10, Sysmon + Wazuh agent 4.9.2 |

## Sysmon

- Sysmon v15 from Sysinternals
- Config: [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), a widely used baseline that logs process creation, network connections, file creation and registry changes while filtering common noise

```powershell
iwr https://download.sysinternals.com/files/Sysmon.zip -OutFile s.zip; Expand-Archive s.zip -Force
iwr https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile c.xml
.\s\Sysmon64.exe -accepteula -i c.xml
```

## Wazuh agent

```powershell
iwr https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile w.msi
Start-Process msiexec.exe '/i w.msi /q WAZUH_MANAGER=192.168.56.101' -Wait
```

Sysmon events are forwarded by adding this block to `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then restart the agent: `Restart-Service WazuhSvc`.

## Verification

- Agent log shows `Valid key received` and `Connected to the server`
- The agent shows as **Active** in the Wazuh dashboard
- Sysmon events are searchable with `data.win.system.channel:Microsoft-Windows-Sysmon/Operational`

## Problems I hit (and fixed)

- **No shared clipboard between host and VM** (Guest Additions not installed). I installed everything with short commands typed directly into the VM, and later pulled files from GitHub with `iwr`/`curl`.
- **Disk space on C:**. I moved the VM disks to D: with VirtualBox's Move function.
- **PowerShell not elevated**. Installing Sysmon and the agent needs an *Administrator* PowerShell.
