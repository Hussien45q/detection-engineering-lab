# Week 2 – Deploy the custom rules and test them

Because the VMs download the files straight from GitHub, you don't need copy-paste between your laptop and the VMs.

## Step 0 – Finish Week 1

In the **Windows Victim** admin PowerShell:

```powershell
sls 'connected to|error' 'C:\Program Files (x86)\ossec-agent\ossec.log' | select -last 5
```

You should see `Connected to the server`. In the dashboard, **Agents** should list the agent as **Active**. Take the VirtualBox snapshot **"Sysmon + agent working"**.

## Step 1 – Install the rules on the Wazuh server

In the **Wazuh_Server** terminal (you type the sudo password):

```bash
sudo curl -sL -o /var/ossec/etc/rules/detection_lab_rules.xml \
  https://raw.githubusercontent.com/Hussien45q/detection-engineering-lab/main/rules/detection_lab_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/detection_lab_rules.xml
sudo chmod 660 /var/ossec/etc/rules/detection_lab_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

`wazuh-analysisd -t` checks the rule file for mistakes. If it prints an error, the manager is **not** restarted. Send a screenshot of the error.

## Step 2 – Run the attack simulations on Windows Victim

In the **Windows Victim** admin PowerShell:

```powershell
cd C:\lab
iwr https://raw.githubusercontent.com/Hussien45q/detection-engineering-lab/main/attacks/run-tests.ps1 -OutFile run-tests.ps1
powershell -ExecutionPolicy Bypass -File .\run-tests.ps1
```

## Step 3 – Check the alerts

In the Wazuh dashboard, go to **Threat Hunting → Events** (or **Security events**) and search:

```
rule.groups:local_detections
```

You should see one alert per test (rule 100102 fires twice, for `net.exe` and `net1.exe`). You can also check on the server:

```bash
sudo grep -h '"groups":\["local_detections' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## Step 4 – Record the results

For each rule, take a screenshot of the alert, save it in `screenshots/`, and fill in its file in `detections/` (copy `TEMPLATE.md`). Then update the status column in the README table.

## If a rule doesn't fire

1. Check that Sysmon logged the process. On Windows Victim: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 20 | ? Id -eq 1 | select -first 5 TimeCreated,Message`
2. Check that the event reached Wazuh: search `data.win.system.eventID:1` in the dashboard.
3. If the event is there but no alert fires, compare the event's `data.win.eventdata.commandLine` with the rule's regex. Fixing that gap is exactly the detection-engineering work worth writing up.
