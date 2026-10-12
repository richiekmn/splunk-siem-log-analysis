Watch me explain this lab: [LoomLink](https://www.loom.com/share/adf27b36e807457ea121ba9c0ebc6faa)

# splunk-siem-log-analysis

Built a working SIEM on Azure: Splunk Enterprise on an Ubuntu VM, Windows Security logs forwarded from my Active Directory domain controller, SPL searches, a security dashboard, and an automated alert.

# Lab 3: Splunk SIEM & Log Analysis

**Splunk Enterprise · Azure · SOC / Security Monitoring**

I deployed Splunk on an Ubuntu VM (named splunkVM for this lab) in Azure, forwarded the Windows Event Logs from my Active Directory domain controller (testVM from my Active Directory Lab) into it, then wrote SPL searches, built a security dashboard, and set up a scheduled alert. This is the workflow you would expect from a SOC analyst: get the logs in, search them, visualize them, and get notified when something looks wrong. Below is what I built, the searches I used, and what I took away.

This lab connects my previous labs: Lab 1 built the environment, Lab 2 was network level analysis, and Lab 3 is host and log level monitoring of that same environment. It also maps directly to cloud SIEM tooling.

| | |
|---|---|
| **Platform** | Splunk Enterprise on Ubuntu 24.04 Azure VM + Universal Forwarder on Windows Server Azure VM |
| **Time** | 6 hours across multiple sessions |

---

## What a SIEM is for

A real organization generates millions of log events a day across servers, workstations, firewalls, and cloud services. Without a SIEM, those logs sit in separate systems, and nobody can search across them or spot patterns. A **SIEM** (Security Information and Event Management) pulls it all into one searchable place. Its two core jobs are **correlation** (connecting events across systems to reveal patterns no single system would show) and **alerting** (automatically flagging suspicious conditions). When an alert fires, analysts search the logs to answer what happened, when, from where, and what was affected.

---

## Architecture


```
Windows Server VM (testVM, my domain controller from my Active Directory Lab) → Universal Forwarder installed here
        │
        │  Universal Forwarder  →  port 9997
        ▼
Ubuntu 24.04 VM (splunkVM) running Splunk Enterprise  →  indexes into windows_logs
        │
        │
        ▼
Splunk Web UI (port 8000) → SPL searches, dashboards, alerts
```

| NSG rule (Splunk VM) | Source | Why |
|---|---|---|
| 22 (SSH) | splunkVM's public IP | Admin access |
| 8000 (Splunk web UI) | splunkVM's public IP | Analyst access |
| 9997 (forwarder input) | testVM's private IP | Only my own VM can send logs, not the public internet |

<img width="1253" height="426" alt="SplunkLabPortRulesUbuntuVM" src="https://github.com/user-attachments/assets/68ca6022-5664-4e86-9eae-fbe13b7b2c51" />

Key concepts I needed:

- **Index:** a named storage bucket for events, like a database table. A dedicated `windows_logs` index lets me control retention and permissions separately from other sources.
- **Universal Forwarder:** a lightweight free agent that ships logs to Splunk over port 9997.
- **`inputs.conf`:** the forwarder config file that says which logs to collect and which index they land in.
- **SPL (Splunk Processing Language):** a pipeline language. Start with a search, then pipe the results through commands that filter, shape, and visualize.

---

## What I built

### 1. Deployed Splunk on an Ubuntu Azure VM
Created an Ubuntu 24.04 VM (Splunk needs at least 4 GB RAM) with the NSG rules above, scoped tightly rather than opened to the internet.

<img width="1613" height="287" alt="SplunkLabVMProvisioning" src="https://github.com/user-attachments/assets/4cbafa3e-adc3-4207-8e8d-056a42e8fd81" />

> `testVM` is my Windows VM serving as the log source for Splunk which will be deployed on `splunkVM` which is running Ubuntu

### 2. Connected over SSH with PuTTY and installed Splunk
I worked from a Windows machine, so I used **PuTTY** as my SSH client:

This is where I ran into my first hiccup. Azure provides a private key in **`.pem`** format, but PuTTY can only read **`.ppk`**files. Pointing PuTTY at the `.pem` file fails, so the key must be converted first with **PuTTYgen**, which installs alongside PuTTY.

**Convert the key (one time):**
1. Installed PuTTY (the 64-bit `.msi` from www.chiark.greenend.org.uk, run as Administrator), which includes PuTTYgen
2. Opened **PuTTYgen** → **Conversions → Import key** → selected the downloaded `.pem` file
3. Clicked **Save private key** to write out a `.ppk` file and saved it

<img width="452" height="361" alt="SplunkLabPuttyKeyConversion" src="https://github.com/user-attachments/assets/0e22f6d4-2ef2-48e4-8778-99b72ee68636" />


**Connect with the key:**
1. Opened **PuTTY** and entered the splunkVM's **public IP** (from the Azure portal) in **Host Name**, with **Port** `22` and **Connection type** `SSH`
2. Went to **Connection → Data** and set **Auto-login username** to the admin username I chose when creating splunkVM
3. Went to **Connection → SSH → Auth → Credentials**, clicked **Browse** next to **Private key file for authentication**, and selected the `.ppk`
4. Back on the **Session** page, saved the settings as a named session so I don't have to repeat this each time, then clicked **Open**
5. Accepted the host key alert, which appears the first time you connect to a new server

<img width="337" height="338" alt="SplunkLabPuttySSH" src="https://github.com/user-attachments/assets/792ce1e8-041d-4874-ae59-31eebafc209c" />
<img width="535" height="421" alt="SplunkLabUbuntuTerminal" src="https://github.com/user-attachments/assets/64cd7a81-4298-4bff-82a9-ae74b5a319d2" />


No password is typed because the key authenticates me. In PuTTY, a right click pastes clipboard text into the terminal, which is how I ran the commands below.

Then downloaded and installed Splunk, started it, and set it to launch on boot:

```bash
wget -O splunk-10.6.0.5-86587d4e3b27-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.6.0.5/linux/splunk-10.6.0.5-86587d4e3b27-linux-amd64.deb"
sudo dpkg -i splunk-10.6.0.5-86587d4e3b27-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
sudo /opt/splunk/bin/splunk enable boot-start
```
If the `wget` returns a 404, Splunk has released a newer version. Copy the current command from the download page on splunk.com. The web UI came up at `http://<splunkVM's public IP>:8000`.

### 3. Set up VNet Peering
Because my VMs are in two separate VNets, they cannot communicate unless I configure Vnet Peering. Peering allows me to create a direct private connection between the two VNets, and is necessary in this case because without it port 9997 traffic from the forwarder (testVM) never reaches the Splunk indexer (splunkVM) regardless of the rules I set.

**Go to portal.azure.com**
1. Search Virtual Networks → click on splunkVM’s VNet → click peerings in the left menu → Add
2. Set the peering link names so they are self describing: This VNet peering link name (splunkVM's) = splunk-vnet-to-ad-vnet → Remote VNet peering link name (testVM's) = ad-vnet-to-splunk-vnet
3. Under Remote virtual network select the Windows Server VM’s VNet (testVM's) → leave other settings as default → click Add
4. Azure creates the peering in both directions automatically. Wait until both peering links show status Connected before continuing
5. Go to the Windows Server VM and restart the forwarder in PowerShell as Administrator
```powershell
Restart-Service SplunkForwarder
```
<img width="1532" height="230" alt="SplunkLabPeeringSuccess" src="https://github.com/user-attachments/assets/e46b21e6-f0b3-469c-bf20-57b65f591f53" />

One thing to note is that I actually ran into an issue while setting up peering. The problem was that both VNets had overlapping address spaces, so they could not be peered. Although changing the address space of one of the VNets sounded simple enough, I had to perform a couple steps before Azure allowed me to change the address space of one of the VNets.
1. Add a new address space in the VNet you want to change while temporarily keeping the prexisting address space because the existing subnet is still in use due to the NIC being attached to the existing subnet
2. Create a new subnet corresponding to the new address space you added to the VNet
3. Move the NIC to the new subnet. If the private IP of the VM is dynamic (my was) Azure will assign the VM a new address from the new subnet
4. Restart the VM and verify that the private IP corresponds to the new subnet
5. If everything works and you've confirmed the VM's NIC is using the new subnet, you can safely remove the old existing subnet
6. Finally you can remove the old prexisting VNet address space without problems from Azure
7. Now the VNet should have a different address space than the other VNet, and peering should work fine

<img width="1912" height="287" alt="SplunkLabAddressRangeChange" src="https://github.com/user-attachments/assets/5a3375fd-9e46-4783-a069-fe9ad2587f02" />

> `vnet-eastus-1` originally had address range 172.16.0.0 which overlapped with `vnet-eastus-2`
<img width="1913" height="274" alt="SplunkLabAddressRange" src="https://github.com/user-attachments/assets/6b3ac500-6231-4c85-8f95-b2211c47544f" />

### 4. Enabled receiving and created an index
In the Splunk UI:
- **Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port** → `9997`
- **Settings → Indexes → New Index** → `windows_logs`

### 5. Installed the Universal Forwarder on the Windows domain controller
On the Lab 1 Windows Server VM, I installed the 64-bit Windows forwarder (`.msi`) and answered the installer screens carefully:

| Installer screen | What I chose |
|---|---|
| Installation type | **An on premises Splunk Enterprise instance** (not Splunk Cloud, which skips the receiving indexer screen) |
| Administrator credentials | `admin` with my own password (uncheck "generate random password") |
| Deployment Server | **Leave blank.** Pointing it at my own Splunk VM makes the forwarder phone home to the wrong place and no data flows |
| Receiving Indexer | The Splunk VM's **private IP** and port `9997` |

### 6. Configured `inputs.conf`
The forwarder only sends what it's told to. I created the file below to collect the Security, System, and Application logs into my `windows_logs` index:

```ini
# File location on Windows Server VM:
# C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
 
# Each section in square brackets defines one log source to collect
 
[WinEventLog://Security]
# The Security log contains all authentication events — logins, failures, lockouts
disabled = 0
# disabled=0 means enabled. disabled=1 would turn this source off.
start_from = oldest
# Collect historical events, not just new ones going forward
current_only = 0
evt_resolve_ad_obj = 1
# Resolve Active Directory object names so usernames appear instead of SIDs
index = windows_logs
# Required — without this line data goes to the main index not windows_logs
 
[WinEventLog://System]
# System log contains OS-level events — service starts/stops, driver failures
disabled = 0
index = windows_logs
 
[WinEventLog://Application]
# Application log contains events from installed applications
disabled = 0
index = windows_logs

```
Comments sit on their own lines on purpose: Splunk `.conf` files don't support comments after a setting on the same line, and the comment text can end up as part of the value.

Applied it with PowerShell:
```powershell
Restart-Service SplunkForwarder
```

### 6. Generated test activity
A fresh VM has mostly empty logs, so I ran a PowerShell log-generator script that creates a temporary test account and produces failed logons (4625), a successful logon (4624), service stop/start events (7036), application warnings, and repeated bad passwords to trigger a lockout (4740), then restarted the forwarder. 

```powershell
$logFile = 'C:\lab3-log-output.txt'
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
 
function Log($message, $color = 'White') {
    Write-Host $message -ForegroundColor $color
    Add-Content -Path $logFile -Value "[$timestamp] $message"
}
 
# Clear any previous run output
if (Test-Path $logFile) { Remove-Item $logFile }
Add-Content -Path $logFile -Value "Lab 3 Log Generator - Run started at $timestamp"
Add-Content -Path $logFile -Value '============================================='
 
Log 'Starting log generation...' Green
 
# Create a temporary test user account
$testUser = 'labtest.user'
$testPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
New-LocalUser -Name $testUser -Password $testPass -Description 'Splunk lab test account' -ErrorAction SilentlyContinue
Log "Created test user: $testUser" Gray
 
# --- Generate failed logon attempts (creates Security log activity) ---
Log 'Generating failed logon attempts (Security log activity)...' Yellow
$wrongPass = ConvertTo-SecureString 'WrongPassword!' -AsPlainText -Force
1..15 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $wrongPass)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}
Log '  Generated 15 failed logon attempts' Gray
 
# --- Generate successful login (Event ID 4624) ---
Log 'Generating successful login event (4624)...' Yellow
$correctPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($testUser, $correctPass)
Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c whoami' -Wait -ErrorAction SilentlyContinue
Log '  Generated successful login (Event ID 4624)' Gray
 
# --- Generate service start/stop events (Event ID 7036) ---
Log 'Generating service events (7036)...' Yellow
$services = @('Spooler','Schedule','Netlogon')
$services | ForEach-Object {
    Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name $_ -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Log "  Stopped and restarted service: $_" Gray
}
 
# --- Generate application log entries ---
Log 'Generating application log events...' Yellow
$eventSource = 'SplunkLabTest'
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName Application -Source $eventSource -ErrorAction SilentlyContinue
}
1..5 | ForEach-Object {
    Write-EventLog -LogName Application -Source $eventSource -EventId 1001 `
        -EntryType Warning -Message 'Splunk lab test event - application warning'
    Start-Sleep -Milliseconds 300
}
Log '  Generated 5 application log entries (Event ID 1001)' Gray
 
# --- Lock out the test account (Event ID 4740) ---
Log 'Generating account lockout event (4740)...' Yellow
$badCred = ConvertTo-SecureString 'BadPass!' -AsPlainText -Force
1..20 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $badCred)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 200
}
Log '  Account lockout triggered (Event ID 4740)' Gray
 
# --- Clean up the test account ---
Start-Sleep -Seconds 3
Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
Log "Removed test user: $testUser" Gray
 
# --- Restart the forwarder ---
Log 'Restarting forwarder to ship events to Splunk...' Yellow
Restart-Service SplunkForwarder -ErrorAction SilentlyContinue
Log '  SplunkForwarder restarted' Gray
 
$endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $logFile -Value '============================================='
Add-Content -Path $logFile -Value "Run completed at $endTime"
Add-Content -Path $logFile -Value 'Wait 60 seconds then run: index=windows_logs | head 100'
 
Write-Host ''
Write-Host '=============================================' -ForegroundColor Green
Write-Host 'Done. Output saved to C:\lab3-log-output.txt' -ForegroundColor Green
Write-Host 'Wait 60 seconds then search Splunk.' -ForegroundColor Green
Write-Host '=============================================' -ForegroundColor Green

```

After about 60 seconds, on the Splunk Web UI, I set the time range to **All time**, then searched the index using the SPL command below. This let me see events from the Security, System, and Application logs that confirmed data was flowing:
```spl
index=windows_logs | head 100
```

---

## The Windows Event IDs that matter

| Event ID | What it means | Why it matters |
|---|---|---|
| 4624 | Successful logon | Who logged in, when, and how (interactive, remote, service) |
| 4625 | Failed logon | Repeated failures can mean brute force |
| 4648 | Logon with explicit credentials | Seen in lateral movement; rare in normal environments |
| 4672 | Privileged logon | Admin-level rights assigned at logon |
| 4688 | New process created | The core of threat hunting: what actually ran |
| 4697 | Service installed | A favorite persistence mechanism for malware |
| 4740 | Account lockout | A trail of these can mean password spraying |

---

## SPL searches I wrote

**Confirm data is flowing:**
```spl
index=windows_logs | head 100
```

**Successful logins by account:**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name
| sort -count
```

**Detect after-hours logins:**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=tonumber(strftime(_time, "%H"))
| where hour < 7 OR hour > 19
| table _time, Account_Name, Account_Domain, ComputerName
| sort -_time
```
Account names ending in `$` are computer accounts, which is normal. A **human** account logging in after hours is what you'd investigate.

---

## The dashboard

I turned the searches into a Classic dashboard called **Windows Security Overview** for a permanent at-a-glance view instead of running searched by hand every time:

| Panel | Search | Visualization |
|---|---|---|
| Account Activity (24h) | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| stats count by Account_Name \| sort -count` | Bar chart |
| Top Processes (24h) | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4688 \| stats count by Creator_Process_Name \| sort -count \| head 20` | Events list |
| Login Activity Over Time | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| timechart count` | Line chart |
| After-Hours Logins | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| eval hour=strftime(_time, "%H") \| where hour < 7 OR hour > 19 \| table _time, Account_Name, Account_Domain, ComputerName \| sort -_time` | Events list |

**Account Activity (Last 24h)** — logon count by account. `testVM$` (the machine account) and SYSTEM dominate, which is the normal baseline. Knowing what normal looks like is what lets you spot the abnormal.
<img width="1504" height="290" alt="AccountActivity" src="https://github.com/user-attachments/assets/7f7b09f7-1279-48e6-a762-22f560685f9a" />

**Top Processes (Last 24h)** — process creation events (EventCode 4688) from `testVM.lab.local`. This is endpoint execution monitoring: seeing what ran, when, and under which account.
<img width="1506" height="856" alt="TopProcesses" src="https://github.com/user-attachments/assets/b563e019-500f-4278-84de-397c50198355" />

**Login Activity Over Time** — a `timechart` of logon volume. The spike to ~120 around 6 AM is the kind of shape an analyst learns to notice in a timeline.
<img width="1504" height="287" alt="LoginActivityOverTime" src="https://github.com/user-attachments/assets/3bc4172e-c576-4457-b246-a5b94bcda7f3" />

**After-Hours Logins** — successful logons (4624) filtered to outside business hours. This is a real detection use case, not just a chart.
<img width="1505" height="856" alt="AfterHoursLogins" src="https://github.com/user-attachments/assets/f2411a7b-ab2f-449f-b6e6-9eaedf7b627c" />

---

## Automated alert

Dashboards need a human watching them. An alert doesn't. I built one that runs on a schedule and records a hit when the condition is met, which is how real SOC detection works.

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4672
| stats count as privilege_logons by Account_Name, ComputerName
| where privilege_logons > 50
```

| Setting | Value |
|---|---|
| Name | High Privileged Logon Count |
| Type | Scheduled, cron `*/15 * * * *` (every 15 minutes) |
| Trigger condition | Number of results is greater than 0 |
| Action | Add to Triggered Alerts (history at **Activity → Triggered Alerts**) |

Saved as an alert named High Privileged Logon Count, set to run every 15 minutes. It's triggered when results are greater than 0, with the action set to Add to Triggered Alerts so every hit gets logged with a timestamp in Splunk's own alert history. Something to keep in mind is that alert quality is everything. Too broad and analysts get alert fatigue, too narrow and real threats slip through. The threshold is a starting point you tune from observed false positives.

---

## Problems and fixes

| What broke | Cause | Fix |
|---|---|---|
| PuTTY connection timed out | NSG rule for port 22 missing, or my public IP / the VM's IP changed | Check the 22 rule allows my current IP, and copy the VM's current public IP from the portal |
| PuTTY won't accept the Azure key | Azure's `.pem` isn't a format PuTTY can read | Convert it in PuTTYgen (**Conversions → Import key → Save private key**) and load the `.ppk` instead |
| "No supported authentication methods available" or "Access denied" | Username or private key not set in PuTTY | Set **Connection → Data → Auto-login username** and **Connection → SSH → Auth → Credentials → Private key file** to the `.ppk` |
| Web UI "site can't be reached" on :8000 | Missing NSG rule, Splunk stopped, or stale public IP | Add the 8000 rule from my IP; `sudo /opt/splunk/bin/splunk status`; `sudo ss -tlnp \| grep 8000`; re-check the current IP in the portal |
| No logs arriving | Port 9997 blocked, or VMs in different VNets | Add a 9997 NSG rule for the Windows VM's private IP; set up **VNet peering** (both links must show *Connected*), then `Restart-Service SplunkForwarder` |
| Forwarder installed but no data | Deployment Server field set to the Splunk VM | Leave Deployment Server blank; reinstall or fix the forwarder config |
| Public IP changed between sessions | Azure reassigns dynamic IPs on stop/start | Set the public IP assignment to **Static** |
| Events landing in the wrong index | `index =` line missing in `inputs.conf` | Add `index = windows_logs` to each stanza |
| Empty search results | Fresh VM, or time picker too narrow | Run the log generator and set the time range to All time |

---

## Key takeaways

1. **Getting data in is the whole first battle.** A SIEM is only as good as its inputs. Half this lab was forwarder config, NSG rules, and VNet peering, and that's true in production too.
2. **Know what normal looks like.** The baseline is mostly machine accounts and SYSTEM. You can't spot an abnormal login until you know that.
3. **SPL is the skill.** `stats`, `eval`, `where`, and `timechart` carried this entire lab. The analysts who find threats are the ones who can write the search.
4. **Alerts beat manually checking dashboards.** A scheduled alert watches for you, which is how detection scales.

If I did this again, I'd put all my lab VMs in **one shared VNet** with a subnet per environment (e.g., `10.0.1.0/24` for AD, `10.0.2.0/24` for Splunk) from the start. VMs in the same VNet can talk without peering, and NSG rules can be managed at the subnet level.

---

## SPL quick reference

```spl
index=windows_logs | head 100                                        # confirm data is flowing
... EventCode=4624 | stats count by Account_Name                      # logins by account
... EventCode=4625 | stats count by Account_Name                      # failed logins by account
... EventCode=4688 | stats count by Creator_Process_Name             # process execution
... EventCode=4740                                                    # account lockouts
... | eval hour=tonumber(strftime(_time,"%H")) | where hour<7 OR hour>19   # after-hours filter
... | timechart count                                                 # volume over time
```

---

## Verification

| Check | How I verified it |
|---|---|
| Data flowing | `index=windows_logs \| head 10` returns recent events |
| Login search works | The 4624 search returns results |
| Dashboard works | **Windows Security Overview** shows populated panels |
| Alert active | **Settings → Searches, Reports, and Alerts** lists *High Privileged Logon Count* as Enabled |

---

## Next steps

- Add a brute-force detection on failed logons (4625) with a short time window:
  ```spl
  index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
  | bin _time span=5m
  | stats count by _time, Account_Name
  | where count > 10
  ```
- Enable TLS between the forwarder and indexer, and put Splunk Web behind HTTPS
- Forward Azure activity logs and correlate them with the Windows events

---

**Status: complete.** Splunk deployed → Universal Forwarder configured → logs flowing into `windows_logs` → SPL searches → security dashboard → automated alert.
