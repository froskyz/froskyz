# 🔐 SSH Log Analysis using Splunk
 
> Detect, investigate, and visualize SSH-based threats using Splunk SIEM — covering brute-force attacks, unauthorized access attempts, and anomalous login behavior.
 
---
 
## 📌 Overview
 
This project demonstrates how to use **Splunk** to ingest, parse, and analyze SSH authentication logs (`/var/log/auth.log` or `/var/log/secure`) to identify security threats in real time. It includes SPL queries, dashboard configurations, and alert rules tailored for SSH threat hunting.
 
---
 
## 🎯 Objectives
 
- Ingest SSH logs into Splunk using a Universal Forwarder or file monitor
- Detect brute-force login attempts and credential stuffing
- Identify successful logins after multiple failures (potential compromise)
- Visualize attacker IPs, targeted usernames, and geo-locations
- Set up real-time alerts for critical SSH events
---
 
## 🧰 Prerequisites
 
| Tool | Version |
|------|---------|
| Splunk Enterprise / Splunk Free | 9.x+ |
| Splunk Universal Forwarder | 9.x (optional) |
| Linux host generating SSH logs | Ubuntu / CentOS / RHEL |
| SSH log path | `/var/log/auth.log` or `/var/log/secure` |
 
---
 
## 📁 Project Structure
 
```
ssh-log-analysis-splunk/
├── README.md
├── inputs/
│   └── inputs.conf              # Splunk forwarder config to monitor SSH logs
├── transforms/
│   └── transforms.conf          # Field extractions for SSH events
├── searches/
│   ├── brute_force_detection.spl
│   ├── successful_logins.spl
│   ├── failed_logins_by_ip.spl
│   └── geo_lookup.spl
├── dashboards/
│   └── ssh_analysis_dashboard.xml
└── alerts/
    └── brute_force_alert.xml
```
 
---
 
## ⚙️ Setup
 
### 1. Configure Log Ingestion
 
Add the following to your **Splunk Universal Forwarder** or local `inputs.conf`:
 
```ini
# inputs/inputs.conf
[monitor:///var/log/auth.log]
index = linux_logs
sourcetype = linux_secure
disabled = false
```
 
> On RHEL/CentOS, replace `auth.log` with `/var/log/secure`.
 
### 2. Set the Source Type
 
In Splunk Web: **Settings → Source Types → linux_secure**  
Or define it in `props.conf`:
 
```ini
[linux_secure]
TIME_PREFIX = ^
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 20
SHOULD_LINEMERGE = false
```
 
---
 
## 🔍 SPL Queries
 
### 🚨 Brute Force Detection — Failed Logins > Threshold
 
```spl
index=linux_logs sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failures by src_ip, username
| where failures > 10
| sort -failures
| rename src_ip as "Source IP", username as "Targeted User", failures as "Failed Attempts"
```
 
---
 
### ✅ Successful Logins
 
```spl
index=linux_logs sourcetype=linux_secure "Accepted password" OR "Accepted publickey"
| rex field=_raw "Accepted \S+ for (?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, src_ip, username, host
| sort -_time
```
 
---
 
### 🔥 Compromise Indicator — Success After Many Failures
 
```spl
index=linux_logs sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex field=_raw "(?P<status>Failed|Accepted) password for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(status="Failed")) as failures, count(eval(status="Accepted")) as successes by src_ip, username
| where failures > 5 AND successes > 0
| eval risk="HIGH - Possible Compromise"
| table src_ip, username, failures, successes, risk
```
 
---
 
### 🌍 Geo-Location of Attacking IPs
 
```spl
index=linux_logs sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| stats count by src_ip, Country, City
| sort -count
```
 
---
 
### 👤 Invalid User Login Attempts
 
```spl
index=linux_logs sourcetype=linux_secure "Invalid user"
| rex field=_raw "Invalid user (?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by username, src_ip
| sort -count
```
 
---
 
## 📊 Dashboard
 
Import `dashboards/ssh_analysis_dashboard.xml` into Splunk:
 
1. Go to **Search & Reporting → Dashboards → Create New Dashboard**
2. Switch to **Source** view
3. Paste the contents of `ssh_analysis_dashboard.xml`
The dashboard includes panels for:
- Failed login attempts over time (line chart)
- Top attacking IPs (bar chart)
- Geo-map of attack origins
- Successful logins timeline
- High-risk IP table
---
 
## 🔔 Alerts
 
### Brute Force Alert — Real-time
 
```spl
index=linux_logs sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 20
```
 
**Alert Settings:**
- **Schedule:** Real-time or every 5 minutes
- **Trigger:** Number of results > 0
- **Action:** Send email / Slack webhook / create notable event
---
 
## 🧪 Testing with Sample Logs
 
To test without a live SSH server, replay sample log data:
 
```bash
# Upload sample auth.log to Splunk via UI:
# Settings → Add Data → Upload → Select auth.log → Set sourcetype: linux_secure
```
 
A sample log entry looks like:
 
```
Jun 21 14:32:01 server01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2
Jun 21 14:32:15 server01 sshd[1235]: Accepted password for ubuntu from 10.0.0.5 port 22 ssh2
```
 
---
 
## 📈 Key Metrics to Monitor
 
| Metric | SPL Field | Threshold |
|--------|-----------|-----------|
| Failed logins per IP | `failures` | > 10 in 5 min |
| Unique usernames tried | `dc(username)` | > 5 per IP |
| Login success after failures | `successes > 0 AND failures > 5` | Any |
| Logins from new countries | `iplocation` delta | First seen |
 
---
 
## 🛡️ Hardening Recommendations
 
Based on findings from your Splunk analysis, consider:
 
- Block high-frequency attacker IPs using `fail2ban` or firewall rules
- Disable password authentication — enforce SSH key-based login only
- Change the default SSH port (22) to reduce noise
- Implement multi-factor authentication (MFA) for SSH
- Use `AllowUsers` in `sshd_config` to whitelist authorized users
---
 
## 📚 Resources
 
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk `iplocation` Command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Iplocation)
- [Linux auth.log Format](https://man7.org/linux/man-pages/man8/sshd.8.html)
- [MITRE ATT&CK — Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
---
