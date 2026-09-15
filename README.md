# Home SOC Lab
A hands-on Security Operations Center (SOC) lab built to practice security monitoring, threat detection, log analysis, alert creation, incident investigation, and MITRE ATT&CK mapping using Splunk, Sysmon, Windows 11, and Kali Linux.
## Project Overview
This project simulates a small SOC environment where Windows security activity is collected, forwarded to Splunk, analyzed, and investigated.
The lab demonstrates an end-to-end SOC workflow:
**Generate Activity → Collect Logs → Forward Events → Analyze in Splunk → Detect Suspicious Activity → Investigate → Alert → Document Incident**
The project currently focuses on two detection scenarios:
- Suspicious PowerShell execution
- Windows brute-force / repeated failed login attempts
---
## Lab Architecture
The environment includes:
- macOS host system
- VMware Fusion
- Windows 11 ARM virtual machine
- Kali Linux ARM virtual machine
- Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise
Windows security and Sysmon events are collected from the Windows VM and forwarded to Splunk for analysis.
---
## Detection 1 — Suspicious PowerShell Execution
A Splunk detection was created to identify suspicious PowerShell executions recorded by Sysmon.
The detection looks for PowerShell processes using suspicious command-line options such as:
- `ExecutionPolicy Bypass`
- `EncodedCommand`
- `-enc`
- `NoProfile`
Example SPL:
```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*powershell.exe"
(CommandLine="*-ExecutionPolicy Bypass*" OR
 CommandLine="*-EncodedCommand*" OR
 CommandLine="*-enc *" OR
 CommandLine="*-NoProfile*")
| table _time ComputerName User Image ParentImage CommandLine

Investigation

The detected PowerShell activity was reviewed in Splunk using Sysmon process creation telemetry.

Relevant information included:

* Timestamp
* Host
* User
* Process image
* Parent process
* Command line

The investigation is documented in:

incident-reports/01-suspicious-powershell-investigation.md

MITRE ATT&CK Mapping

Tactic: Execution
Technique: PowerShell
Technique ID: T1059.001 — PowerShell

⸻

Detection 2 — Brute-Force Login Attempts

Windows Security Event ID 4625 was used to identify failed authentication attempts.

Example SPL:

index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count as Failed_Attempts by Account_Name Source_Network_Address
| sort - Failed_Attempts

The detection helps identify accounts and source addresses generating repeated authentication failures.

Investigation

The brute-force investigation included analysis of:

* Failed login attempts
* Target accounts
* Source network addresses
* Event frequency
* Authentication activity over time

The investigation is documented in:

incident-reports/02-brute-force-investigation.md

Alerting

A scheduled Splunk alert named:

Brute Force Login Detection

was configured to automatically evaluate failed Windows authentication events.

MITRE ATT&CK Mapping

Tactic: Credential Access
Technique: Brute Force
Technique ID: T1110 — Brute Force

⸻

SOC Monitoring Dashboard

A Splunk dashboard was created to provide a centralized view of security activity.

Dashboard Panels

Suspicious PowerShell Execution

Displays suspicious PowerShell processes detected through Sysmon telemetry.

Brute Force Login Attempts

Displays failed authentication attempts grouped by account and source network address.

Failed Login Attempts Over Time

Displays failed authentication activity over time, making bursts or spikes in login failures easier to identify.

⸻

Incident Response Workflow

The lab follows a basic SOC investigation workflow:

1. Security activity occurs on the endpoint.
2. Windows/Sysmon records the event.
3. Splunk Universal Forwarder sends the event to Splunk.
4. Splunk searches analyze the telemetry.
5. Detection logic identifies suspicious behavior.
6. Alerts notify the analyst when detection conditions are met.
7. The analyst investigates related events.
8. Findings are mapped to MITRE ATT&CK.
9. Investigation results are documented in an incident report.

⸻

Repository Structure

Home-SOC-Lab/
├── configs/
├── detection-rules/
├── diagrams/
├── docs/
├── incident-reports/
│   ├── 01-suspicious-powershell-investigation.md
│   └── 02-brute-force-investigation.md
├── screenshots/
│   └── final-soc-dashboard.png
├── scripts/
├── LICENSE
└── README.md

⸻

Skills Demonstrated

This project demonstrates practical experience with:

* SOC monitoring
* SIEM fundamentals
* Splunk
* SPL queries
* Windows Event Logs
* Sysmon
* Log forwarding
* Security event analysis
* PowerShell detection
* Authentication monitoring
* Brute-force detection
* Alert configuration
* Incident investigation
* MITRE ATT&CK mapping
* Security documentation

⸻

Key Takeaways

Building this lab provided hands-on experience with the workflow a SOC analyst uses to move from raw endpoint telemetry to actionable security detections.

Instead of only generating logs, the project demonstrates the complete process of collecting security telemetry, writing detection logic, identifying suspicious behavior, investigating events, creating alerts, mapping activity to MITRE ATT&CK, building monitoring dashboards, and documenting findings.

Disclaimer

All attack simulations and security testing in this project were performed in an isolated lab environment for educational purposes.

### Then commit it
At the bottom of GitHub, use this commit message:
**`Update README with SOC detections, dashboard, and investigations`**
Then click **Commit changes**.
One important thing: don't add tools, detections, or accomplishments to the README unless we actually implemented them. This version is specifically based on the work we've completed in your lab.
After you commit it, **send me a screenshot of the rendered README**. I'll review the presentation, links, image, and formatting before we call the GitHub project finished. 
