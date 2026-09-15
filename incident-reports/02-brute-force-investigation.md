# Incident Report 02 – RDP Brute-Force Detection

## Summary
A simulated brute-force attack was performed against the Windows 11 VM from the Kali Linux VM. Multiple failed RDP authentication attempts were generated and detected in Splunk.

## Lab Environment
- Attacker: Kali Linux VM
- Target: Windows 11 VM
- SIEM: Splunk Enterprise
- Target service: Remote Desktop (RDP)
- Port: TCP 3389

## Detection
Windows recorded the failed authentication attempts as Security Event ID 4625.

Splunk detection query:

    index=* sourcetype="WinEventLog:Security" EventCode=4625
    | stats count as Failed_Attempts by Account_Name Source_Network_Address
    | where Failed_Attempts >= 5
    | sort - Failed_Attempts

## Findings
Splunk identified repeated failed authentication attempts originating from:

- Source IP: 192.168.106.129
- Target account: Oluwatobi
- Failed attempts observed: 11
- Windows Event ID: 4625

The repeated authentication failures from the same source are consistent with brute-force behavior generated during the lab simulation.

## Evidence
Screenshot:

`../screenshots/brute-force-detection-splunk.png`

## Response / Remediation
In a real environment, an analyst should investigate the source IP, review additional authentication activity, determine whether any login eventually succeeded, consider blocking the malicious source, and apply account lockout or other authentication protections where appropriate.

## Conclusion
The simulation successfully demonstrated the process of generating suspicious authentication activity, collecting Windows Security logs, analyzing the events in Splunk, and creating a reusable detection rule for repeated failed logins.
