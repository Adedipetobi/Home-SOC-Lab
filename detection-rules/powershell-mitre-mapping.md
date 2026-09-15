# Suspicious PowerShell Execution — MITRE ATT&CK Mapping

## Detection

This detection identifies suspicious PowerShell execution using Sysmon Event ID 1 (Process Creation).

The Splunk detection looks for PowerShell processes using suspicious command-line options such as:

- ExecutionPolicy Bypass
- EncodedCommand
- -enc
- NoProfile

## MITRE ATT&CK Mapping

**Technique:** Command and Scripting Interpreter: PowerShell  
**Technique ID:** T1059.001  
**Tactic:** Execution

PowerShell is a legitimate Windows administration tool that can also be abused by attackers to execute commands, scripts, encoded payloads, and other malicious activity.

## Data Source

- Sysmon Event ID 1 — Process Creation
- Windows endpoint telemetry
- Splunk Universal Forwarder
- Splunk Enterprise

## Detection Rule

See:

`powershell-detection.spl`
