# MITRE ATT&CK Mapping – RDP Brute Force Detection

## Detection
RDP Brute Force Login Detection

## MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## Detection Method

The detection monitors Windows Security Event ID 4625, which represents failed logon attempts.

Multiple failed authentication attempts from the same source IP address within a short period may indicate brute-force activity.

Splunk is used to aggregate failed authentication attempts by account name and source network address.

## Lab Evidence

During the simulation, repeated failed RDP authentication attempts were generated from the Kali Linux VM against the Windows 11 VM.

Splunk detected the failed authentication events and identified repeated attempts originating from:

192.168.106.129

The activity was successfully detected and investigated in the Home SOC Lab.

## Detection Query

    index=* sourcetype="WinEventLog:Security" EventCode=4625
    | stats count as Failed_Attempts by Account_Name Source_Network_Address
    | sort - Failed_Attempts

## MITRE ATT&CK Reference

T1110 – Brute Force
Credential Access
