# MITRE ATT&CK Mapping — Brute Force Detection

## Detection

Windows Brute Force Login Detection

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** Brute Force
- **Technique ID:** T1110

## Detection Method

The detection monitors Windows Security Event ID `4625`, which represents failed logon attempts.

Failed authentication events are grouped into **5-minute time buckets** by account name and source network address.

The detection triggers when **5 or more failed authentication attempts** are observed for the same account and source network address within a 5-minute time bucket.

## Lab Evidence

During the lab simulation, repeated failed authentication attempts were generated against the Windows 11 VM.

Splunk successfully collected the Windows Security events and identified repeated failed authentication activity.

Observed activity included failed attempts originating from:

`192.168.106.129`

The activity was successfully detected and investigated in the Home SOC Lab.

## Detection Query

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as Failed_Attempts by _time Account_Name Source_Network_Address
| where Failed_Attempts >= 5
| sort - Failed_Attempts
```

## MITRE ATT&CK Reference

**T1110 — Brute Force**
