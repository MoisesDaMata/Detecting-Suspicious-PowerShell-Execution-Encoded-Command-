# Detecting Suspicious PowerShell Execution Encoded Command

## Objective

This lab demonstrates how a Security Operations Center (SOC) can detect suspicious PowerShell execution using Base64 encoded commands.

Attackers frequently use encoded PowerShell commands to evade detection and hide malicious payloads.

In this lab we simulate an attacker executing an encoded PowerShell command on a Windows machine and show how Wazuh detects the activity through Windows Security Event Logs.
## Lab Architecture
Attacker: Kali Linux
Target: Windows 10
SIEM: Wazuh Server

Diagrama
Kali Linux → Windows Target → Wazuh Agent → Wazuh SIEM
## Attack Simulation

The attacker executes a PowerShell command using the `-EncodedCommand` parameter.

Encoded commands are commonly used by attackers to obfuscate malicious scripts.

Example command executed on the target system:

powershell.exe -EncodedCommand <Base64EncodedPayload>

For demonstration purposes the payload launches `calc.exe`.
## Detection (Wazuh)

Wazuh detects the suspicious activity by analyzing Windows Security Event ID 4688 (Process Creation).

The alert is triggered when PowerShell executes a command using the `EncodedCommand` parameter.

Relevant fields observed in the alert:

* Event ID: 4688
* Parent Process: powershell.exe
* New Process Name: C:\Windows\System32\calc.exe
## Log Analysis

During investigation the SOC analyst reviews the Windows Security logs.

Key indicators:

Parent Process:
powershell.exe

Child Process:
C:\Windows\System32\calc.exe

PowerShell launching system processes using encoded commands is a common indicator of malicious activity.
## Investigation Steps

A SOC analyst should perform the following steps:

1. Verify the user account that executed the PowerShell command
2. Check the source host and IP address
3. Review the PowerShell command line arguments
4. Investigate other processes spawned by PowerShell
5. Correlate with other suspicious events in the same timeframe
## MITRE ATT&CK Mapping

Technique: T1059.001
Execution: PowerShell

Attackers use PowerShell to execute malicious scripts and commands on compromised systems.
## Response Actions

Recommended response actions:

* Isolate the affected host
* Investigate PowerShell command history
* Search for persistence mechanisms
* Reset potentially compromised credentials
* Scan the system for malware
## Lessons Learned

Encoded PowerShell commands are frequently used by attackers to bypass detection.

Monitoring process creation events and PowerShell activity is critical for early detection of post-exploitation techniques.
