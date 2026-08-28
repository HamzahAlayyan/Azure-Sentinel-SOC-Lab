# Azure Sentinel SOC Lab

A cloud-based Security Operations Center (SOC) lab built with Microsoft Azure and Microsoft Sentinel to practice detection engineering, threat hunting, and incident response.

## Lab Overview

- **Cloud:** Microsoft Azure
- **SIEM:** Microsoft Sentinel  
- **Endpoint:** Windows 11 (SOC-WIN01)
- **Telemetry:** Windows Events + Sysmon
- **Agent:** Azure Monitor Agent

## Architecture

Windows Endpoint (SOC-WIN01)
        
Windows Events + Sysmon
Azure Monitor Agent
        
Data Collection Rules
Log Analytics Workspace
        
Microsoft Sentinel


## Current Detections

- Detection 1: Multiple Failed Logon Attempts (Credential Access)
- Detection 2: Suspicious PowerShell Encoded Command (Execution)
- Detection 3: PowerShell Network Connection (Command & Control)
- Detection 4: Scheduled Task Creation (Persistence)

## Skills Demonstrated

- Microsoft Azure
- Microsoft Sentinel & KQL
- Windows Event Log analysis
- Sysmon telemetry
- Detection engineering
- MITRE ATT&CK framework
- Incident response

## Lab Environment

| Component | Value |
|-----------|-------|
| Region | Spain Central |
| VM | Windows 11 Enterprise |
| Agent | Azure Monitor Agent |
| Telemetry | Sysmon + Windows Events |
| Log Sources | Security, Application, System, Sysmon, Task Scheduler |

---
 
**Lab Status:** Active Development
