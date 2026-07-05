# SentinelAI — VM3 Sysmon Configuration

## Overview

VM3 (Windows 10 endpoint) uses Sysmon with the SwiftOnSecurity configuration
to generate detailed endpoint telemetry. This telemetry is collected by the
Wazuh agent and forwarded to VM1 for analysis.

## Installation Steps

### 1. Download Sysmon

Download Sysmon from Microsoft Sysinternals:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

### 2. Download the SwiftOnSecurity config

The SwiftOnSecurity configuration is a community-maintained Sysmon config that
covers 400+ attack scenarios with sensible defaults:
https://github.com/SwiftOnSecurity/sysmon-config

Download `sysmonconfig-export.xml`.

### 3. Install Sysmon with the config

Open PowerShell **as Administrator**:

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### 4. Verify installation

```powershell
Get-Service Sysmon64
```

Should show "Running".

## Key Sysmon Event IDs Captured

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 1 | Process Create | Captures command line, hashes, parent process — primary detection source |
| 3 | Network Connection | Source/dest IP and port for every connection |
| 7 | Image Loaded | DLL loading (detects injection) |
| 10 | Process Access | Detects LSASS access (credential theft) |
| 11 | File Create | Detects malware drops to disk |
| 13 | Registry Value Set | Detects persistence via registry |
| 22 | DNS Query | Detects C2 domain lookups |

## Configuration Notes

- The SwiftOnSecurity config is well-commented — review it to understand what
  is included and excluded
- For the SentinelAI detection rules, Event IDs 1, 3, 10, and 11 are the most
  important
- Sysmon runs as a kernel-mode driver, making it difficult for user-mode
  malware to tamper with

## Verifying Telemetry Flow

After Sysmon and the Wazuh agent are both installed:

1. Run any process on VM3 (e.g., open Notepad)
2. Check the Wazuh dashboard on VM1 — you should see Sysmon Event ID 1 alerts
3. This confirms the telemetry pipeline: Sysmon → Wazuh agent → VM1

## Lab Constraint: Windows Defender

For attack simulation, Windows Defender real-time protection is disabled so
test payloads can execute:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**This is a controlled lab environment practice only.** In production, endpoint
protection would remain enabled and SentinelAI would complement it.
