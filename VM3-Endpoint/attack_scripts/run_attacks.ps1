# SentinelAI — Attack Simulation Scripts
# Location on VM3: run these in PowerShell to trigger detection rules
#
# Each attack maps to a custom Wazuh rule. Run these to test the full
# detection pipeline: VM3 attack -> VM1 alert -> VM2 n8n -> TheHive case.
#
# WARNING: Only run these in the controlled lab environment on VM3.
# Windows Defender must be disabled for some payloads to execute.

# ═══════════════════════════════════════════════════════════════
# ATTACK 1 — PowerShell Obfuscation (Rule 100011, T1059.001)
# ═══════════════════════════════════════════════════════════════
# Encoded PowerShell command with hidden window — simulates obfuscated
# payload execution. The base64 decodes to a harmless echo.

powershell -nop -windowstyle hidden -enc ZQBjAGgAbwAgACIAUwBlAG4AdABpAG4AZQBsAEEASQAgAHQAZQBzAHQAIgA=


# ═══════════════════════════════════════════════════════════════
# ATTACK 2 — Port Scan (Rule 100014, T1595)
# ═══════════════════════════════════════════════════════════════
# Nmap SYN scan against VM1 — simulates network reconnaissance.
# Replace the IP with VM1's current IP.

nmap -sS 192.168.1.34


# ═══════════════════════════════════════════════════════════════
# ATTACK 3 — Aggressive Nmap Scan (Rule 100014, T1595)
# ═══════════════════════════════════════════════════════════════
# Service version + OS detection scan — more aggressive reconnaissance.

nmap -sS -sV -O 192.168.1.0/24


# ═══════════════════════════════════════════════════════════════
# ATTACK 4 — LSASS Access Simulation (Rule 100013, T1003.001)
# ═══════════════════════════════════════════════════════════════
# Simulates credential dumping via comsvcs.dll MiniDump.
# This is the technique real attackers use to dump LSASS memory.
# NOTE: This creates an actual LSASS dump — handle with care in the lab.

# Get LSASS process ID first:
# $lsassPid = (Get-Process lsass).Id
# Then run (requires admin):
# rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\temp\lsass.dmp full


# ═══════════════════════════════════════════════════════════════
# ATTACK 5 — Suspicious Executable Drop (Rule 92213, T1547)
# ═══════════════════════════════════════════════════════════════
# Copies an executable to a suspicious location (Downloads/Temp).
# Simulates malware staging.

# Copy-Item C:\Windows\System32\calc.exe C:\Users\$env:USERNAME\Downloads\payload.exe


# ═══════════════════════════════════════════════════════════════
# VERIFICATION
# ═══════════════════════════════════════════════════════════════
# After running an attack, verify on VM1:
#   sudo tail -f /var/ossec/logs/alerts/alerts.json
#   sudo tail -f /var/ossec/logs/integrations.log
#
# And check:
#   - Wazuh dashboard shows the alert with MITRE tag
#   - n8n Executions tab shows a triggered workflow
#   - TheHive shows a new case with AI-generated tasks
