# SentinelAI — Project Deployment Guide
## AI-Enhanced Self-Hosted Security Operations Center Platform

---

## 1. Overview

SentinelAI is deployed across three virtual machines connected on a shared local
network. This guide documents the complete deployment process from a clean state,
including all software installation, configuration, and inter-VM connections.

### Deployment Order

The system must be deployed in this sequence because each component depends on the
previous one:

1. **VM1 (SIEM)** first — the central detection and storage server
2. **VM3 (Endpoint)** second — connects as an agent to VM1
3. **VM2 (SOAR)** third — receives alerts from VM1 and runs automation

---

## 2. Infrastructure Requirements

### Virtual Machine Specifications

| VM | Role | OS | RAM | CPU | Disk |
|----|------|----|----|-----|------|
| VM1 | SIEM Server | Ubuntu Server 22.04 | 6 GB | 6 cores | 80 GB |
| VM2 | SOAR Server | Ubuntu Server 22.04 | 6 GB | 4 cores | 60 GB |
| VM3 | Windows Endpoint | Windows 10 | 4 GB | 2 cores | 50 GB |

### Network Configuration

All VMs run in VMware with **bridged network mode** connected to a shared network
(mobile hotspot in the lab environment). 

**Important:** In bridged mode, IP addresses change when the network changes.
A reconnect script handles re-registration at the start of each session.

| VM | Hostname | Example IP | User |
|----|----------|-----------|------|
| VM1 | wazuhserver2 | 192.168.1.34 | socadmin |
| VM2 | aogo-virtual-machine | 192.168.1.31 | aogo |
| VM3 | DESKTOP-SJCO2UM | 192.168.1.36 | dell |

---

## 3. VM1 Deployment — SIEM Server

### 3.1 — Install Wazuh (All-in-One)

The Wazuh all-in-one installation includes the Manager, OpenSearch Indexer, and
Dashboard in a single command.

```bash
# Download and run the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

This installs and configures:
- **Wazuh Manager** — receives and analyzes agent logs (port 1514/1515)
- **Wazuh Indexer (OpenSearch)** — stores alerts (port 9200)
- **Wazuh Dashboard** — web interface (port 443)

At the end, the installer prints admin credentials. **Save these** — you need them
for OpenSearch and the dashboard.

### 3.2 — Verify the Stack is Running

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

All three should show "active (running)".

Access the dashboard at `https://192.168.1.34` (accept the self-signed certificate).

### 3.3 — Enable Autostart

```bash
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-dashboard
```

### 3.4 — Deploy Custom Detection Rules

Edit the local rules file:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add the five custom MITRE-tagged rules:

```xml
<group name="sentinelai,custom,">

  <rule id="100010" level="14">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\mimikatz\.exe</field>
    <description>Mimikatz execution detected</description>
    <mitre><id>T1003</id></mitre>
  </rule>

  <rule id="100011" level="12">
    <if_sid>91802</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-enc|-encodedcommand|frombase64string|-windowstyle hidden</field>
    <description>PowerShell obfuscation detected</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

  <rule id="100012" level="13">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.destinationPort">4444</field>
    <description>Metasploit C2 communication detected</description>
    <mitre><id>T1571</id></mitre>
  </rule>

  <rule id="100013" level="15">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <description>LSASS memory access attempt</description>
    <mitre><id>T1003.001</id></mitre>
  </rule>

  <rule id="100014" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)nmap|masscan|zenmap</field>
    <description>Port scanning tool detected</description>
    <mitre><id>T1595</id></mitre>
  </rule>

</group>
```

### 3.5 — Configure Agent Channels

Edit the shared agent configuration to push Windows event channels:

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

### 3.6 — Create the Webhook Integration Script

This script forwards high-severity alerts to VM2's n8n.

```bash
sudo nano /var/ossec/integrations/custom-webhook
```

```python
#!/usr/bin/env python3
import sys
import json
import requests

alert_file = sys.argv[1]
hook_url = sys.argv[3] if len(sys.argv) > 3 else 'http://192.168.1.31:5678/webhook/wazuh-alerts'

try:
    with open(alert_file) as f:
        alert = json.load(f)
    requests.post(hook_url, json=alert, headers={'Content-Type': 'application/json'}, timeout=10)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
```

Set permissions:

```bash
sudo chmod 750 /var/ossec/integrations/custom-webhook
sudo chown root:wazuh /var/ossec/integrations/custom-webhook
```

### 3.7 — Configure the Webhook in ossec.conf

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside the **first** `<ossec_config>` block, add:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://192.168.1.31:5678/webhook/wazuh-alerts</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

This sends every alert at severity 10 or higher to n8n on VM2.

### 3.8 — Restart and Verify

```bash
sudo systemctl restart wazuh-manager
sleep 10
sudo grep -i "integrat" /var/ossec/logs/ossec.log | tail -3
```

Confirm you see "Enabling integration for: 'custom-webhook'" with no errors.

---

## 4. VM3 Deployment — Windows Endpoint

### 4.1 — Install Sysmon

Download Sysmon from Microsoft Sysinternals and the SwiftOnSecurity configuration.

Open PowerShell **as Administrator**:

```powershell
# Navigate to where Sysmon and config are downloaded
cd C:\Tools\Sysmon

# Install Sysmon with the SwiftOnSecurity config
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

### 4.2 — Install the Wazuh Agent

Download the Wazuh agent MSI from packages.wazuh.com. Install via PowerShell
(as Administrator), pointing to VM1's IP:

```powershell
.\wazuh-agent-4.7.5.msi /q WAZUH_MANAGER="192.168.1.34" WAZUH_AGENT_NAME="windows_endpoint"
```

### 4.3 — Register and Start the Agent

On **VM1**, add the agent:

```bash
sudo /var/ossec/bin/manage_agents
# Press A to add, name it windows_endpoint, enter VM3 IP
# Press E to extract the key, copy it
```

On **VM3**, import the key:

```powershell
& "C:\Program Files (x86)\ossec-agent\manage_agents.exe" -i "PASTE_KEY_HERE"
```

Start the agent:

```powershell
Start-Service WazuhSvc
```

### 4.4 — Disable Windows Defender (Lab Only)

For attack simulation, Windows Defender must be disabled so test payloads run:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

> **Note:** This is for the controlled lab environment only. Document this clearly
> as a lab constraint, not a production practice.

### 4.5 — Verify Connection

On **VM1**:

```bash
sudo /var/ossec/bin/agent_control -l
```

The agent (ID 006, windows_endpoint) should show **Active**.

### 4.6 — Install Attack Tools

```powershell
# Install Nmap for port scan simulation
# Download from nmap.org and install
```

---

## 5. VM2 Deployment — SOAR Server

### 5.1 — Install Docker

```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

### 5.2 — Deploy n8n

```bash
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -e N8N_SECURE_COOKIE=false \
  -v n8n_data:/home/node/.n8n \
  --restart unless-stopped \
  n8nio/n8n
```

Access n8n at `http://192.168.1.31:5678`.

### 5.3 — Deploy TheHive + Dependencies

TheHive 5 requires Cassandra (database) and Elasticsearch (search). Use a
docker-compose file:

```bash
mkdir -p ~/soc/thehive && cd ~/soc/thehive
nano docker-compose.yml
```

```yaml
version: "3"
services:
  cassandra:
    image: cassandra:4
    container_name: cassandra
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
    volumes:
      - cassandra_data:/var/lib/cassandra
    restart: unless-stopped

  elasticsearch:
    image: elasticsearch:7.17.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped

  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    depends_on:
      - cassandra
      - elasticsearch
    ports:
      - "9000:9000"
    restart: unless-stopped

volumes:
  cassandra_data:
  es_data:
```

Start the stack:

```bash
docker-compose up -d
```

Access TheHive at `http://192.168.1.31:9000`.

### 5.4 — Configure TheHive Organization and User

1. Login as the default platform admin (`admin@thehive.local`)
2. Create an organization (e.g., `SentinelAI`)
3. Create an org-level user (e.g., `soc@thehive.local`) with **org-admin** role
4. Login as this org user and generate an **API key**

> **Critical:** The platform admin cannot create cases. All case operations must
> use the org-level user's API key.

### 5.5 — Deploy the ML API

Transfer the ML files and create the API directory:

```bash
mkdir -p ~/soc/mlapi && cd ~/soc/mlapi
# Copy app.py, generate_and_train.py, and the .pkl files here
```

Train the model (generates the .pkl files):

```bash
pip install xgboost scikit-learn joblib pandas numpy flask --break-system-packages
python3 generate_and_train.py
```

Start the Flask API:

```bash
nohup python3 app.py > mlapi.log 2>&1 &
```

Verify:

```bash
curl http://localhost:5000/health
```

Expected: `{"status":"ok","model":"sentinel_xgb_v2","features":21}`

### 5.6 — Import the n8n Workflow

1. In n8n, click the menu → **Import from File**
2. Select the exported `n8n_workflow.json`
3. Configure credentials:
   - VirusTotal API key
   - AbuseIPDB API key
   - TheHive Authorization header (Bearer + org API key)
   - Anthropic API key (for AI task generation)
4. Update all IP addresses to current session IPs
5. Toggle the workflow to **Active**

### 5.7 — Deploy Grafana (Optional Visualization)

```bash
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e "GF_SECURITY_ADMIN_PASSWORD=SentinelAI2026" \
  -v grafana-storage:/var/lib/grafana \
  --restart unless-stopped \
  grafana/grafana-oss:latest

docker exec grafana grafana-cli plugins install grafana-opensearch-datasource
docker restart grafana
```

Connect Grafana to OpenSearch on VM1 (`https://192.168.1.34:9200`).

---

## 6. Inter-VM Connections Summary

| Connection | From | To | Port | Protocol |
|-----------|------|----|----|----------|
| Agent telemetry | VM3 | VM1 | 1514 | TCP |
| Agent registration | VM3 | VM1 | 1515 | TCP |
| Webhook alerts | VM1 | VM2 | 5678 | HTTP |
| ML predictions | VM2 (n8n) | VM2 (Flask) | 5000 | HTTP (localhost) |
| Case creation | VM2 (n8n) | VM2 (TheHive) | 9000 | HTTP (localhost) |
| Dashboard data | VM2 (Grafana) | VM1 (OpenSearch) | 9200 | HTTPS |
| Threat intel | VM2 (n8n) | Internet | 443 | HTTPS |
| AI tasks | VM2 (n8n) | Internet (Anthropic) | 443 | HTTPS |

---

## 7. Session Startup Procedure

Because the network uses bridged mode, IPs change each session. At the start of
each session:

### Step 1 — Get current IPs

On each VM:
```bash
hostname -I          # Linux (VM1, VM2)
ipconfig             # Windows (VM3)
```

### Step 2 — Update VM1 webhook to VM2's current IP

On VM1:
```bash
sudo sed -i 's|<hook_url>.*</hook_url>|<hook_url>http://NEW_VM2_IP:5678/webhook/wazuh-alerts</hook_url>|' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### Step 3 — Update n8n IPs

In n8n, update the TheHive node URL and ML API URL if they reference IPs.

### Step 4 — Verify all services

On VM2:
```bash
docker ps                                    # n8n, thehive, cassandra, elasticsearch, grafana
curl http://localhost:5000/health            # ML API
```

On VM1:
```bash
sudo /var/ossec/bin/agent_control -l         # VM3 agent active
```

---

## 8. End-to-End Verification

After deployment, verify the complete pipeline:

1. **On VM3**, run a test attack:
   ```powershell
   powershell -nop -windowstyle hidden -enc ZQBjAGgAbwAgACIAUwBlAG4AdABpAG4AZQBsAEEASQAiAA==
   ```

2. **On VM1**, confirm the alert is generated and the webhook fires:
   ```bash
   sudo tail -f /var/ossec/logs/integrations.log
   ```

3. **In n8n**, check the Executions tab shows a triggered workflow

4. **In TheHive**, confirm a case was created with AI-generated tasks

If all four steps succeed, the deployment is complete and operational.

---

## 9. Troubleshooting Quick Reference

| Problem | Cause | Solution |
|---------|-------|----------|
| Webhook not firing | Stale VM2 IP in ossec.conf | Update hook_url, restart manager |
| Integration error in logs | Missing custom-webhook script | Create script, set permissions |
| Agent disconnected | IP changed | Re-register agent, restart WazuhSvc |
| ML API not responding | Flask not running | Restart with nohup python3 app.py |
| TheHive case fails | Wrong API key (platform admin) | Use org-level user key |
| Grafana no data | OpenSearch not reachable | Set network.host to 0.0.0.0 on VM1 |
