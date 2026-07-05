# SentinelAI — Grafana Dashboard Setup Guide
# Complete Step-by-Step with VM Locations and Connection Details

---

## How Grafana Fits in the Architecture

Grafana is a visualization platform that reads data from databases and displays
it as charts, tables, and graphs. In SentinelAI, Grafana will:

- Run on VM2 (SOAR server) as a Docker container on port 3000
- Connect REMOTELY to OpenSearch on VM1 (port 9200) to read Wazuh alert data
- Display dashboards showing alert trends, MITRE coverage, severity distribution, and more

The data flow for Grafana:

    VM3 attacks → VM1 Wazuh processes alerts → OpenSearch stores alerts
                                                       ↑
                                               VM2 Grafana reads from here


## Prerequisites Checklist

Before starting, confirm these are true:

- [ ] VM1 is running (Wazuh Manager + OpenSearch + Dashboard)
- [ ] VM2 is running with Docker installed
- [ ] VM3 has generated some alerts (you need data to visualize)
- [ ] You know VM1's current IP (currently 192.168.1.34)
- [ ] You know VM2's current IP (currently 192.168.1.31)


---


## PHASE 1 — Prepare OpenSearch on VM1 to Accept Remote Connections

> **Do this on: VM1 (192.168.1.34)**
> **Why:** By default, OpenSearch on VM1 only listens on localhost (127.0.0.1).
> Grafana on VM2 cannot connect to it remotely unless we open it up.


### Step 1.1 — Test if OpenSearch is accessible from VM2

First, check if VM2 can already reach OpenSearch. Run this **on VM2**:

```bash
curl -k -u admin:admin https://192.168.1.34:9200
```

**If you get a JSON response** with cluster name and version → OpenSearch is already
accessible remotely. Skip to Phase 2.

**If you get "Connection refused" or timeout** → OpenSearch is only listening on
localhost. Continue with Step 1.2.

**If you get "Authentication failed"** → OpenSearch is accessible but the
password is not "admin". Check Step 1.4 below.


### Step 1.2 — Configure OpenSearch to listen on all interfaces

**On VM1**, open the OpenSearch configuration file:

```bash
sudo nano /etc/wazuh-indexer/opensearch.yml
```

Find the line that says:

```yaml
network.host: "127.0.0.1"
```

Or it might say:

```yaml
network.host: "localhost"
```

Change it to:

```yaml
network.host: "0.0.0.0"
```

This tells OpenSearch to listen on all network interfaces, making it accessible
from other VMs on the network.

Save the file (Ctrl+O, Enter, Ctrl+X).


### Step 1.3 — Restart OpenSearch (Wazuh Indexer)

**On VM1**, restart the indexer service. IMPORTANT: restart in the correct order
to avoid breaking the Wazuh stack:

```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
sleep 10
sudo systemctl start wazuh-indexer
sleep 15
sudo systemctl start wazuh-manager
sleep 10
sudo systemctl start wazuh-dashboard
```

Verify all three services are running:

```bash
sudo systemctl status wazuh-indexer | head -5
sudo systemctl status wazuh-manager | head -5
sudo systemctl status wazuh-dashboard | head -5
```

All three should show "active (running)".


### Step 1.4 — Find the OpenSearch admin password

**On VM1**, the password might be in one of these locations:

```bash
# Check Wazuh's internal users file
sudo cat /etc/wazuh-indexer/opensearch-security/internal_users.yml | head -20
```

Or it may have been set during Wazuh installation. Common defaults:
- Username: admin
- Password: admin (or SecretPassword or whatever was set during install)

Test it:

```bash
curl -k -u admin:YOUR_PASSWORD https://localhost:9200
```

When you get a JSON response, note the username and password — you will need them
for Grafana.


### Step 1.5 — Verify remote access works

**On VM2**, test the connection again:

```bash
curl -k -u admin:YOUR_PASSWORD https://192.168.1.34:9200
```

Expected output (something like):

```json
{
  "name" : "wazuhserver2",
  "cluster_name" : "wazuh-cluster",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.x.x"
  }
}
```

If this works, VM2 can reach OpenSearch on VM1. Grafana will use this same
connection.


### Step 1.6 — Check what alert indices exist

**On VM2** (or VM1), list all Wazuh alert indices:

```bash
curl -k -u admin:YOUR_PASSWORD https://192.168.1.34:9200/_cat/indices?v | grep wazuh-alerts
```

Expected output (something like):

```
green open wazuh-alerts-4.x-2026.04.13  xxx  1  0   1523  0  2.1mb  2.1mb
green open wazuh-alerts-4.x-2026.04.17  xxx  1  0    892  0  1.3mb  1.3mb
green open wazuh-alerts-4.x-2026.06.03  xxx  1  0    347  0  0.5mb  0.5mb
```

Note the index pattern — it looks like `wazuh-alerts-4.x-YYYY.MM.DD`.
The Grafana index pattern will be: `wazuh-alerts-*`
This wildcard catches all daily indices.


---


## PHASE 2 — Install Grafana on VM2

> **Do this on: VM2 (192.168.1.31)**
> **Why:** Grafana runs as a Docker container alongside n8n, TheHive, and the ML API.


### Step 2.1 — Pull and run the Grafana container

**On VM2**, run:

```bash
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e "GF_SECURITY_ADMIN_USER=admin" \
  -e "GF_SECURITY_ADMIN_PASSWORD=SentinelAI2026" \
  -v grafana-storage:/var/lib/grafana \
  --restart unless-stopped \
  grafana/grafana-oss:latest
```

What each flag does:
- `-d` — run in background (detached)
- `--name grafana` — container name for easy reference
- `-p 3000:3000` — expose Grafana on port 3000
- `-e GF_SECURITY_ADMIN_USER=admin` — set admin username
- `-e GF_SECURITY_ADMIN_PASSWORD=SentinelAI2026` — set admin password
- `-v grafana-storage:/var/lib/grafana` — persist dashboards and settings across restarts
- `--restart unless-stopped` — auto-start on boot


### Step 2.2 — Verify Grafana is running

```bash
docker ps | grep grafana
```

Expected: a line showing grafana container with status "Up" and port 3000 mapped.

Also test from command line:

```bash
curl -s http://localhost:3000/api/health
```

Expected: `{"commit":"...","database":"ok","version":"..."}`


### Step 2.3 — Access Grafana in browser

Open your browser and go to:

```
http://192.168.1.31:3000
```

Login with:
- Username: `admin`
- Password: `SentinelAI2026`

You should see the Grafana home page.


### Step 2.4 — Install the OpenSearch data source plugin

Grafana does not include OpenSearch support by default. Install the plugin:

```bash
docker exec grafana grafana-cli plugins install grafana-opensearch-datasource
```

Then restart Grafana to load the plugin:

```bash
docker restart grafana
```

Wait 15 seconds, then refresh your browser. The plugin is now available.


---


## PHASE 3 — Connect Grafana to OpenSearch on VM1

> **Do this in: Grafana web UI (browser)**
> **What this does:** Creates a data pipeline from Grafana (VM2) → OpenSearch (VM1)
> so Grafana can query Wazuh alert data stored on VM1.


### Step 3.1 — Add data source

1. In Grafana, click the **hamburger menu** (☰) on the top left
2. Go to **Connections** → **Data Sources**
3. Click **Add data source**
4. Search for **OpenSearch** and select it


### Step 3.2 — Configure the connection

Fill in these settings exactly:

**HTTP Section:**

| Setting | Value |
|---------|-------|
| URL | `https://192.168.1.34:9200` |

Note: This is VM1's IP with OpenSearch's HTTPS port.

**Auth Section:**

| Setting | Value |
|---------|-------|
| Basic auth | **Toggle ON** |
| With Credentials | Leave OFF |

**Basic Auth Details Section:**

| Setting | Value |
|---------|-------|
| User | `admin` |
| Password | (your OpenSearch password from Step 1.4) |

**TLS/SSL Auth Details Section:**

| Setting | Value |
|---------|-------|
| Skip TLS Verify | **Toggle ON** |

This is necessary because Wazuh uses self-signed SSL certificates. Without this
toggle, Grafana will reject the connection.

**OpenSearch Details Section:**

| Setting | Value |
|---------|-------|
| Index name | `wazuh-alerts-*` |
| Pattern | **No pattern** |
| Time field name | `timestamp` |
| Version | Select **OpenSearch** (not Elasticsearch) |


### Step 3.3 — Test and save

Click **Save & Test** at the bottom.

**Expected result:** Green banner saying "Data source is working"

**If it fails with "Bad Gateway" or "Connection refused":**
- Go back to Phase 1 and verify OpenSearch is listening on 0.0.0.0
- Check VM1's firewall: `sudo ufw status` — if active, run `sudo ufw allow 9200`
- Test from VM2: `curl -k -u admin:password https://192.168.1.34:9200`

**If it fails with "Authentication error":**
- Double-check username and password
- Test credentials from VM2 terminal first with curl

**If it fails with "index not found":**
- Check index names from Step 1.6
- Make sure the index pattern matches what actually exists


---


## PHASE 4 — Build the Dashboard

> **Do this in: Grafana web UI (browser)**
> **What this does:** Creates visual panels that query OpenSearch and display
> Wazuh alert data in charts, tables, and graphs.


### Step 4.1 — Create a new dashboard

1. Click the **hamburger menu** (☰) on the top left
2. Go to **Dashboards**
3. Click **New** → **New Dashboard**
4. Click **Add visualization**
5. Select your **Wazuh-OpenSearch** data source


### Step 4.2 — Panel 1: Alert Volume Over Time

This panel shows how many alerts are generated per hour/day, giving you a
timeline of attack activity.

**Panel settings:**
1. In the visualization type dropdown (top right of editor), select **Time series**
2. In the query editor at the bottom:
   - Metric: select **Count**
   - Group by: click **+** → select **Date Histogram**
   - Field: `timestamp`
   - Interval: `auto` (Grafana will pick hourly/daily based on time range)
3. On the right side panel:
   - Title: `Alert Volume Over Time`
4. Click **Apply** (top right) to save this panel to the dashboard


### Step 4.3 — Panel 2: Alerts by Severity Level

This panel shows the distribution of alerts by Wazuh rule level (1-15).
Higher levels indicate more critical threats.

1. Click **Add** → **Visualization** on the dashboard
2. Select **Wazuh-OpenSearch** data source
3. Visualization type: **Bar chart**
4. Query editor:
   - Metric: **Count**
   - Group by: click **+** → select **Terms**
   - Field: `rule.level`
   - Order by: `Count`
   - Order: `Descending`
   - Size: `15`
5. Title: `Alerts by Severity Level`
6. Click **Apply**


### Step 4.4 — Panel 3: Top 10 Triggered Rules

This table shows which detection rules fire most frequently, helping identify
the most common threat patterns.

1. Add new visualization → **Table**
2. Query editor:
   - Metric: **Count**
   - Group by: click **+** → select **Terms**
     - Field: `rule.id`
     - Size: `10`
   - Group by: click **+** again → select **Terms**
     - Field: `rule.description`
     - Size: `10`
3. Title: `Top 10 Triggered Rules`
4. Click **Apply**


### Step 4.5 — Panel 4: MITRE ATT&CK Tactics Distribution

This pie chart shows which MITRE ATT&CK tactics are most detected —
directly demonstrates MITRE integration for thesis defense.

1. Add new visualization → **Pie chart**
2. Query editor:
   - Metric: **Count**
   - Group by: click **+** → select **Terms**
     - Field: `rule.mitre.tactic`
     - Size: `12`
3. Title: `MITRE ATT&CK Tactics Distribution`
4. Click **Apply**


### Step 4.6 — Panel 5: Alerts by Agent

This pie chart shows which monitored endpoints generate the most alerts.
In your setup this will show the Windows endpoint (VM3) and any other
registered agents.

1. Add new visualization → **Pie chart**
2. Query editor:
   - Metric: **Count**
   - Group by: click **+** → select **Terms**
     - Field: `agent.name`
     - Size: `10`
3. Title: `Alerts by Agent`
4. Click **Apply**


### Step 4.7 — Panel 6: High Severity Alerts Only (Level 10+)

This table shows only the critical alerts that trigger the SOAR pipeline
(your webhook threshold is level 10). This is the most operationally
relevant panel for SOC analysts.

1. Add new visualization → **Table**
2. In the query editor, find the **Query** field (Lucene syntax) at the top
   and type:
   ```
   rule.level: >=10
   ```
3. Metric: **Count**
4. Group by: **Terms** → field `rule.description` → size `10`
5. Group by: **Terms** → field `rule.mitre.id` → size `10`
6. Title: `High Severity Alerts (Level 10+)`
7. Click **Apply**


### Step 4.8 — Panel 7: MITRE Technique ID Breakdown

This shows specific MITRE technique IDs (T1059.001, T1003, etc.) not just
tactics. Examiners will ask about MITRE granularity — this panel answers that.

1. Add new visualization → **Bar chart**
2. Query editor:
   - Metric: **Count**
   - Group by: **Terms** → field `rule.mitre.id` → size `15`
3. Title: `MITRE Technique IDs Detected`
4. Click **Apply**


### Step 4.9 — Panel 8: Alert Timeline by Rule (Stacked)

This shows alert activity over time, broken down by rule — useful for
identifying which attacks happened when during a demo.

1. Add new visualization → **Time series**
2. Query editor:
   - Metric: **Count**
   - Group by: **Date Histogram** → field `timestamp` → interval `auto`
   - Group by: **Terms** → field `rule.description` → size `5`
3. In the panel options on the right:
   - Under **Graph styles** → Stack series: **Normal**
4. Title: `Alert Timeline by Rule`
5. Click **Apply**


---


## PHASE 5 — Arrange and Save the Dashboard

> **Do this in: Grafana web UI (browser)**


### Step 5.1 — Arrange the layout

Drag panels into a 2-column grid layout:

```
Row 1:  [Alert Volume Over Time          ] [Alert Timeline by Rule (Stacked) ]
Row 2:  [Alerts by Severity Level        ] [MITRE ATT&CK Tactics Distribution]
Row 3:  [Top 10 Triggered Rules          ] [MITRE Technique IDs Detected     ]
Row 4:  [High Severity Alerts (Level 10+)] [Alerts by Agent                  ]
```

Resize panels by dragging their bottom-right corners. Each panel should be
roughly half the dashboard width.


### Step 5.2 — Set the default time range

1. Click the time picker in the top right corner
2. Select **Last 7 days** (or a range that covers your attack sessions)
3. If your attacks were from specific dates (e.g., April 21), use a custom range


### Step 5.3 — Save the dashboard

1. Click the **save icon** (💾) in the top right
2. Name: `SentinelAI SOC Dashboard`
3. Click **Save**


### Step 5.4 — Enable auto-refresh (for live demo)

1. Click the refresh dropdown (next to the time picker)
2. Select **10s** or **30s** for auto-refresh during demos
3. This makes the dashboard update live as new alerts come in


---


## PHASE 6 — Verify Everything Works

> **Do this across all VMs**


### Step 6.1 — Generate fresh alerts

**On VM3**, run several attacks to create fresh data:

```powershell
# PowerShell obfuscation (rule 100011)
powershell -nop -windowstyle hidden -enc ZQBjAGgAbwAgACIAUwBlAG4AdABpAG4AZQBsAEEASQAiAA==

# Port scan (rule 100014)
nmap -sS 192.168.1.34
```


### Step 6.2 — Verify alerts reach OpenSearch

**On VM1**, check that alerts are being indexed:

```bash
curl -k -u admin:YOUR_PASSWORD "https://localhost:9200/wazuh-alerts-*/_count"
```

This returns the total number of alerts stored. Run attacks, wait 30 seconds,
run it again — the count should increase.


### Step 6.3 — Check Grafana panels update

Go back to the Grafana dashboard in your browser. Set the time range to
**Last 15 minutes**. The panels should show the alerts you just generated.

If panels show "No data":
- Widen the time range (Last 24 hours, Last 7 days)
- Check that the timestamp field is correct (`timestamp` not `@timestamp`)
- Verify the index pattern matches actual indices


---


## Troubleshooting Reference

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| "Data source is not working" | OpenSearch not reachable from VM2 | Check network, firewall, and opensearch.yml network.host |
| Panels show "No data" | Wrong time range or wrong index pattern | Widen time range, verify index names with curl |
| "Authentication error" | Wrong OpenSearch credentials | Test with curl first to find correct password |
| "Index not found" | Index pattern doesn't match real indices | List indices with _cat/indices and adjust pattern |
| Dashboard disappears after restart | Docker volume not persisted | Recreate container with -v grafana-storage:/var/lib/grafana |
| Grafana not accessible from browser | Port 3000 not exposed or firewall blocking | Check docker ps shows port mapping, check ufw |


---


## Connection Diagram Summary

```
┌──────────────────────────────────────────────────────────────────┐
│  VM2 (192.168.1.31) — SOAR Server                               │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ n8n      │  │ TheHive  │  │ Flask ML │  │ Grafana          │ │
│  │ :5678    │  │ :9000    │  │ :5000    │  │ :3000            │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┬─────────┘ │
│                                                      │           │
└──────────────────────────────────────────────────────┼───────────┘
                                                       │
                                          HTTPS :9200  │
                                          (reads data) │
                                                       │
┌──────────────────────────────────────────────────────┼───────────┐
│  VM1 (192.168.1.34) — SIEM Server                    │           │
│                                                      ▼           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Wazuh Manager│  │ Wazuh        │  │ OpenSearch Indexer    │   │
│  │ :1514        │  │ Dashboard    │  │ :9200                │   │
│  │              │──│ :443         │──│ stores wazuh-alerts-* │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│         ▲                                                        │
│         │ agent connection :1514                                  │
└─────────┼────────────────────────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────────────────┐
│  VM3 (192.168.1.36) — Windows Endpoint                           │
│         │                                                        │
│  ┌──────┴───────┐  ┌──────────┐  ┌──────────┐                   │
│  │ Wazuh Agent  │  │ Sysmon   │  │ Attack   │                   │
│  │ ID: 006      │  │          │  │ Tools    │                   │
│  └──────────────┘  └──────────┘  └──────────┘                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```


## What to Show During Thesis Defense

Open Grafana with the SentinelAI SOC Dashboard visible, set auto-refresh to 10s.
Run a live attack from VM3 while the examiner watches. The panels should update
within 15-30 seconds showing the new alert, its severity, MITRE tactic,
and technique ID — demonstrating real-time monitoring capability.
