# SentinelAI — AI-Enhanced Self-Hosted SOC Platform

A graduation project building a complete, self-hosted Security Operations Center
(SOC) that moves beyond traditional signature-based detection by integrating
machine learning for behavioral analysis and a large language model for automated
incident response.

---

## What It Does

SentinelAI detects threats on Windows endpoints, enriches them with threat
intelligence and ML-based behavioral scoring, fuses everything into a composite
risk score, and automatically creates investigation cases with AI-generated
response tasks.

### Detection Pipeline

```
VM3 (Windows + Sysmon)
      │  endpoint telemetry
      ▼
VM1 (Wazuh SIEM)  ──  custom rules + MITRE ATT&CK mapping
      │  webhook (severity ≥ 10)
      ▼
VM2 (n8n SOAR)
      ├─ VirusTotal enrichment
      ├─ AbuseIPDB enrichment
      ├─ ML behavioral scoring (XGBoost, Flask API)
      ├─ Composite risk score (0–100)
      ├─ TheHive case creation
      ├─ AI-generated response tasks (Claude)
      └─ Active response (score ≥ 70 → kill process on VM3)
```

### Composite Risk Score

Four independent signals are weighted into a single 0–100 score:

| Signal | Weight |
|--------|--------|
| Wazuh rule severity | 40% |
| ML model confidence | 30% |
| AbuseIPDB reputation | 20% |
| VirusTotal detections | 10% |

---

## Architecture

| VM | Role | Stack |
|----|------|-------|
| VM1 | SIEM Server | Wazuh Manager, OpenSearch, Dashboard |
| VM2 | SOAR Server | n8n, TheHive 5, Flask ML API, Grafana |
| VM3 | Endpoint | Windows 10, Sysmon, Wazuh Agent |

---

## Repository Structure

```
SentinelAI/
├── VM1-SIEM/                      # SIEM server configuration
│   ├── local_rules.xml           # 5 custom MITRE-tagged detection rules
│   ├── custom-webhook            # Python webhook integration script
│   ├── agent.conf                # Windows event channel config
│   └── ossec_integration_block.xml  # ossec.conf integration snippet
│
├── VM2-SOAR/                      # SOAR server
│   ├── ml_api/                   # Machine learning API
│   │   ├── app.py                # Flask prediction API
│   │   ├── generate_and_train.py # Model training script
│   │   ├── sentinel_xgb.pkl      # Trained XGBoost model
│   │   ├── sentinel_scaler.pkl   # Feature scaler
│   │   ├── sentinel_features.pkl # Feature names
│   │   └── requirements.txt      # Python dependencies
│   ├── n8n/                      # n8n workflow Code nodes
│   │   ├── 01_code_webhook_parser.js
│   │   ├── 02_code2_risk_scoring.js
│   │   ├── 03_ai_tasks_claude.js
│   │   └── 04_create_tasks.js
│   └── docker-compose.yml        # TheHive + Cassandra + Elasticsearch
│
├── VM3-Endpoint/                 # Windows endpoint
│   ├── SYSMON_SETUP.md           # Sysmon installation guide
│   └── attack_scripts/
│       └── run_attacks.ps1       # Attack simulation scripts
│
├── dashboard/                    # Interactive SOC dashboard
│   ├── SentinelAI_Dashboard.jsx  # React dashboard with AI analysis
│   └── README.md
│
└── docs/                         # Documentation
    ├── DEPLOYMENT.md             # Full deployment guide
    ├── ML_DOCUMENTATION.md       # ML model documentation
    └── GRAFANA_SETUP.md          # Grafana dashboard setup
```

---

## Machine Learning Approach

The ML model is a binary classifier (malicious vs. benign) trained on
endpoint behavioral features extracted from Wazuh/Sysmon alerts. It uses a
knowledge-guided synthetic dataset derived from the MITRE ATT&CK framework,
because the live system produces endpoint metadata (process names, command-line
arguments, rule severity) rather than the network flow features used by public
datasets like CICIDS2017.

The 21 features include command-line entropy, command-line length, rule severity,
encoded-PowerShell detection, suspicious port flags, and one-hot encoded MITRE
tactics. See `docs/ML_DOCUMENTATION.md` for full details.

**Model performance:** 98% accuracy, 0.999 ROC AUC, validated with 5-fold
cross-validation. (High metrics reflect the structured synthetic data; the
analyst feedback loop is designed to improve real-world accuracy over time.)

---

## Quick Start

See `docs/DEPLOYMENT.md` for the complete deployment guide. Summary:

1. **VM1**: Install Wazuh all-in-one, deploy custom rules, configure webhook
2. **VM3**: Install Sysmon + Wazuh agent, register to VM1
3. **VM2**: Deploy Docker (n8n, TheHive), train and run ML API, import n8n workflow

---

## Detection Rules

| Rule ID | Detection | MITRE | Severity |
|---------|-----------|-------|----------|
| 100010 | Mimikatz execution | T1003 | 14 |
| 100011 | PowerShell obfuscation | T1059.001 | 12 |
| 100012 | Metasploit C2 (port 4444) | T1571 | 13 |
| 100013 | LSASS memory access | T1003.001 | 15 |
| 100014 | Port scanning tools | T1595 | 12 |

---

## Configuration Notes

Before deploying, update these placeholders:
- **IP addresses**: All configs use example IPs (192.168.1.x). The lab uses
  bridged networking, so IPs change per session.
- **API keys**: VirusTotal, AbuseIPDB, TheHive (org-level), and Anthropic keys
  must be added to the n8n workflow.
- **TheHive API key**: Must come from an org-level user with org-admin role,
  NOT the platform admin account.

---

## Technologies

Wazuh · OpenSearch · n8n · TheHive 5 · XGBoost · Flask · Docker · Sysmon ·
MITRE ATT&CK · VirusTotal API · AbuseIPDB API · Anthropic Claude API · React ·
Grafana

---

## Team

A 5-person graduation project. Each member owns a component: SIEM, SOAR, endpoint
/ red team, ML pipeline, and integration.

---

## Academic Note

SentinelAI's distinction is its layered detection model: deterministic rules for
known TTPs, threat intelligence for reputation, ML for behavioral anomaly scoring,
and an LLM for automated response — consistent with modern XDR architecture. This
positions it against commercial SIEMs (Splunk, QRadar) as a self-hosted,
AI-adaptive alternative with a feedback-driven retraining loop.
