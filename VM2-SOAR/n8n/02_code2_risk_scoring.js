// SentinelAI — n8n "Code2" Node (Composite Risk Scoring)
// Position: After ML Predict node (HTTP Request3), before the If node
//
// This node fuses four independent signals into a composite risk score (0-100):
//   - Wazuh rule severity  (40% weight)
//   - ML model confidence  (30% weight)
//   - AbuseIPDB score      (20% weight)
//   - VirusTotal detections (10% weight)
//
// It also builds the TheHive case body and a set of fallback response tasks.
//
// IMPORTANT: The node names below (HTTP Request, HTTP Request1, HTTP Request3)
// must match your actual n8n canvas node names. Adjust if different.

const webhook = $('Webhook').item.json.body || {};
const ml      = $('HTTP Request3').item.json || {};       // ML Predict
const vt      = $('HTTP Request').item.json?.data?.attributes?.last_analysis_stats || {};  // VirusTotal
const abuse   = $('HTTP Request1').item.json?.data || {};  // AbuseIPDB

// ── Component scores ───────────────────────────────────────
const ruleLevel  = webhook?.rule?.level || 0;
const wazuhScore = Math.min(100, (ruleLevel / 15) * 100);
const mlScore    = (ml?.confidence || 0.5) * 100;
const abuseScore = abuse?.abuseConfidenceScore || 0;

const vtMalicious = vt?.malicious || 0;
const vtTotal     = (vt?.harmless || 0) + (vt?.malicious || 0) +
                    (vt?.suspicious || 0) + (vt?.undetected || 0);
const vtScore     = vtTotal > 0 ? (vtMalicious / vtTotal) * 100 : 0;

// ── Weighted composite score ───────────────────────────────
const finalScore = Math.round(
  (wazuhScore * 0.40) +
  (mlScore    * 0.30) +
  (abuseScore * 0.20) +
  (vtScore    * 0.10)
);

// ── Severity and action thresholds ─────────────────────────
let severity, action;
if      (finalScore >= 70) { severity = 'CRITICAL'; action = 'auto_response'; }
else if (finalScore >= 50) { severity = 'HIGH';     action = 'create_case';   }
else if (finalScore >= 30) { severity = 'MEDIUM';   action = 'create_case';   }
else                       { severity = 'LOW';      action = 'log_only';      }

// ── Extract alert fields ───────────────────────────────────
const ruleId    = webhook?.rule?.id          || 'N/A';
const ruleDesc  = webhook?.rule?.description || 'Unknown';
const mitreId   = webhook?.rule?.mitre?.id?.[0]      || 'N/A';
const mitreTac  = webhook?.rule?.mitre?.tactic?.[0]  || 'N/A';
const agentName = webhook?.agent?.name       || 'Unknown';
const agentIp   = webhook?.agent?.ip         || 'Unknown';
const timestamp = webhook?.timestamp         || '';
const mlVerdict = ml?.risk_label             || 'unknown';
const mlConf    = ml?.confidence             || 0.5;

// ── Build TheHive case body ────────────────────────────────
const thehive_body = {
  title: '[' + severity + '] ' + ruleDesc,
  description:
    'Agent: ' + agentName + ' (' + agentIp + ')\n' +
    'Rule: ' + ruleId + ' — ' + ruleDesc + '\n' +
    'MITRE: ' + mitreId + ' / ' + mitreTac + '\n\n' +
    'Risk Score: ' + finalScore + '/100\n\n' +
    'Wazuh Score: ' + Math.round(wazuhScore) + '\n' +
    'ML Score: ' + Math.round(mlScore) + '\n' +
    'AbuseIPDB Score: ' + Math.round(abuseScore) + '\n' +
    'VirusTotal Score: ' + Math.round(vtScore) + '\n\n' +
    'ML Verdict: ' + mlVerdict + ' (' + mlConf + ')',
  severity: finalScore >= 70 ? 3 : finalScore >= 50 ? 2 : 1,
  tlp: 2,
  tags: ['sentinelai', mitreId, severity]
};

// ── Fallback response tasks (used if AI generation is unavailable) ──
const TASK_MAP = {
  'T1003': [
    { title: 'Isolate affected endpoint', desc: 'Isolate ' + agentName + ' from the network to prevent credential reuse.' },
    { title: 'Reset compromised credentials', desc: 'Force password reset for all accounts accessed from ' + agentIp + '.' },
    { title: 'Check for lateral movement', desc: 'Review logs for RDP, SMB, or WMI connections from ' + agentIp + '.' },
  ],
  'T1059.001': [
    { title: 'Decode PowerShell command', desc: 'Extract and decode the base64 payload to identify intent.' },
    { title: 'Check persistence mechanisms', desc: 'Search scheduled tasks, registry run keys, startup entries on ' + agentName + '.' },
    { title: 'Review parent process chain', desc: 'Trace the parent-child tree to find the initial execution vector.' },
  ],
  'T1003.001': [
    { title: 'Emergency credential reset', desc: 'LSASS access detected. Reset all domain admin and service passwords.' },
    { title: 'Check Active Directory integrity', desc: 'Scan AD for unauthorized changes and golden ticket indicators.' },
  ],
  'T1571': [
    { title: 'Block C2 IP at firewall', desc: 'Add destination IP and port 4444 to firewall deny rules.' },
    { title: 'Scan for data exfiltration', desc: 'Review network logs for large outbound transfers from ' + agentIp + '.' },
  ],
  'T1595': [
    { title: 'Review scan scope', desc: 'Identify which hosts and ports were scanned from ' + agentIp + '.' },
    { title: 'Check for follow-up exploitation', desc: 'Review alerts after the scan for exploitation of discovered services.' },
  ],
};

const defaultTasks = [
  { title: 'Validate the threat', desc: 'Analyze the alert, ML confidence, and enrichment data. Determine TP/FP.' },
  { title: 'Document and close', desc: 'Record findings, mark TP/FP, update the feedback loop for ML retraining.' },
];

const responseTasks = [...(TASK_MAP[mitreId] || TASK_MAP[mitreId?.split('.')[0]] || []), ...defaultTasks];

// ── Output ─────────────────────────────────────────────────
return [{
  json: {
    final_score: finalScore, severity, action,
    scores: { wazuhScore, mlScore, abuseScore, vtScore },
    alert: {
      rule_id: ruleId, rule_desc: ruleDesc, mitre_id: mitreId,
      mitre_tac: mitreTac, agent_name: agentName,
      agent_ip: agentIp, timestamp
    },
    ml_verdict: mlVerdict, ml_confidence: mlConf,
    thehive_body, responseTasks
  }
}];
