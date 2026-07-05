const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// In-memory store — holds the last 100 alerts
let alerts = [];
let nextId = 1;

// n8n posts here after each case is created
app.post('/alert', (req, res) => {
  const data = req.body;
  const alert = {
    id: nextId++,
    rule_id:    data.alert?.rule_id     || 'N/A',
    desc:       data.alert?.rule_desc   || 'Unknown',
    mitre:      data.alert?.mitre_id    || 'N/A',
    tactic:     data.alert?.mitre_tac   || 'N/A',
    severity:   data.alert?.rule_level  || 0,
    agent:      data.alert?.agent_name  || 'Unknown',
    agentIp:    data.alert?.agent_ip    || 'Unknown',
    score:      data.final_score        || 0,
    mlConf:     data.ml_confidence      || 0.5,
    mlVerdict:  data.ml_verdict         || 'unknown',
    action:     data.action             || 'log_only',
    severity_label: data.severity       || 'LOW',
    scores: {
      wazuh: data.scores?.wazuhScore   || 0,
      ml:    data.scores?.mlScore      || 0,
      abuse: data.scores?.abuseScore   || 0,
      vt:    data.scores?.vtScore      || 0,
    },
    tasks:     data.ai_tasks            || [],
    time:      new Date().toISOString(),
  };

  alerts.unshift(alert);
  if (alerts.length > 100) alerts = alerts.slice(0, 100);

  console.log(`[+] Alert received: ${alert.desc} | Score: ${alert.score}`);
  res.json({ status: 'ok', id: alert.id });
});

// Dashboard fetches from here
app.get('/alerts', (req, res) => {
  res.json(alerts);
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', alerts: alerts.length });
});

app.listen(4000, '0.0.0.0', () => {
  console.log('SentinelAI Dashboard Backend running on port 4000');
});
