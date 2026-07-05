// SentinelAI — n8n "AI Tasks" Node (LLM-Powered Task Generation)
// Position: After TheHive case creation, before "Create Tasks" node
//
// This node calls an LLM (Claude / DeepSeek / OpenAI) to generate contextual
// incident response tasks based on the specific attack. Unlike static templates,
// the tasks are tailored to the exact alert details.
//
// Replace YOUR_ANTHROPIC_API_KEY with your actual key.
//
// NOTE: If $http.request is not available in your n8n version, use an
// HTTP Request node instead (see 03b_ai_tasks_http_alternative.txt).

const data   = $('If').item.json;
const alert  = data.alert;
const scores = data.scores;

const prompt = `You are a senior SOC analyst. A security alert just fired. Generate 3-5 specific, actionable incident response tasks for this alert. Each task must be practical and specific to this exact attack.

Alert Details:
- Rule: ${alert.rule_id} — ${alert.rule_desc}
- MITRE: ${alert.mitre_id} / ${alert.mitre_tac}
- Agent: ${alert.agent_name} (${alert.agent_ip})
- Risk Score: ${data.final_score}/100
- ML Confidence: ${data.ml_confidence}
- Wazuh Score: ${scores.wazuhScore}, ML Score: ${scores.mlScore}
- AbuseIPDB: ${scores.abuseScore}, VirusTotal: ${scores.vtScore}

Respond ONLY with a JSON array, no markdown, no explanation:
[{"title": "short task name", "description": "detailed steps", "priority": "HIGH|MEDIUM|LOW"}]`;

let tasks = [];

try {
  const response = await $http.request({
    method: 'POST',
    url: 'https://api.anthropic.com/v1/messages',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'YOUR_ANTHROPIC_API_KEY',
      'anthropic-version': '2023-06-01'
    },
    body: {
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    },
    json: true
  });

  const text = response.content[0].text.replace(/```json|```/g, '').trim();
  tasks = JSON.parse(text);

} catch (e) {
  // Fall back to the static tasks built in Code2 if AI fails
  tasks = (data.responseTasks || []).map(t => ({
    title: t.title,
    description: t.desc,
    priority: 'MEDIUM'
  }));
}

return [{ json: { ...data, ai_tasks: tasks } }];
