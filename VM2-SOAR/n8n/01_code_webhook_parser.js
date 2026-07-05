// SentinelAI — n8n "Code" Node (Webhook Parser)
// Position: First Code node after the Webhook node
//
// This node extracts the key fields from the incoming Wazuh alert and
// passes them downstream. The webhook payload arrives wrapped in a "body"
// property, so we access $input.item.json.body.

const webhook = $input.item.json.body || $input.item.json;

const rule      = webhook.rule || {};
const agent     = webhook.agent || {};
const eventdata = webhook.data?.win?.eventdata || {};

return [{
  json: {
    // Pass the full original payload downstream for later nodes
    body: webhook,

    // Extracted fields for enrichment lookups
    rule_id:      rule.id || 'N/A',
    rule_level:   rule.level || 0,
    rule_desc:    rule.description || 'Unknown',
    mitre_id:     rule.mitre?.id?.[0] || 'N/A',
    mitre_tactic: rule.mitre?.tactic?.[0] || 'N/A',

    agent_name:   agent.name || 'Unknown',
    agent_ip:     agent.ip || 'Unknown',

    // Fields for threat intel lookups
    file_hash:    eventdata.hashes || '',
    dest_port:    eventdata.destinationPort || '',
    process_name: eventdata.image || '',
    command_line: eventdata.commandLine || '',

    timestamp:    webhook.timestamp || new Date().toISOString(),
  }
}];
