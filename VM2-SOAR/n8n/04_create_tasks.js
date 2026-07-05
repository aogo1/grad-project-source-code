// SentinelAI — n8n "Create Tasks" Node (Push Tasks to TheHive)
// Position: Final node, after AI Tasks generation
//
// This node takes the AI-generated (or fallback) tasks and creates each one
// in the TheHive case via the TheHive API.
//
// Replace the IP and Bearer token with your current VM2 IP and org-level
// TheHive API key.

const data     = $('AI Tasks').item.json;       // or $('If').item.json for fallback tasks
const caseData = $input.first().json;            // TheHive case creation response

// Extract the case ID from TheHive's response
const caseId = caseData._id || caseData.id;
if (!caseId) {
  return [{ json: { error: 'No case ID returned from TheHive', received: caseData } }];
}

// Use AI tasks if available, otherwise fall back to static tasks
const tasks = data.ai_tasks || (data.responseTasks || []).map(t => ({
  title: t.title,
  description: t.desc || t.description,
  priority: 'MEDIUM'
}));

const results = [];

for (const task of tasks) {
  try {
    await $http.request({
      method: 'POST',
      url: 'http://192.168.1.31:9000/api/v1/case/' + caseId + '/task',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer YOUR_THEHIVE_ORG_API_KEY'
      },
      body: {
        title: task.title,
        description: task.description,
        status: 'Waiting',
        flag: false
      },
      json: true
    });
    results.push({ task: task.title, status: 'created' });
  } catch (e) {
    results.push({ task: task.title, status: 'failed', error: e.message });
  }
}

return [{ json: { case_id: caseId, tasks_created: results.length, results } }];
