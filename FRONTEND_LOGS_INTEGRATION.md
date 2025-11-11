# Frontend Integration Guide: Real-Time Execution Logs

## Overview

The backend now provides real-time execution logs for security scans via the `/scan/{job_id}/logs` endpoint. This allows the frontend to display live updates as agents execute tools, discover vulnerabilities, and complete tasks.

## API Endpoint

### GET /scan/{job_id}/logs

Returns execution logs for a specific scan job.

**Authentication:** Bearer token (JWT) or API key

**Example Request:**
```javascript
GET /scan/a203fc03-f0e3-4269-a711-def93dbbf9df/logs
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Example Response:**
```json
{
  "job_id": "a203fc03-f0e3-4269-a711-def93dbbf9df",
  "logs": [
    {
      "timestamp": "2025-11-09T19:15:22.123Z",
      "agent": "System",
      "action": "Scan status: started",
      "details": "Initializing security assessment for https://example.com"
    },
    {
      "timestamp": "2025-11-09T19:15:23.456Z",
      "agent": "System",
      "action": "Scan status: running",
      "details": "Root coordinator agent created, beginning analysis"
    },
    {
      "timestamp": "2025-11-09T19:15:25.789Z",
      "agent": "Root Coordinator",
      "action": "Created Reconnaissance Agent",
      "details": "Agent spawned by Root Coordinator"
    },
    {
      "timestamp": "2025-11-09T19:15:28.012Z",
      "agent": "Reconnaissance Agent",
      "action": "Executing http_scan",
      "details": "Running http_scan on https://example.com"
    },
    {
      "timestamp": "2025-11-09T19:15:35.345Z",
      "agent": "Root Coordinator",
      "action": "Created API Security Agent",
      "details": "Agent spawned by Root Coordinator"
    },
    {
      "timestamp": "2025-11-09T19:15:40.678Z",
      "agent": "API Security Agent",
      "action": "Executing api_fuzzing",
      "details": "Running api_fuzzing on /api/v1/users"
    },
    {
      "timestamp": "2025-11-09T19:16:12.901Z",
      "agent": "API Security Agent",
      "action": "Found HIGH vulnerability",
      "details": "Broken Object Level Authorization (BOLA) in User API"
    },
    {
      "timestamp": "2025-11-09T19:18:45.234Z",
      "agent": "System",
      "action": "Scan status: completed",
      "details": "Assessment complete. Found 5 vulnerabilities (1 critical, 2 high) in 192.5s"
    }
  ]
}
```

## Log Entry Structure

Each log entry contains:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string (ISO 8601) | When the event occurred |
| `agent` | string | Name of the agent performing the action (e.g., "Root Coordinator", "API Security Agent", "System") |
| `action` | string | Brief description of the action (e.g., "Created Recon Agent", "Executing nmap", "Found CRITICAL vulnerability") |
| `details` | string | Detailed information about the action |

## Frontend Implementation

### 1. Polling Strategy

Poll the logs endpoint every 2-3 seconds while the scan status is `running`.

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { scansApi } from '@/api/scans'

const props = defineProps<{
  scanId: string
}>()

const logs = ref<Array<{
  timestamp: string
  agent: string
  action: string
  details: string
}>>([])

const scanStatus = ref<'queued' | 'running' | 'completed' | 'failed'>('queued')
let pollInterval: number | null = null

const fetchLogs = async () => {
  try {
    const response = await scansApi.getLogs(props.scanId)
    logs.value = response.logs
  } catch (error) {
    console.error('Failed to fetch logs:', error)
  }
}

const fetchScanStatus = async () => {
  try {
    const scan = await scansApi.getById(props.scanId)
    scanStatus.value = scan.status

    // Stop polling if scan is complete or failed
    if ((scan.status === 'completed' || scan.status === 'failed') && pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
      // Fetch logs one final time
      await fetchLogs()
    }
  } catch (error) {
    console.error('Failed to fetch scan status:', error)
  }
}

onMounted(() => {
  // Initial fetch
  fetchLogs()
  fetchScanStatus()

  // Poll every 2.5 seconds
  pollInterval = setInterval(async () => {
    await fetchLogs()
    await fetchScanStatus()
  }, 2500)
})

onUnmounted(() => {
  if (pollInterval) {
    clearInterval(pollInterval)
  }
})
</script>
```

### 2. API Client Method

Add the logs method to your scans API client (`src/api/scans.ts`):

```typescript
import { apiClient } from './client'

export const scansApi = {
  // ... existing methods ...

  getLogs: async (scanId: string) => {
    const response = await apiClient.get<{
      job_id: string
      logs: Array<{
        timestamp: string
        agent: string
        action: string
        details: string
      }>
    }>(`/scan/${scanId}/logs`)
    return response.data
  },
}
```

### 3. Display Component

Example component for displaying logs with auto-scroll:

```vue
<template>
  <div class="execution-logs">
    <h3>Live Execution Logs</h3>

    <div class="logs-container" ref="logsContainer">
      <div
        v-for="(log, index) in logs"
        :key="index"
        class="log-entry"
        :class="getLogClass(log)"
      >
        <span class="log-timestamp">{{ formatTime(log.timestamp) }}</span>
        <span class="log-agent">{{ log.agent }}</span>
        <span class="log-action">{{ log.action }}</span>
        <span class="log-details">{{ log.details }}</span>
      </div>

      <div v-if="logs.length === 0" class="no-logs">
        Waiting for scan to start...
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'

const props = defineProps<{
  logs: Array<{
    timestamp: string
    agent: string
    action: string
    details: string
  }>
}>()

const logsContainer = ref<HTMLElement | null>(null)

// Auto-scroll to bottom when new logs arrive
watch(() => props.logs.length, async () => {
  await nextTick()
  if (logsContainer.value) {
    logsContainer.value.scrollTop = logsContainer.value.scrollHeight
  }
})

const formatTime = (timestamp: string) => {
  const date = new Date(timestamp)
  return date.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

const getLogClass = (log: any) => {
  // Add visual distinction for different log types
  if (log.action.includes('CRITICAL') || log.action.includes('Failed')) {
    return 'log-critical'
  }
  if (log.action.includes('HIGH')) {
    return 'log-high'
  }
  if (log.action.includes('Created') || log.action.includes('Agent')) {
    return 'log-agent'
  }
  if (log.action.includes('Executing')) {
    return 'log-tool'
  }
  if (log.action.includes('completed')) {
    return 'log-success'
  }
  return ''
}
</script>

<style scoped>
.execution-logs {
  background: #1a1a1a;
  border-radius: 8px;
  padding: 20px;
  margin: 20px 0;
}

.execution-logs h3 {
  margin-top: 0;
  color: #fff;
  font-size: 18px;
  margin-bottom: 15px;
}

.logs-container {
  background: #0d0d0d;
  border: 1px solid #333;
  border-radius: 4px;
  padding: 15px;
  max-height: 500px;
  overflow-y: auto;
  font-family: 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
}

.log-entry {
  padding: 6px 0;
  border-bottom: 1px solid #222;
  display: grid;
  grid-template-columns: 90px 180px 1fr;
  gap: 12px;
  color: #ccc;
}

.log-entry:last-child {
  border-bottom: none;
}

.log-timestamp {
  color: #888;
  font-size: 12px;
}

.log-agent {
  color: #4a9eff;
  font-weight: 600;
}

.log-action {
  color: #fff;
  font-weight: 500;
}

.log-details {
  color: #aaa;
}

/* Visual distinction for different log types */
.log-critical {
  background: rgba(220, 38, 38, 0.1);
  border-left: 3px solid #dc2626;
  padding-left: 8px;
}

.log-high {
  background: rgba(249, 115, 22, 0.1);
  border-left: 3px solid #f97316;
  padding-left: 8px;
}

.log-agent {
  background: rgba(34, 197, 94, 0.05);
}

.log-tool {
  background: rgba(59, 130, 246, 0.05);
}

.log-success {
  background: rgba(34, 197, 94, 0.1);
  border-left: 3px solid #22c55e;
  padding-left: 8px;
}

.no-logs {
  color: #666;
  text-align: center;
  padding: 40px;
  font-style: italic;
}

/* Custom scrollbar */
.logs-container::-webkit-scrollbar {
  width: 8px;
}

.logs-container::-webkit-scrollbar-track {
  background: #1a1a1a;
}

.logs-container::-webkit-scrollbar-thumb {
  background: #444;
  border-radius: 4px;
}

.logs-container::-webkit-scrollbar-thumb:hover {
  background: #555;
}
</style>
```

### 4. Integration into Scan Detail Page

Add the logs component to your scan detail page:

```vue
<template>
  <div class="scan-detail-page">
    <h1>Scan Details</h1>

    <!-- Scan status and info -->
    <ScanStatusCard :scan="scan" />

    <!-- Live execution logs (show when running or just completed) -->
    <ExecutionLogs
      v-if="scan.status === 'running' || scan.status === 'completed'"
      :scan-id="scanId"
    />

    <!-- Findings table -->
    <FindingsTable :findings="scan.findings" />
  </div>
</template>
```

## Log Types Reference

The backend generates the following types of log entries:

### System Logs
- **Scan status: started** - Scan initialization
- **Scan status: running** - Scan is actively running
- **Scan status: completed** - Scan finished successfully
- **Scan status: failed** - Scan encountered an error

### Agent Creation Logs
- **Created {AgentName}** - When a new specialized agent is spawned
  - Examples: "Created Reconnaissance Agent", "Created SQL Injection Agent"

### Tool Execution Logs
- **Executing {tool_name}** - When a security tool starts running
  - Examples: "Executing nmap", "Executing sqlmap", "Executing api_fuzzing"

### Vulnerability Discovery Logs
- **Found {SEVERITY} vulnerability** - When a vulnerability is discovered
  - Examples: "Found CRITICAL vulnerability", "Found HIGH vulnerability"

## Performance Considerations

1. **Polling Frequency**: 2-3 seconds is recommended. Faster polling may increase server load without meaningful UX benefits.

2. **Auto-scroll**: Only auto-scroll if user is already at the bottom of the logs. This prevents disrupting users who are reading earlier logs.

3. **Log Limit**: The backend returns all logs. Consider implementing client-side pagination or virtualization for very long-running scans.

4. **Stop Polling**: Always stop polling when scan status is `completed` or `failed`.

## Example User Experience

When a user visits `http://localhost:8080/dashboard/scans/{job_id}`, they will see:

```
Live Execution Logs
┌─────────────────────────────────────────────────────────────────────┐
│ 19:15:22  System              Scan status: started                   │
│           Initializing security assessment for https://example.com   │
│                                                                       │
│ 19:15:23  System              Scan status: running                   │
│           Root coordinator agent created, beginning analysis         │
│                                                                       │
│ 19:15:25  Root Coordinator    Created Reconnaissance Agent           │
│           Agent spawned by Root Coordinator                          │
│                                                                       │
│ 19:15:28  Reconnaissance      Executing http_scan                    │
│           Agent               Running http_scan on https://example... │
│                                                                       │
│ 19:15:40  API Security Agent  Executing api_fuzzing                  │
│           Running api_fuzzing on /api/v1/users                       │
│                                                                       │
│ 19:16:12  API Security Agent  Found HIGH vulnerability               │
│           Broken Object Level Authorization (BOLA) in User API       │
└─────────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Logs not updating
- Check that the scan status is `running`
- Verify polling interval is active
- Check browser console for API errors
- Verify authentication token is valid

### Empty logs array
- Scan may not have started yet (status: `queued`)
- Database connection issue (check backend logs)
- Job ID mismatch

### High server load
- Increase polling interval (currently 2.5s)
- Implement exponential backoff if errors occur
- Consider WebSocket implementation for production

## Future Enhancements

For production deployments, consider:
- **WebSockets**: Replace polling with WebSocket for true real-time updates
- **Log Streaming**: Stream logs as Server-Sent Events (SSE)
- **Log Filtering**: Allow users to filter by agent, severity, or action type
- **Export Logs**: Download logs as text file for offline analysis
