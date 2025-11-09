# Frontend Integration Guide

## Complete Flow: From URL Entry to Results Display

This document explains what the frontend needs to implement to work with the dynamic agent scan API.

---

## User Journey

1. User visits `http://localhost:8080/dashboard/scans`
2. User enters target URL: `https://example.com`
3. User clicks "Start Scan"
4. Frontend shows "Scanning..." with live updates
5. When complete, frontend shows all findings

---

## Implementation Steps

### 1. Get API Key

The frontend needs to store the organization's API key (from organization creation):

```javascript
// Store this from login or organization setup
const API_KEY = 'fb_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
const BASE_URL = 'http://localhost:8080';
```

### 2. Start Scan Function

```javascript
async function startScan(targetUrl) {
  const response = await fetch(`${BASE_URL}/scan`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      target: targetUrl
    })
  });

  if (!response.ok) {
    throw new Error(`Scan failed: ${response.status}`);
  }

  const data = await response.json();

  return {
    jobId: data.job_id,
    status: data.status,
    message: data.message,
    target: data.target
  };
}
```

**Expected Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Dynamic security assessment started",
  "target": "https://example.com"
}
```

### 3. Poll for Status Updates

```javascript
async function getScanStatus(jobId) {
  const response = await fetch(`${BASE_URL}/scan/${jobId}`, {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to get status: ${response.status}`);
  }

  return await response.json();
}

function pollScanStatus(jobId, onUpdate, onComplete) {
  const pollInterval = setInterval(async () => {
    try {
      const status = await getScanStatus(jobId);

      // Call update callback with current status
      onUpdate(status);

      // If scan is done, stop polling
      if (status.status === 'completed' || status.status === 'failed') {
        clearInterval(pollInterval);
        onComplete(status);
      }
    } catch (error) {
      console.error('Polling error:', error);
      clearInterval(pollInterval);
      onComplete({ status: 'error', error: error.message });
    }
  }, 3000); // Poll every 3 seconds

  return pollInterval; // Return so caller can cancel if needed
}
```

**Status Response Structure:**

**While Running:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "target": "https://example.com",
  "findings": [],
  "total_findings": 0,
  "critical_findings": 0,
  "high_findings": 0,
  "execution_time_seconds": 45.2,
  "agents_created": []
}
```

**When Completed:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "target": "https://example.com",
  "findings": [
    {
      "title": "Critical: Database Credentials Exposed",
      "severity": "critical",
      "type": "INFORMATION_DISCLOSURE",
      "description": "API endpoint /api/config exposes DATABASE_URL",
      "discovered_by": "API Security Agent",
      "payload": "GET /api/config",
      "evidence": "{\"DATABASE_URL\": \"postgres://user:pass@db:5432/prod\"}",
      "url": "https://example.com/api/config"
    }
  ],
  "total_findings": 1,
  "critical_findings": 1,
  "high_findings": 0,
  "execution_time_seconds": 487.3,
  "agents_created": []
}
```

### 4. Get Agent Graph (Optional)

```javascript
async function getAgentGraph(jobId) {
  const response = await fetch(`${BASE_URL}/scan/${jobId}/agent-graph`, {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to get agent graph: ${response.status}`);
  }

  return await response.json();
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "graph": {
    "nodes": [
      {
        "id": "root-abc",
        "name": "Root Coordinator",
        "parent_id": null,
        "status": "completed"
      },
      {
        "id": "agent-001",
        "name": "API Security Agent",
        "parent_id": "root-abc",
        "modules": ["api_testing"],
        "status": "completed",
        "findings_count": 3
      }
    ],
    "edges": [
      {
        "from": "root-abc",
        "to": "agent-001",
        "type": "created"
      }
    ]
  }
}
```

---

## Complete Example: React Component

```javascript
import React, { useState } from 'react';

function ScanDashboard() {
  const [targetUrl, setTargetUrl] = useState('');
  const [currentScan, setCurrentScan] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const API_KEY = 'fb_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  const BASE_URL = 'http://localhost:8080';

  const handleStartScan = async () => {
    if (!targetUrl) {
      alert('Please enter a target URL');
      return;
    }

    setIsScanning(true);

    try {
      // Start the scan
      const response = await fetch(`${BASE_URL}/scan`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: targetUrl })
      });

      const data = await response.json();
      setCurrentScan(data);

      // Start polling for status
      pollStatus(data.job_id);
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan');
      setIsScanning(false);
    }
  };

  const pollStatus = (jobId) => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${BASE_URL}/scan/${jobId}`, {
          headers: {
            'Authorization': `Bearer ${API_KEY}`
          }
        });

        const status = await response.json();
        setScanStatus(status);

        // Stop polling when done
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(interval);
          setIsScanning(false);
        }
      } catch (error) {
        console.error('Polling error:', error);
        clearInterval(interval);
        setIsScanning(false);
      }
    }, 3000);
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}m ${secs}s`;
  };

  return (
    <div className="scan-dashboard">
      <h1>Security Scanner</h1>

      {/* Input Form */}
      <div className="scan-input">
        <input
          type="text"
          placeholder="Enter target URL (e.g., https://example.com)"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          disabled={isScanning}
        />
        <button onClick={handleStartScan} disabled={isScanning}>
          {isScanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {/* Scan Status */}
      {scanStatus && (
        <div className="scan-status">
          <h2>Scan Status</h2>
          <p><strong>Target:</strong> {scanStatus.target}</p>
          <p><strong>Status:</strong> {scanStatus.status}</p>
          {scanStatus.execution_time_seconds && (
            <p><strong>Time:</strong> {formatTime(scanStatus.execution_time_seconds)}</p>
          )}
          <p>
            <strong>Findings:</strong> {scanStatus.total_findings}
            (Critical: {scanStatus.critical_findings}, High: {scanStatus.high_findings})
          </p>
        </div>
      )}

      {/* Findings List */}
      {scanStatus?.findings && scanStatus.findings.length > 0 && (
        <div className="findings">
          <h2>Findings</h2>
          {scanStatus.findings.map((finding, index) => (
            <div key={index} className={`finding finding-${finding.severity}`}>
              <h3>
                <span className="severity-badge">{finding.severity.toUpperCase()}</span>
                {finding.title}
              </h3>
              <p><strong>Type:</strong> {finding.type}</p>
              <p><strong>Discovered by:</strong> {finding.discovered_by}</p>
              {finding.url && <p><strong>URL:</strong> {finding.url}</p>}
              <p>{finding.description}</p>

              {finding.payload && (
                <details>
                  <summary>View Payload</summary>
                  <pre>{finding.payload}</pre>
                </details>
              )}

              {finding.evidence && (
                <details>
                  <summary>View Evidence</summary>
                  <pre>{finding.evidence}</pre>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanDashboard;
```

---

## Status Values

The `status` field can be:

| Status | Meaning | Frontend Action |
|--------|---------|-----------------|
| `queued` | Scan is waiting to start | Show "Queued..." |
| `running` | Scan is in progress | Show "Scanning..." + findings so far |
| `completed` | Scan finished successfully | Show all findings, stop polling |
| `failed` | Scan encountered an error | Show error message, stop polling |

---

## Severity Levels

Findings have these severity levels:

| Severity | Color | Badge |
|----------|-------|-------|
| `critical` | Red | 🔴 CRITICAL |
| `high` | Orange | 🟠 HIGH |
| `medium` | Yellow | 🟡 MEDIUM |
| `low` | Blue | 🔵 LOW |
| `info` | Gray | ⚪ INFO |

---

## Error Handling

### Authentication Errors (401)
```json
{
  "detail": "Invalid API key"
}
```

**Frontend Action:** Redirect to login or show "Invalid API key" error

### Not Found (404)
```json
{
  "detail": "Scan not found"
}
```

**Frontend Action:** Show "Scan not found" error

### Server Error (500)
```json
{
  "detail": "Internal server error"
}
```

**Frontend Action:** Show "Server error, please try again"

---

## Summary: What Frontend Needs to Do

1. **Collect URL from user** - Simple text input
2. **Send POST /scan** - With Authorization header
3. **Save job_id** - From the response
4. **Poll GET /scan/{job_id}** - Every 2-5 seconds
5. **Update UI** - Show status, time, findings count
6. **Display findings** - When status changes to "completed"
7. **Stop polling** - When status is "completed" or "failed"

That's it! The backend handles all the complexity of running agents, discovering vulnerabilities, and storing results. The frontend just needs to:
- Submit the URL
- Poll for updates
- Display the results

---

## Testing

You can test the API using curl:

```bash
# Start a scan
curl -X POST http://localhost:8080/scan \
  -H "Authorization: Bearer fb_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get status (replace JOB_ID with actual job_id from above)
curl http://localhost:8080/scan/JOB_ID \
  -H "Authorization: Bearer fb_live_xxxxxxxxxxxx"

# Get agent graph
curl http://localhost:8080/scan/JOB_ID/agent-graph \
  -H "Authorization: Bearer fb_live_xxxxxxxxxxxx"
```
