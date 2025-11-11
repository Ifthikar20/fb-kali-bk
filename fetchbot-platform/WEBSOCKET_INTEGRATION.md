# WebSocket Real-Time Scan Streaming

## Overview

The backend now supports **WebSocket real-time event streaming** for scans. Instead of polling, the frontend establishes a WebSocket connection and receives instant updates as the scan progresses.

## WebSocket Endpoint

```
ws://localhost:8000/ws/scan/{job_id}
```

## Event Types

Events are JSON messages with this structure:

```json
{
  "event": "event_type",
  "data": { ...event-specific data... }
}
```

| Event | Description | Data Fields |
|-------|-------------|-------------|
| `connected` | Connection established | `job_id`, `message` |
| `log` | Scan progress log | `timestamp`, `message`, `level` |
| `status` | Status change | `status` |
| `finding` | New vulnerability found | `title`, `severity`, `type`, `url` |
| `completed` | Scan finished | `status`, `total_findings`, `critical`, `high` |
| `error` | Scan failed | `status`, `error` |

## Frontend Example (React)

```jsx
import { useEffect, useState } from 'react';

function ScanLiveView({ jobId }) {
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [status, setStatus] = useState('queued');

  useEffect(() => {
    const ws = new WebSocket(`ws://localhost:8000/ws/scan/${jobId}`);

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);

      switch(msg.event) {
        case 'log':
          setLogs(prev => [...prev, msg.data]);
          break;

        case 'status':
          setStatus(msg.data.status);
          break;

        case 'finding':
          setFindings(prev => [...prev, msg.data]);
          break;

        case 'completed':
          setStatus('completed');
          console.log('Scan complete:', msg.data);
          break;

        case 'error':
          setStatus('failed');
          console.error('Scan error:', msg.data.error);
          break;
      }
    };

    return () => ws.close();
  }, [jobId]);

  return (
    <div>
      <h2>Scan Status: {status}</h2>

      <div className="logs">
        <h3>Live Logs</h3>
        {logs.map((log, i) => (
          <div key={i} className={log.level}>
            {new Date(log.timestamp).toLocaleTimeString()} - {log.message}
          </div>
        ))}
      </div>

      <div className="findings">
        <h3>Findings ({findings.length})</h3>
        {findings.map((f, i) => (
          <div key={i} className={f.severity}>
            <strong>{f.title}</strong>
            <span>{f.severity}</span>
            <small>{f.url}</small>
          </div>
        ))}
      </div>
    </div>
  );
}
```

## Example Event Flow

### 1. Connection Established
```json
{
  "event": "connected",
  "data": {
    "job_id": "abc-123",
    "message": "Connected to scan stream"
  }
}
```

### 2. Scan Starts
```json
{
  "event": "log",
  "data": {
    "timestamp": "2025-11-09T15:00:00.123Z",
    "message": "🚀 Starting scan for https://example.com",
    "level": "INFO"
  }
}
```

### 3. Status Update
```json
{
  "event": "status",
  "data": {
    "status": "running"
  }
}
```

### 4. Finding Discovered
```json
{
  "event": "finding",
  "data": {
    "title": "SQL Injection",
    "severity": "critical",
    "type": "sql_injection",
    "url": "https://example.com/api/login"
  }
}
```

### 5. Scan Completes
```json
{
  "event": "completed",
  "data": {
    "status": "completed",
    "total_findings": 15,
    "critical": 2,
    "high": 5
  }
}
```

## Benefits

- ✅ **Instant updates** - No polling delay
- ✅ **Efficient** - Only sends when there's new data
- ✅ **Real-time UX** - Live progress feed
- ✅ **Lower server load** - No repeated HTTP requests
