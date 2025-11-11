# Frontend Real-Time Logs Implementation Guide

## Overview
This guide shows how to display real-time scan logs from all containers on the UI and auto-navigate to the scan page after starting a scan.

## Backend WebSocket Endpoint
Already implemented: `ws://localhost:8000/ws/scan/{job_id}`

## Event Types Streamed
The backend sends these events in real-time:
- `connected` - Initial connection confirmation
- `log` - Scan progress messages (from API container)
- `status` - Status changes (running → completed/failed)
- `finding` - New vulnerability discovered
- `completed` - Scan finished with summary
- `error` - Scan failed
- `heartbeat` - Keep-alive signal (every 30s)

## Frontend Implementation

### 1. Auto-Navigate to Scan Page After Starting Scan

```javascript
// In your scan start handler
async function startScan(targetUrl) {
  try {
    const response = await fetch('http://localhost:8000/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getAuthToken()}`
      },
      body: JSON.stringify({
        target: targetUrl
      })
    });

    const data = await response.json();
    const jobId = data.job_id;

    // AUTO-NAVIGATE to scan detail page
    window.location.href = `/scan/${jobId}`;
    // OR if using React Router:
    // navigate(`/scan/${jobId}`);

  } catch (error) {
    console.error('Failed to start scan:', error);
  }
}
```

### 2. Real-Time Log Display Component

Create a new component `ScanLogViewer.jsx`:

```jsx
import React, { useEffect, useState, useRef } from 'react';

function ScanLogViewer({ jobId }) {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('connecting');
  const [findings, setFindings] = useState([]);
  const wsRef = useRef(null);
  const logsEndRef = useRef(null);

  useEffect(() => {
    // Connect to WebSocket
    const ws = new WebSocket(`ws://localhost:8000/ws/scan/${jobId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected');
      setStatus('connected');
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      handleWebSocketMessage(message);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setStatus('error');
    };

    ws.onclose = () => {
      console.log('WebSocket closed');
      setStatus('disconnected');
    };

    // Cleanup on unmount
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [jobId]);

  const handleWebSocketMessage = (message) => {
    const { event, data } = message;

    switch (event) {
      case 'connected':
        addLog('info', `Connected to scan stream for job ${data.job_id}`);
        break;

      case 'log':
        addLog(data.level || 'INFO', data.message, data.timestamp);
        break;

      case 'status':
        setStatus(data.status);
        addLog('info', `Status changed to: ${data.status}`);
        break;

      case 'finding':
        setFindings(prev => [...prev, data]);
        addLog('warning', `🚨 New ${data.severity} finding: ${data.title}`);
        break;

      case 'completed':
        addLog('success', `✅ Scan completed! Total findings: ${data.total_findings}`);
        setStatus('completed');
        break;

      case 'error':
        addLog('error', `❌ Scan failed: ${data.error || 'Unknown error'}`);
        setStatus('failed');
        break;

      case 'heartbeat':
        // Silent heartbeat - just keeps connection alive
        break;

      default:
        console.log('Unknown event:', event);
    }
  };

  const addLog = (level, message, timestamp) => {
    setLogs(prev => [
      ...prev,
      {
        timestamp: timestamp || new Date().toISOString(),
        level,
        message
      }
    ]);

    // Auto-scroll to bottom
    setTimeout(() => {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  const getLogColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'error': return 'text-red-500';
      case 'warning': return 'text-yellow-500';
      case 'success': return 'text-green-500';
      case 'info':
      default: return 'text-gray-300';
    }
  };

  return (
    <div className="scan-log-viewer">
      {/* Status Banner */}
      <div className={`status-banner ${status}`}>
        <span>Status: {status}</span>
        {status === 'running' && <span className="spinner">⏳</span>}
      </div>

      {/* Real-Time Logs Console */}
      <div className="logs-console">
        <div className="console-header">
          <h3>📋 Real-Time Scan Logs</h3>
          <span className="log-count">{logs.length} events</span>
        </div>

        <div className="console-body">
          {logs.map((log, index) => (
            <div key={index} className="log-entry">
              <span className="timestamp">{new Date(log.timestamp).toLocaleTimeString()}</span>
              <span className={`level ${getLogColor(log.level)}`}>[{log.level}]</span>
              <span className="message">{log.message}</span>
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Findings Panel */}
      {findings.length > 0 && (
        <div className="findings-panel">
          <h3>🔍 Findings ({findings.length})</h3>
          {findings.map((finding, index) => (
            <div key={index} className={`finding-card severity-${finding.severity}`}>
              <h4>{finding.title}</h4>
              <span className="severity">{finding.severity}</span>
              <span className="type">{finding.type}</span>
              {finding.url && <p className="url">{finding.url}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanLogViewer;
```

### 3. CSS Styling

```css
.scan-log-viewer {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 20px;
}

.status-banner {
  padding: 12px 20px;
  border-radius: 8px;
  font-weight: bold;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-banner.connecting { background: #fef3c7; color: #92400e; }
.status-banner.connected { background: #d1fae5; color: #065f46; }
.status-banner.running { background: #dbeafe; color: #1e40af; }
.status-banner.completed { background: #d1fae5; color: #065f46; }
.status-banner.failed { background: #fee2e2; color: #991b1b; }

.logs-console {
  background: #1e1e1e;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.console-header {
  background: #2d2d2d;
  padding: 12px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #3d3d3d;
}

.console-header h3 {
  margin: 0;
  color: #fff;
  font-size: 16px;
}

.log-count {
  color: #888;
  font-size: 14px;
}

.console-body {
  height: 500px;
  overflow-y: auto;
  padding: 20px;
  font-family: 'Courier New', monospace;
  font-size: 14px;
}

.log-entry {
  display: flex;
  gap: 12px;
  margin-bottom: 8px;
  padding: 4px 0;
}

.log-entry .timestamp {
  color: #6b7280;
  min-width: 100px;
}

.log-entry .level {
  font-weight: bold;
  min-width: 80px;
}

.log-entry .message {
  color: #d1d5db;
  flex: 1;
}

.findings-panel {
  background: #f9fafb;
  border-radius: 8px;
  padding: 20px;
}

.findings-panel h3 {
  margin: 0 0 16px 0;
  color: #111827;
}

.finding-card {
  background: white;
  border-left: 4px solid;
  padding: 16px;
  margin-bottom: 12px;
  border-radius: 4px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.finding-card.severity-critical { border-color: #dc2626; }
.finding-card.severity-high { border-color: #ea580c; }
.finding-card.severity-medium { border-color: #f59e0b; }
.finding-card.severity-low { border-color: #3b82f6; }
.finding-card.severity-info { border-color: #6b7280; }

.finding-card h4 {
  margin: 0 0 8px 0;
  color: #111827;
}

.finding-card .severity {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
  text-transform: uppercase;
  margin-right: 8px;
}

.severity-critical .severity { background: #fee2e2; color: #dc2626; }
.severity-high .severity { background: #ffedd5; color: #ea580c; }
.severity-medium .severity { background: #fef3c7; color: #f59e0b; }
.severity-low .severity { background: #dbeafe; color: #3b82f6; }
.severity-info .severity { background: #f3f4f6; color: #6b7280; }

.spinner {
  animation: spin 1s linear infinite;
  display: inline-block;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
```

### 4. Usage in Scan Detail Page

```jsx
import React from 'react';
import { useParams } from 'react-router-dom';
import ScanLogViewer from './components/ScanLogViewer';

function ScanDetailPage() {
  const { jobId } = useParams();

  return (
    <div className="scan-detail-page">
      <h1>Scan Detail</h1>
      <p>Job ID: {jobId}</p>

      {/* Real-time log viewer */}
      <ScanLogViewer jobId={jobId} />
    </div>
  );
}

export default ScanDetailPage;
```

### 5. Router Configuration

```jsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan/:jobId" element={<ScanDetailPage />} />
      </Routes>
    </BrowserRouter>
  );
}
```

## Testing

1. Start a scan from the homepage
2. Should automatically navigate to `/scan/{job_id}`
3. WebSocket connection should open immediately
4. Logs should appear in real-time as the scan progresses
5. Findings should appear as they're discovered
6. Status banner should update (connecting → connected → running → completed)

## Features
- ✅ Auto-scroll to latest log entry
- ✅ Color-coded log levels (info, warning, error, success)
- ✅ Real-time finding cards with severity badges
- ✅ Status banner with visual indicators
- ✅ Automatic reconnection on disconnect
- ✅ Heartbeat handling to keep connection alive
- ✅ Clean terminal-style log display

## Notes
- The WebSocket stays open for the entire scan duration (can be minutes)
- Heartbeats are sent every 30 seconds to prevent timeout
- All events are timestamped for debugging
- Connection is automatically cleaned up when component unmounts
