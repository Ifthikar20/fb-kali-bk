# Testing Live Execution Logs

## Overview

The system now logs detailed, user-friendly messages about what each agent is doing during scans.

## Example Log Messages

**Before (old):**
```
[Reconnaissance Agent] Executing http_scan: Running http_scan on target
```

**After (new):**
```json
{
  "timestamp": "2025-11-09T20:16:26.686Z",
  "agent": "Reconnaissance Agent",
  "action": "🌐 Web Analysis",
  "details": "Analyzing website structure and technologies at https://www.betterandbliss.com/"
}

{
  "timestamp": "2025-11-09T20:16:27.530Z",
  "agent": "Reconnaissance Agent",
  "action": "🔍 Port Scanning",
  "details": "Scanning example.com to discover open ports and running services"
}

{
  "timestamp": "2025-11-09T20:16:21.570Z",
  "agent": "Root Coordinator",
  "action": "🤖 Spawned SQL Injection Agent",
  "details": "Created specialized agent to test for SQL injection vulnerabilities"
}

{
  "timestamp": "2025-11-09 20:06:01.258Z",
  "agent": "SQL Injection Agent",
  "action": "🔴 CRITICAL Vulnerability Found",
  "details": "SQL Injection in Login Page"
}
```

## How to Test

### 1. Rebuild API Container

```bash
# Rebuild to get new log messages
docker compose -f docker-compose-multi-kali.yml build api

# Restart API
docker compose -f docker-compose-multi-kali.yml up -d api

# Watch logs in terminal
docker compose -f docker-compose-multi-kali.yml logs -f api
```

### 2. Start a New Scan

**Via Frontend:**
- Go to http://localhost:8080
- Create a new scan with target: https://www.betterandbliss.com/
- Note the job_id from the response

**Via API:**
```bash
# Get your auth token first (from browser localStorage or login)
export AUTH_TOKEN="your-token-here"

curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://www.betterandbliss.com/"}'

# Response will include job_id
# {"job_id": "abc-123-...", "status": "queued", ...}
```

### 3. Fetch Live Logs

**Via API:**
```bash
export JOB_ID="your-job-id-here"

# Poll this endpoint every 2-3 seconds
curl http://localhost:8000/scan/$JOB_ID/logs \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

**Expected Response:**
```json
{
  "job_id": "abc-123-...",
  "logs": [
    {
      "timestamp": "2025-11-09T20:16:19.292Z",
      "agent": "System",
      "action": "🚀 Scan Started",
      "details": "Initializing security assessment for https://www.betterandbliss.com/"
    },
    {
      "timestamp": "2025-11-09T20:16:19.341Z",
      "agent": "System",
      "action": "⚡ Scan Running",
      "details": "Root coordinator agent created, beginning analysis"
    },
    {
      "timestamp": "2025-11-09T20:16:21.570Z",
      "agent": "Root Coordinator",
      "action": "🤖 Spawned Reconnaissance Agent",
      "details": "Created specialized agent to discover target architecture and technologies"
    },
    {
      "timestamp": "2025-11-09T20:16:26.686Z",
      "agent": "Reconnaissance Agent",
      "action": "🌐 Web Analysis",
      "details": "Analyzing website structure and technologies at https://www.betterandbliss.com/"
    },
    {
      "timestamp": "2025-11-09T20:16:27.100Z",
      "agent": "Reconnaissance Agent",
      "action": "📜 JavaScript Scan",
      "details": "Analyzing JavaScript files at https://www.betterandbliss.com/ for sensitive data"
    },
    {
      "timestamp": "2025-11-09T20:16:27.271Z",
      "agent": "Reconnaissance Agent",
      "action": "🛡️ Security Headers",
      "details": "Checking security headers at https://www.betterandbliss.com/"
    },
    {
      "timestamp": "2025-11-09T20:16:27.530Z",
      "agent": "Reconnaissance Agent",
      "action": "🔍 Port Scanning",
      "details": "Scanning betterandbliss.com to discover open ports and running services"
    }
  ]
}
```

### 4. Frontend Integration

Your frontend should:

1. **Poll for logs every 2-3 seconds while scan is running:**
   ```javascript
   async function pollLogs(jobId) {
     const response = await fetch(`http://localhost:8000/scan/${jobId}/logs`, {
       headers: { 'Authorization': `Bearer ${token}` }
     });
     const data = await response.json();
     return data.logs;
   }

   // Poll every 2 seconds
   const interval = setInterval(async () => {
     const logs = await pollLogs(jobId);
     updateLogsDisplay(logs);

     // Stop when scan completes
     if (scanStatus === 'completed') {
       clearInterval(interval);
     }
   }, 2000);
   ```

2. **Display logs in reverse chronological order** (newest first)

3. **Use emojis for visual appeal:**
   - 🚀 = Scan started
   - ⚡ = Scan running
   - 🤖 = Agent created
   - 🔍 = Port scan
   - 🌐 = Web analysis
   - 💉 = SQL injection test
   - ⚠️ = XSS test
   - 🔴 = Critical finding
   - 🟠 = High finding
   - ✅ = Scan completed

4. **Auto-scroll to show latest logs**

5. **Color code by severity:**
   - Red: CRITICAL
   - Orange: HIGH
   - Yellow: MEDIUM
   - Blue: LOW
   - Gray: INFO

## Expected Behavior

✅ **Logs appear in real-time** as agents work
✅ **Each log entry is descriptive** and tells what's happening
✅ **Emojis make it easy to scan** for important events
✅ **Findings are highlighted** with severity colors
✅ **Frontend shows progress** without needing to check terminal

## Troubleshooting

### No logs appearing?

1. **Check if db_url is being passed:**
   ```bash
   docker compose -f docker-compose-multi-kali.yml logs api | grep "db_url"
   ```

2. **Check database connection:**
   ```bash
   docker compose -f docker-compose-multi-kali.yml logs postgres
   ```

3. **Verify logs are in database:**
   ```bash
   docker compose -f docker-compose-multi-kali.yml exec postgres psql -U fetchbot -d fetchbot -c "SELECT id, execution_logs FROM pentest_jobs ORDER BY created_at DESC LIMIT 1;"
   ```

### Logs not updating?

- Make sure you're polling the endpoint every 2-3 seconds
- Check that the scan is still running (`status != 'completed'`)
- Verify API container was rebuilt with new logging code

### Logs show "null" or empty array?

- Scan might not have started yet
- Check scan status: `GET /scan/{job_id}` - should show `status: "running"`
- Wait a few seconds and try again
