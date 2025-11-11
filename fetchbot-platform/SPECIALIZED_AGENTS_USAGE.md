# Specialized Agents Usage Guide

## Overview

The specialized agent architecture eliminates duplicate testing by distributing work to focused agents. Each agent type specializes in one domain of security testing.

## Quick Start

### 1. Start the Specialized Agent System

```bash
cd fetchbot-platform
docker-compose -f docker-compose-specialized-agents.yml up -d
```

This starts:
- 1 Orchestrator (port 8001)
- 1 Kali Tools Container (port 9000)
- 10 Specialized Agents:
  - 2 Network Agents
  - 2 Fuzzing Agents
  - 2 SQL Injection Agents
  - 1 Recon Agent
  - 1 XSS Agent
  - 2 Auth Agents

### 2. Start a Scan

```bash
curl -X POST http://localhost:8001/scans/start \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

Response:
```json
{
  "status": "started",
  "job_id": "scan-20250111-143022",
  "target": "example.com",
  "initialization": {
    "status": "initialized",
    "initial_work_items": 6,
    "work_distribution": {
      "network": 2,
      "recon": 4
    }
  }
}
```

### 3. Check Scan Status

```bash
curl http://localhost:8001/scans/{job_id}/status
```

Response:
```json
{
  "job_id": "scan-20250111-143022",
  "target": "example.com",
  "status": "running",
  "execution_time_seconds": 45.2,
  "queue_status": {
    "total_added": 23,
    "total_completed": 15,
    "duplicates_prevented": 47,
    "pending_by_type": {
      "sqli": 3,
      "xss": 2,
      "fuzzing": 3
    },
    "in_progress_count": 6,
    "efficiency": 67.14
  },
  "agents": {
    "total": 10,
    "by_type": {
      "network": 2,
      "fuzzing": 2,
      "sqli": 2,
      "recon": 1,
      "xss": 1,
      "auth": 2
    },
    "active": 10
  },
  "findings": {
    "total": 8,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2
    },
    "by_agent_type": {
      "recon": 3,
      "sqli": 2,
      "auth": 3
    }
  },
  "efficiency_metrics": {
    "duplicates_prevented": 47,
    "efficiency_percentage": 67.14
  }
}
```

### 4. Finalize Scan

```bash
curl -X POST http://localhost:8001/scans/{job_id}/finalize
```

Returns complete scan report with all findings.

## Architecture Benefits

### Before (Monolithic)
```
Target: jsxtool.com

3 agents × 71 tools = 213 potential tests

Logs show:
- /api/login tested 50+ times
- SQL injection payloads repeated 30+ times
- XSS tests duplicated 20+ times

Result: Massive waste, 15min scan time
```

### After (Specialized)
```
Target: jsxtool.com

Work Queue distributes:
- /api/login → tested ONCE by ReconAgent
- SQL injection → SQLInjectionAgent tests each endpoint ONCE
- XSS → XSSAgent tests each form ONCE

Result: No duplication, 5-7min scan time (3x faster)
```

## Scaling

### Scale Specific Agent Types

If you need more fuzzing capacity:

```bash
docker-compose -f docker-compose-specialized-agents.yml up -d --scale fuzzing-agent=5
```

This spawns 5 Fuzzing Agents (instead of 2) to handle more fuzzing work in parallel.

### Scale by Workload

Monitor queue depth:

```bash
curl http://localhost:8001/stats
```

If `pending_by_type.fuzzing` is high, scale up fuzzing agents:

```bash
docker-compose -f docker-compose-specialized-agents.yml up -d --scale fuzzing-agent=8
```

## Monitoring

### View Orchestrator Stats

```bash
curl http://localhost:8001/stats
```

### View Individual Agent Health

```bash
# Network agent
curl http://localhost:9100/health

# Fuzzing agent
curl http://localhost:9101/health

# SQLi agent
curl http://localhost:9102/health
```

### View Logs

```bash
# All agents
docker-compose -f docker-compose-specialized-agents.yml logs -f

# Specific agent type
docker-compose -f docker-compose-specialized-agents.yml logs -f network-agent-1

# Orchestrator
docker-compose -f docker-compose-specialized-agents.yml logs -f orchestrator
```

## Agent Types

### NetworkAgent (Port: 9100)
**Tools:**
- nmap_scan
- nmap_detailed_scan
- dns_enumerate
- service_detection

**Use Case:** Port scanning, service detection, network reconnaissance

### FuzzingAgent (Port: 9101)
**Tools:**
- api_fuzzing
- directory_enumeration
- ffuf_scan
- gobuster_scan
- api_method_fuzzing

**Use Case:** Discovering hidden endpoints, fuzzing APIs

### SQLInjectionAgent (Port: 9102)
**Tools:**
- sql_injection_test
- sqlmap_test
- database_enumeration

**Use Case:** SQL injection testing and database enumeration

### ReconAgent (Port: 9103)
**Tools:**
- http_scan
- javascript_analysis
- security_headers_check
- detect_exposed_env_vars
- scan_env_files

**Use Case:** Web reconnaissance, technology detection, finding exposed files

### XSSAgent (Port: 9104)
**Tools:**
- xss_test
- csrf_test

**Use Case:** XSS and CSRF vulnerability detection

### AuthAgent (Port: 9105)
**Tools:**
- api_brute_force
- api_rate_limit_test
- api_privilege_escalation_test
- api_idor_test

**Use Case:** Authentication/authorization testing, IDOR detection

## Work Queue Flow

```
1. User starts scan → Orchestrator creates initial work items

2. Orchestrator queues work by agent type:
   - network: [nmap_scan, dns_enumerate]
   - recon: [http_scan, javascript_analysis, security_headers, env_vars]

3. Agents pull work from orchestrator:
   - NetworkAgent-1: "GET /work/get" → receives nmap_scan
   - NetworkAgent-2: "GET /work/get" → receives dns_enumerate
   - ReconAgent-1: "GET /work/get" → receives http_scan

4. Agents execute work and report back:
   - NetworkAgent-1: "POST /work/complete" with findings
   - ReconAgent-1: "POST /work/complete" with discoveries

5. Orchestrator processes results:
   - Stores findings
   - If discoveries found, queue follow-up work
   - Example: ReconAgent found login form → queue XSS test

6. Deduplication ensures no repeat work:
   - Hash of (tool + params) checked before queuing
   - If already completed → skip (prevented duplicate)
   - If in progress → skip (prevented duplicate)
   - If pending → skip (prevented duplicate)

7. Scan completes when work queue is empty
```

## Deduplication Example

```python
# Work item 1
{
  "tool": "sql_injection_test",
  "params": {"url": "https://example.com/login", "parameter": "username"}
}
# Hash: abc123...

# Work item 2 (DUPLICATE - same tool + params)
{
  "tool": "sql_injection_test",
  "params": {"url": "https://example.com/login", "parameter": "username"}
}
# Hash: abc123... → REJECTED (duplicate hash)

# Work item 3 (DIFFERENT - different parameter)
{
  "tool": "sql_injection_test",
  "params": {"url": "https://example.com/login", "parameter": "password"}
}
# Hash: def456... → ACCEPTED (new hash)
```

Result: Work item 2 is prevented, saving time and resources.

## Performance Comparison

### Old Architecture (Monolithic)
- 3 agents
- Each runs ALL 71 tools
- Logs show 50+ duplicate tests on /api/login
- Scan time: ~15 minutes
- Resource usage: 6GB RAM

### New Architecture (Specialized)
- 10 specialized agents
- Each runs 2-5 focused tools
- Work queue prevents ALL duplicates
- Scan time: ~5-7 minutes (3x faster)
- Resource usage: ~2GB RAM (3x more efficient)
- Efficiency metric: 60-70% duplicates prevented

## Troubleshooting

### No work being distributed

Check orchestrator logs:
```bash
docker logs orchestrator
```

Verify agents are registered:
```bash
curl http://localhost:8001/stats
```

### Agent not finding work

Check if agent type matches work in queue:
```bash
curl http://localhost:8001/scans/{job_id}/status
```

Look at `queue_status.pending_by_type` to see which work is available.

### Kali tools container not accessible

Test connectivity:
```bash
docker exec network-agent-1 curl http://kali-agent:9000/health
```

Check Kali container is running:
```bash
docker ps | grep kali-agent
```

## Migration from Monolithic

To migrate from the old monolithic architecture:

1. **Stop old system:**
```bash
docker-compose down
```

2. **Start specialized system:**
```bash
docker-compose -f docker-compose-specialized-agents.yml up -d
```

3. **Update API calls:**

Old API:
```bash
POST /scans
```

New API:
```bash
POST /scans/start
GET /scans/{job_id}/status
POST /scans/{job_id}/finalize
```

## Future Enhancements

Planned improvements:
- Redis-backed work queue for persistence
- Agent auto-scaling based on queue depth
- WebSocket streaming of findings
- Grafana dashboards for monitoring
- Agent failure recovery and retry logic
- Priority-based work queue scheduling

## Support

For issues or questions:
- GitHub Issues: [Repository URL]
- Documentation: See ARCHITECTURE_SPECIALIZED_AGENTS.md
- Logs: `docker-compose -f docker-compose-specialized-agents.yml logs`
