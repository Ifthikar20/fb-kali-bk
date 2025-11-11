# Specialized Agent Architecture

## Overview

This document describes the refactored architecture using specialized agents, each focused on a single domain of security testing. This replaces the monolithic Kali agent that runs all tools.

## Problem Statement

**Current Issues:**
- One monolithic agent runs ALL 71 security tools
- Multiple agent instances duplicate the same tests
- No coordination between agents
- Inefficient resource usage
- Difficult to scale specific testing types

**Evidence from logs:**
- Same `/api/login` endpoint tested 50+ times
- SQL injection payloads repeated across multiple agents
- XSS tests duplicated identically
- No shared state between agents

## New Architecture

### Specialized Agent Types

Each agent runs in its own Docker container with only the tools it needs:

#### 1. **NetworkAgent** (Container: `network-agent`)
**Tools:**
- `nmap_scan`
- `nmap_detailed_scan`
- `dns_enumerate`
- `service_detection`

**Responsibilities:**
- Port scanning and service detection
- DNS enumeration
- OS fingerprinting
- Network topology mapping

**Container:** Lightweight Kali with nmap, masscan, dnsutils

---

#### 2. **FuzzingAgent** (Container: `fuzzing-agent`)
**Tools:**
- `api_fuzzing`
- `directory_enumeration`
- `ffuf_scan`
- `gobuster_scan`
- `api_method_fuzzing`

**Responsibilities:**
- API endpoint fuzzing
- Directory/file brute forcing
- Parameter fuzzing
- HTTP method testing

**Container:** Kali with ffuf, gobuster, wfuzz

---

#### 3. **SQLInjectionAgent** (Container: `sqli-agent`)
**Tools:**
- `sql_injection_test`
- `sqlmap_test`
- `database_enumeration`

**Responsibilities:**
- SQL injection testing (all techniques)
- Database enumeration
- sqlmap automation

**Container:** Kali with sqlmap, custom SQL injection tools

---

#### 4. **NoSQLInjectionAgent** (Container: `nosqli-agent`)
**Tools:**
- `nosql_injection_test`

**Responsibilities:**
- MongoDB injection
- CouchDB injection
- NoSQL-specific attacks

**Container:** Lightweight with NoSQL injection tools

---

#### 5. **XSSAgent** (Container: `xss-agent`)
**Tools:**
- `xss_test`
- `csrf_test`

**Responsibilities:**
- XSS testing (reflected, stored, DOM-based)
- CSRF testing
- Client-side injection attacks

**Container:** Lightweight with XSS Hunter, custom payloads

---

#### 6. **AuthAgent** (Container: `auth-agent`)
**Tools:**
- `api_brute_force`
- `api_rate_limit_test`
- `api_privilege_escalation_test`
- `api_idor_test`

**Responsibilities:**
- Authentication bypass
- Authorization testing
- IDOR vulnerabilities
- Privilege escalation
- Rate limiting verification

**Container:** Lightweight with Hydra, custom auth tools

---

#### 7. **ReconAgent** (Container: `recon-agent`)
**Tools:**
- `http_scan`
- `javascript_analysis`
- `security_headers_check`
- `detect_exposed_env_vars`
- `scan_env_files`

**Responsibilities:**
- Web application reconnaissance
- Technology detection
- JavaScript analysis for secrets
- Security header analysis
- Exposed file/config detection

**Container:** Lightweight with curl, wget, JS parsers

---

#### 8. **WebVulnAgent** (Container: `webvuln-agent`)
**Tools:**
- `nikto_scan`
- `security_headers_check`

**Responsibilities:**
- Comprehensive web vulnerability scanning
- Nikto-based testing
- OWASP Top 10 checks

**Container:** Kali with Nikto, Burp Suite (headless)

---

#### 9. **APISecurityAgent** (Container: `apisec-agent`)
**Tools:**
- `api_mass_assignment_test`
- `graphql_security_test`

**Responsibilities:**
- API-specific vulnerabilities
- Mass assignment
- GraphQL introspection and attacks
- API schema validation

**Container:** Lightweight with GraphQL tools

---

## Orchestrator Architecture

### SpecializedAgentOrchestrator

**Responsibilities:**
1. **Work Queue Management** - Distributes unique work items to agents
2. **Deduplication** - Ensures no duplicate testing
3. **Results Aggregation** - Collects findings from all agents
4. **Agent Health Monitoring** - Tracks agent status
5. **Dynamic Scaling** - Spawns more agents based on workload

### Work Queue Design

```python
class WorkQueue:
    """
    Thread-safe work queue with deduplication
    """
    def __init__(self):
        self.pending = {}  # {agent_type: [work_items]}
        self.in_progress = set()  # Set of work_item hashes
        self.completed = set()  # Set of completed work_item hashes
        self.lock = asyncio.Lock()

    async def add_work(self, agent_type: str, work_item: dict):
        """Add work item if not already queued/completed"""
        work_hash = self._hash_work_item(work_item)

        async with self.lock:
            if work_hash in self.completed or work_hash in self.in_progress:
                return False  # Already done or in progress

            if agent_type not in self.pending:
                self.pending[agent_type] = []

            self.pending[agent_type].append(work_item)
            return True

    async def get_work(self, agent_type: str) -> Optional[dict]:
        """Get next work item for agent type"""
        async with self.lock:
            if agent_type not in self.pending or not self.pending[agent_type]:
                return None

            work_item = self.pending[agent_type].pop(0)
            work_hash = self._hash_work_item(work_item)
            self.in_progress.add(work_hash)
            return work_item

    async def mark_completed(self, work_item: dict):
        """Mark work item as completed"""
        work_hash = self._hash_work_item(work_item)

        async with self.lock:
            self.in_progress.discard(work_hash)
            self.completed.add(work_hash)
```

### Workflow

```
User Request → SpecializedAgentOrchestrator
                ↓
        [Work Queue Created]
                ↓
    ┌───────────┴───────────┐
    ↓                       ↓
NetworkAgent         FuzzingAgent
    ↓                       ↓
SQLInjectionAgent    XSSAgent
    ↓                       ↓
AuthAgent            ReconAgent
    ↓                       ↓
    └───────────┬───────────┘
                ↓
    [Results Aggregator]
                ↓
    [Deduplication & Ranking]
                ↓
        [Final Report]
```

## Docker Composition

### docker-compose-specialized-agents.yml

```yaml
version: '3.8'

services:
  orchestrator:
    build: ./orchestrator
    ports:
      - "8001:8001"
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - network-agent
      - fuzzing-agent
      - sqli-agent
      - xss-agent
      - auth-agent
      - recon-agent

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  network-agent:
    build: ./agents/network-agent
    environment:
      - AGENT_TYPE=network
      - AGENT_ID=network-1
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 2

  fuzzing-agent:
    build: ./agents/fuzzing-agent
    environment:
      - AGENT_TYPE=fuzzing
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 3

  sqli-agent:
    build: ./agents/sqli-agent
    environment:
      - AGENT_TYPE=sqli
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 2

  xss-agent:
    build: ./agents/xss-agent
    environment:
      - AGENT_TYPE=xss
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 1

  auth-agent:
    build: ./agents/auth-agent
    environment:
      - AGENT_TYPE=auth
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 2

  recon-agent:
    build: ./agents/recon-agent
    environment:
      - AGENT_TYPE=recon
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 1

  nosqli-agent:
    build: ./agents/nosqli-agent
    environment:
      - AGENT_TYPE=nosqli
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 1

  webvuln-agent:
    build: ./agents/webvuln-agent
    environment:
      - AGENT_TYPE=webvuln
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 1

  apisec-agent:
    build: ./agents/apisec-agent
    environment:
      - AGENT_TYPE=apisec
      - ORCHESTRATOR_URL=http://orchestrator:8001
    deploy:
      replicas: 1
```

## Benefits

### 1. **No Duplication**
- Each agent only runs its specialized tools
- Work queue ensures no duplicate testing
- Shared Redis state prevents re-testing

### 2. **Parallel Execution**
- All agents run simultaneously
- NetworkAgent scans while SQLInjectionAgent tests
- Results come in as they're discovered

### 3. **Resource Efficiency**
- Each container only has tools it needs
- NetworkAgent: 200MB vs monolithic 2GB
- Better CPU/memory utilization

### 4. **Scalability**
- Scale specific agents based on workload
- Heavy fuzzing? Spin up 5 FuzzingAgents
- Light on SQLi? Use 1 SQLInjectionAgent

### 5. **Fault Isolation**
- If SQLInjectionAgent crashes, others continue
- No single point of failure
- Better error handling

### 6. **Clear Separation of Concerns**
- Each agent has focused responsibility
- Easier to maintain and debug
- Simpler to add new capabilities

## Migration Strategy

### Phase 1: Create Base Infrastructure
1. Implement `BaseSpecializedAgent` class
2. Create `SpecializedAgentOrchestrator`
3. Implement `WorkQueue` with Redis backend
4. Create `ResultsAggregator`

### Phase 2: Implement Specialized Agents
1. NetworkAgent (highest priority - foundation for others)
2. ReconAgent (discovers endpoints for other agents)
3. FuzzingAgent (discovers more endpoints)
4. SQLInjectionAgent (high value)
5. XSSAgent
6. AuthAgent
7. NoSQLInjectionAgent
8. WebVulnAgent
9. APISecurityAgent

### Phase 3: Docker Configuration
1. Create Dockerfiles for each agent
2. Create docker-compose-specialized-agents.yml
3. Set up Redis for shared state
4. Configure health checks

### Phase 4: Testing
1. Test each agent in isolation
2. Test orchestrator with 2 agents
3. Test full system with all agents
4. Load testing with multiple replicas

### Phase 5: Deployment
1. Deploy to staging environment
2. Run parallel tests (old vs new architecture)
3. Verify no duplicate testing
4. Measure performance improvements
5. Deploy to production

## Expected Performance Improvements

**Before (Monolithic):**
- 3 agents × 71 tools = 213 potential duplicate tests
- Average scan time: 15 minutes
- Resource usage: 3 × 2GB = 6GB RAM

**After (Specialized):**
- 9 specialized agents × focused tools = no duplication
- Average scan time: 5-7 minutes (3x faster)
- Resource usage: ~2GB total RAM (3x more efficient)
- Findings quality: Same or better

## Monitoring & Observability

### Metrics to Track
- Work items per agent type
- Duplicate work items prevented
- Agent response times
- Findings per agent
- Resource utilization per container

### Dashboards
- Agent health status
- Work queue depth
- Findings timeline
- Resource usage graphs

## Security Considerations

1. **Agent Isolation**: Each agent runs in isolated container
2. **Least Privilege**: Agents only have tools they need
3. **Network Segmentation**: Agents can't communicate directly
4. **Secret Management**: Credentials in environment variables
5. **Audit Logging**: All agent actions logged centrally

## Conclusion

The specialized agent architecture provides:
- ✅ No duplicate testing
- ✅ Parallel execution
- ✅ Better resource utilization
- ✅ Easier scalability
- ✅ Fault isolation
- ✅ Clearer responsibilities

This addresses the core issue in your logs where the same endpoints were being tested repeatedly, wasting resources and time.
