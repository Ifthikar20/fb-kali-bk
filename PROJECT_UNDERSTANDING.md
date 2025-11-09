# FetchBot.ai - Complete Project Understanding

## Executive Summary

FetchBot.ai is a sophisticated **AI-powered penetration testing platform** that leverages Claude AI for intelligent security assessment orchestration. The platform can operate in multiple modes, with the most advanced being the **Dynamic Multi-Agent System** where AI autonomously creates and coordinates specialized security testing agents based on real-time discoveries.

**Key Innovation:** Instead of running fixed, pre-programmed security scans, Claude analyzes the target and dynamically spawns specialized agents (API Security, SQL Injection, XSS Testing, etc.) only when relevant vulnerabilities are discovered during reconnaissance.

---

## Technology Stack

### Backend Core
- **FastAPI** - Modern async web framework for REST API
- **Python 3.11+** - Primary programming language
- **SQLAlchemy** - ORM for database operations
- **PostgreSQL** - Primary database for persistent storage
- **Redis** - Caching, job queues, and session management
- **Pydantic** - Data validation and settings management

### AI & Orchestration
- **Anthropic Claude API** - LLM for intelligent decision-making
- **Jinja2** - Templating for dynamic prompt generation
- **Custom Agent Framework** - Multi-agent coordination system

### Infrastructure & DevOps
- **Docker & Docker Compose** - Containerization
- **Kali Linux Containers** - Isolated security tool execution
- **AWS EC2** (Optional) - Dedicated instances per organization
- **AWS Elastic IPs** - Persistent attack source IPs
- **Uvicorn** - ASGI server

### Security Tools Integration
- **nmap** - Port scanning and service detection
- **SQLMap** - SQL injection automation
- **Nikto** - Web server scanning
- **Custom Python tools** - XSS, CSRF, API testing

---

## Project Structure Deep Dive

```
fb-kali-bk/
├── fetchbot-platform/              # Main application directory
│   │
│   ├── api.py                      # FastAPI REST API (600+ lines)
│   │   ├── Authentication endpoints (/login, /register)
│   │   ├── Organization management (/api/organizations)
│   │   ├── Scan endpoints (/scan, /api/pentest)
│   │   ├── Report generation (/scan/{id}/report)
│   │   └── Logs endpoint (/scan/{id}/logs)
│   │
│   ├── main.py                     # Application entry point
│   ├── config.py                   # Settings & environment config
│   ├── models.py                   # SQLAlchemy database models
│   │   ├── Organization
│   │   ├── User
│   │   ├── PentestJob
│   │   └── Finding
│   │
│   ├── core/                       # Dynamic Agent System (NEW ARCHITECTURE)
│   │   │
│   │   ├── orchestrator.py         # DynamicOrchestrator class
│   │   │                           # Replaces legacy bot orchestration
│   │   │
│   │   ├── agents/                 # Agent system components
│   │   │   ├── base_agent.py       # BaseAgent with agent_loop()
│   │   │   ├── root_agent.py       # Root coordinator (no expertise)
│   │   │   ├── agent_graph.py      # Global agent registry
│   │   │   └── state.py            # AgentState management
│   │   │
│   │   ├── llm/                    # Claude AI integration
│   │   │   ├── llm.py              # ClaudeClient wrapper
│   │   │   ├── config.py           # LLMConfig (prompt modules)
│   │   │   └── parsers.py          # Parse <function> invocations
│   │   │
│   │   ├── tools/                  # Tool registry & execution
│   │   │   ├── registry.py         # @register_tool decorator
│   │   │   ├── executor.py         # Route to local/sandbox
│   │   │   ├── coordination_tools.py    # create_agent, finish_scan
│   │   │   ├── network_tools.py    # nmap_scan, dns_enumerate
│   │   │   ├── web_tools.py        # http_scan, xss_test
│   │   │   ├── database_tools.py   # sql_injection_test
│   │   │   └── api_tools.py        # api_fuzzing, detect_env_vars
│   │   │
│   │   └── prompts/                # Jinja2 prompt templates
│   │       ├── base_system_prompt.jinja
│   │       └── vulnerabilities/    # Specialized expertise modules
│   │           ├── sql_injection.jinja      # SQL expert knowledge
│   │           ├── xss.jinja                # XSS expert knowledge
│   │           ├── api_testing.jinja        # API expert knowledge
│   │           └── authentication.jinja     # Auth expert knowledge
│   │
│   ├── bots/                       # LEGACY: Specialized bot microservices
│   │   ├── network-bot/            # Port scanning (FastAPI on 8002)
│   │   ├── ui-bot/                 # Web scanning (FastAPI on 8001)
│   │   └── db-bot/                 # Database testing (FastAPI on 8003)
│   │
│   ├── bot_orchestrator.py         # LEGACY: Fixed bot orchestration
│   ├── multi_kali_orchestrator.py  # Multi-container orchestration
│   ├── aws_manager.py              # AWS EC2 & Elastic IP management
│   ├── report_generator.py         # HTML/JSON/Markdown reports
│   │
│   ├── app/                        # Frontend application
│   │   ├── __init__.py
│   │   └── main.py
│   │
│   ├── requirements.txt            # Python dependencies
│   ├── docker-compose.yml          # Container orchestration
│   ├── Dockerfile                  # API container image
│   │
│   └── scripts/
│       ├── create-env.sh           # Environment setup
│       ├── verify-setup.sh         # System verification
│       ├── start-local-kali.sh     # Local Kali container
│       └── deploy-ec2-kali.sh      # AWS deployment
│
├── Documentation Files
│   ├── IMPLEMENTATION_SUMMARY.md        # Dynamic system overview
│   ├── DYNAMIC_ARCHITECTURE_PLAN.md     # Architecture blueprint
│   ├── DYNAMIC_AGENT_USAGE.md           # Usage guide
│   ├── BACKEND_IMPLEMENTATION_STATUS.md # Implementation status
│   ├── FRONTEND_INTEGRATION.md          # Frontend integration
│   ├── README.md                        # User guide
│   ├── QUICKSTART.md                    # Quick start guide
│   └── STATUS.md                        # Current status
│
└── setup-fetchbot.sh               # Complete platform setup script
```

---

## Complete Application Flow: Request to Response

### Phase 1: System Initialization

```bash
# Startup command
python fetchbot-platform/main.py
```

**What happens:**
1. `main.py` imports FastAPI app from `api.py`
2. Environment variable `USE_DYNAMIC_AGENTS` is checked
3. Appropriate orchestrator is imported:
   - `USE_DYNAMIC_AGENTS=true` → `core.orchestrator.DynamicOrchestrator`
   - `USE_DYNAMIC_AGENTS=false` → `bot_orchestrator.BotOrchestrator`
4. Database initialized via `init_db()` from `models.py`
5. CORS middleware configured for frontend (port 8080)
6. FastAPI server starts on port 8000

**Startup Logs:**
```
[INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)
FetchBot.ai API Starting
Dynamic Agents Enabled: True
Orchestrator: DynamicOrchestrator
```

### Phase 2: Organization Creation

**API Call:**
```bash
POST /api/organizations
Content-Type: application/json

{
  "name": "Acme Corporation",
  "admin_email": "admin@acme.com",
  "allowed_targets": ["acme.com", "*.acme.com"]
}
```

**Processing Flow:**

1. **Validation** (api.py:562-569)
   - Pydantic model validates request data
   - Check if organization slug already exists

2. **Database Record Creation** (api.py:571-579)
   ```python
   org = Organization(
       name="Acme Corporation",
       slug="acme-corporation",
       admin_email="admin@acme.com",
       api_key="fb_live_<48-char-token>"  # Auto-generated
   )
   db.add(org)
   db.commit()
   ```

3. **AWS Infrastructure Provisioning** (Optional - api.py:581-590)
   - Launch EC2 instance with Kali Linux
   - Allocate Elastic IP
   - Associate IP with instance
   - Wait for instance to be running
   - Update organization record:
     ```python
     org.ec2_instance_id = "i-0123456789abcdef"
     org.elastic_ip = "52.123.45.67"
     org.elastic_ip_allocation_id = "eipalloc-12345"
     org.ec2_running = True
     ```

4. **Response**
   ```json
   {
     "id": "550e8400-e29b-41d4-a716-446655440000",
     "name": "Acme Corporation",
     "api_key": "fb_live_kX9d...",
     "elastic_ip": "52.123.45.67",
     "ec2_instance_id": "i-0123456789abcdef"
   }
   ```

### Phase 3: User Authentication (Optional)

**API Call:**
```bash
POST /login
Content-Type: application/json

{
  "username": "admin",
  "password": "password123"
}
```

**Processing:**
1. Query User by username
2. Verify password hash (SHA256)
3. Generate JWT token with 7-day expiration
4. Return token for subsequent requests

### Phase 4: Scan Initiation (Dynamic Mode)

**API Call:**
```bash
POST /scan
Authorization: Bearer fb_live_kX9d...
Content-Type: application/json

{
  "target": "https://shop.acme.com"
}
```

**Processing Flow:**

**Step 1: API Endpoint Handler** (api.py:430-458)
```python
@app.post("/scan")
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
```

1. **Authentication:**
   - Extract Bearer token from Authorization header
   - Query Organization by api_key
   - Verify organization is active

2. **Job Creation:**
   ```python
   job = PentestJob(
       id=str(uuid.uuid4()),  # e.g., "job_abc123"
       organization_id=org.id,
       name=f"Scan of {target}",
       target="https://shop.acme.com",
       status=JobStatus.QUEUED,
       attack_ip=org.elastic_ip or "local",
       created_at=datetime.utcnow()
   )
   db.add(job)
   db.commit()
   ```

3. **Background Task Scheduling:**
   ```python
   background_tasks.add_task(
       run_dynamic_scan,
       job_id=job.id,
       target=scan_data.target,
       organization_id=org.id,
       db_url=settings.database_url
   )
   ```

4. **Immediate Response:**
   ```json
   {
     "id": "job_abc123",
     "name": "Scan of https://shop.acme.com",
     "target": "https://shop.acme.com",
     "status": "queued",
     "created_at": "2025-11-09T12:34:56.789Z"
   }
   ```

**Step 2: Background Task Execution** (api.py:365-427)

```python
async def run_dynamic_scan(
    job_id: str,
    target: str,
    organization_id: int,
    db_url: str
):
```

1. **New Database Session:**
   ```python
   engine = create_engine(db_url)
   SessionLocal = sessionmaker(bind=engine)
   db = SessionLocal()
   ```

2. **Update Job Status:**
   ```python
   job = db.query(PentestJob).filter(PentestJob.id == job_id).first()
   job.status = JobStatus.RUNNING
   job.started_at = datetime.utcnow()
   db.commit()
   ```

3. **Initialize Orchestrator:**
   ```python
   orchestrator = DynamicOrchestrator(org_elastic_ip=org.elastic_ip)
   ```

4. **Run Scan:**
   ```python
   result = await orchestrator.run_scan(
       target=target,
       job_id=job_id,
       organization_id=organization_id
   )
   ```

**Step 3: Dynamic Orchestrator** (core/orchestrator.py:39-98)

```python
async def run_scan(self, target: str, job_id: str, organization_id: int):
    start_time = datetime.utcnow()

    # Create root coordinator agent
    root_agent = RootAgent(target=target, job_id=job_id)

    # Run assessment
    result = await root_agent.run_assessment()

    # Calculate execution time
    execution_time = (datetime.utcnow() - start_time).total_seconds()

    return {
        "status": "completed",
        "target": target,
        "job_id": job_id,
        "findings": result["findings"],
        "agents_created": result["agents_created"],
        "total_findings": result["total_findings"],
        "critical_findings": result["critical_findings"],
        "execution_time_seconds": execution_time
    }
```

**Step 4: Root Agent Assessment** (core/agents/root_agent.py)

The Root Agent is a **pure coordinator** with NO specialized security knowledge:

```python
class RootAgent(BaseAgent):
    def __init__(self, target: str, job_id: str):
        # NO prompt modules - pure coordinator
        llm_config = LLMConfig(prompt_modules=[])

        super().__init__(
            agent_id=job_id,
            role="root",
            llm_config=llm_config,
            max_iterations=100  # Root gets more iterations
        )
```

**Root Agent Strategy:**

```
MISSION: Coordinate comprehensive security assessment

PHASE 1: RECONNAISSANCE
├─ Action: create_agent(name="Recon Agent", task="Scan target", modules=[])
├─ Tools given to Recon: http_scan, dns_enumerate, resolve_domain
└─ Wait: Monitor with get_my_agents(), read messages

PHASE 2: ANALYZE RECONNAISSANCE RESULTS
├─ Recon discovers:
│  ├─ API endpoints: /api/v1/users, /api/v1/products, /api/config
│  ├─ Forms: Login at /login, Search at /search
│  ├─ Technologies: MySQL database, PHP 7.4, Apache 2.4
│  └─ Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL)
│
└─ Root receives message: "Reconnaissance complete. Found APIs, forms, MySQL"

PHASE 3: DYNAMIC AGENT CREATION (AI Decision!)
├─ Decision: "APIs found → need API security testing"
│  └─ create_agent(
│       name="API Security Agent",
│       task="Test APIs for vulnerabilities",
│       prompt_modules=["api_testing"]  # Loads API expertise
│     )
│
├─ Decision: "MySQL detected → need SQL injection testing"
│  └─ create_agent(
│       name="SQL Injection Agent",
│       task="Test for SQL injection",
│       prompt_modules=["sql_injection"]  # Loads SQL expertise
│     )
│
├─ Decision: "Forms with inputs → need XSS testing"
│  └─ create_agent(
│       name="XSS Testing Agent",
│       task="Test forms for XSS",
│       prompt_modules=["xss"]  # Loads XSS expertise
│     )
│
└─ Decision: "Login form → need auth testing"
   └─ create_agent(
        name="Authentication Testing Agent",
        task="Test authentication security",
        prompt_modules=["authentication"]  # Loads auth expertise
      )

PHASE 4: MONITOR PARALLEL EXECUTION
├─ All agents run simultaneously
├─ Root checks: get_my_agents() every iteration
├─ Root reads messages from agents
└─ Track: Running=3, Completed=1, Failed=0

PHASE 5: AGGREGATE FINDINGS
├─ Wait for all agents to finish
├─ Collect findings from all agents
├─ Review severity and coverage
└─ Call: finish_scan(summary="Found 12 vulnerabilities...")

PHASE 6: COMPLETE
└─ Return all findings to orchestrator
```

**Step 5: Specialized Agent Execution** (core/agents/base_agent.py)

Each specialized agent (API, SQL, XSS, Auth) runs the same base loop:

```python
async def agent_loop(self, task: str):
    # Initial system prompt with loaded expertise modules
    system_prompt = self._build_system_prompt()

    # Add initial task
    self.state.add_message("user", task)

    while self.state.iteration < self.max_iterations:
        # 1. Check for messages from other agents
        self._check_agent_messages()

        # 2. Increment iteration counter
        self.state.increment_iteration()

        # 3. Generate LLM response with tool schemas
        response = await self.llm.generate(
            conversation_history=self.state.get_conversation_history(),
            scan_id=str(self.agent_id),
            step_number=self.state.iteration
        )

        # 4. Add assistant response to conversation
        self.state.add_message("assistant", response.content)

        # 5. Execute tool invocations
        should_finish = await process_tool_invocations(
            response.tool_invocations,
            self.state.conversation_history,
            self.state
        )

        if should_finish:
            break

    # Mark agent as completed
    self.state.status = "completed"
```

**Example: API Security Agent in Action**

Agent receives this system prompt (loaded from `api_testing.jinja`):

```
You are an API Security Testing Expert specializing in:

CAPABILITIES:
- API fuzzing with injection payloads (SQL, XSS, command injection)
- IDOR (Insecure Direct Object Reference) testing
- Authentication bypass techniques
- Mass assignment vulnerability detection
- Rate limiting analysis
- API method fuzzing (GET, POST, PUT, DELETE, PATCH)
- GraphQL security testing
- Exposed environment variable detection

TOOLS AVAILABLE:
- api_fuzzing: Comprehensive API endpoint fuzzing
- api_brute_force: Authentication brute forcing
- api_idor_test: Test for IDOR vulnerabilities
- detect_exposed_env_vars: Find exposed .env, config endpoints
- api_rate_limit_test: Check rate limiting
- create_vulnerability_report: Report findings
- agent_finish: Complete task

YOUR TASK:
Test APIs at /api/v1/users, /api/v1/products, /api/config for vulnerabilities
```

Agent's execution:

```python
# Iteration 1: Start with fuzzing
<thinking>
I'll start by fuzzing the /api/v1/users endpoint with various payloads
to test for SQL injection, XSS, and command injection.
</thinking>

<function=api_fuzzing>
<parameter=api_url>https://shop.acme.com/api/v1/users</parameter>
<parameter=fuzz_type>comprehensive</parameter>
</function>

# Result: Found SQL injection vulnerability

# Iteration 2: Test IDOR
<function=api_idor_test>
<parameter=api_url>https://shop.acme.com/api/v1/users/1</parameter>
<parameter=test_range_start>1</parameter>
<parameter=test_range_end>100</parameter>
</function>

# Result: Can access other users' data

# Iteration 3: Check for exposed secrets
<function=detect_exposed_env_vars>
<parameter=api_url>https://shop.acme.com</parameter>
<parameter=endpoints>["/api/config", "/.env", "/api/debug"]</parameter>
</function>

# Result: /api/config exposes DATABASE_URL!

# Iteration 4: Report critical finding
<function=create_vulnerability_report>
<parameter=title>Critical: Database Credentials Exposed via API</parameter>
<parameter=severity>CRITICAL</parameter>
<parameter=vulnerability_type>INFORMATION_DISCLOSURE</parameter>
<parameter=description>
The /api/config endpoint returns sensitive environment variables including
the complete database connection string with username and password.
</parameter>
<parameter=affected_url>https://shop.acme.com/api/config</parameter>
<parameter=evidence>
{
  "DATABASE_URL": "postgresql://admin:SuperSecret123@db.acme.com:5432/prod",
  "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
</parameter>
<parameter=remediation>
Remove the /api/config endpoint from production or implement proper
authentication and never expose secrets via API responses.
</parameter>
</function>

# Iteration 5: Complete task
<function=agent_finish>
<parameter=summary>
Completed API security testing. Found 3 vulnerabilities:
- CRITICAL: Database credentials exposed
- HIGH: SQL injection in /api/v1/users
- MEDIUM: IDOR vulnerability allowing access to other users
</parameter>
</function>
```

**Step 6: Tool Execution** (core/tools/executor.py)

When agent calls a tool like `api_fuzzing`:

```python
async def execute_tool(
    tool_name: str,
    agent_state: AgentState,
    **parameters
):
    tool_info = get_tool(tool_name)

    if tool_info["sandbox_execution"]:
        # Execute in Kali Docker container
        result = await _execute_in_sandbox(tool_name, agent_state, **parameters)
    else:
        # Execute locally (coordination tools)
        result = await _execute_locally(tool_name, agent_state, **parameters)

    return result
```

**Sandbox Execution:**
```python
async def _execute_in_sandbox(tool_name, agent_state, **parameters):
    # Get Kali container URL (e.g., http://kali-agent-1:9000)
    sandbox_url = agent_state.sandbox_url

    # HTTP POST to Kali container's tool execution endpoint
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{sandbox_url}/execute_tool",
            json={
                "tool_name": tool_name,
                "parameters": parameters,
                "auth_token": agent_state.auth_token
            },
            timeout=300  # 5 minute timeout for long scans
        )

    return response.json()
```

**Inside Kali Container:**
```python
# Kali agent receives /execute_tool request
# Executes actual security tool

if tool_name == "api_fuzzing":
    # Run custom Python fuzzer
    results = run_api_fuzzer(
        url=parameters["api_url"],
        payloads=INJECTION_PAYLOADS
    )

elif tool_name == "sql_injection_test":
    # Run SQLMap
    subprocess.run([
        "sqlmap",
        "-u", parameters["url"],
        "--batch",
        "--level=3",
        "--risk=2"
    ])

elif tool_name == "nmap_scan":
    # Run nmap
    subprocess.run([
        "nmap",
        "-p", parameters["ports"],
        parameters["target"]
    ])
```

**Step 7: Finding Storage** (Automatic)

When agent calls `create_vulnerability_report`:

```python
@register_tool(sandbox_execution=False)
async def create_vulnerability_report(
    title: str,
    severity: str,
    vulnerability_type: str,
    description: str,
    affected_url: str,
    agent_state: AgentState,
    evidence: str = "",
    remediation: str = "",
    payload: str = ""
):
    finding = {
        "title": title,
        "severity": severity,
        "vulnerability_type": vulnerability_type,
        "description": description,
        "affected_url": affected_url,
        "evidence": evidence,
        "remediation": remediation,
        "payload": payload,
        "discovered_by": agent_state.agent_id,
        "discovered_at": datetime.utcnow().isoformat()
    }

    # Add to agent's findings list
    agent_state.findings.append(finding)

    return {
        "status": "success",
        "finding_id": str(uuid.uuid4()),
        "message": f"Vulnerability report created: {title}"
    }
```

**Step 8: Results Aggregation** (core/agents/root_agent.py)

Root agent collects findings from all child agents:

```python
async def _aggregate_findings(self):
    # Get all child agents
    graph = get_agent_graph()
    children = graph.get_children(self.agent_id)

    all_findings = []

    # Collect findings from each agent
    for child_id in children:
        agent = graph.get_agent(child_id)
        if agent:
            all_findings.extend(agent.state.findings)

    # Add root's own findings
    all_findings.extend(self.state.findings)

    return all_findings
```

**Step 9: Database Persistence** (api.py:390-410)

Back in the background task, findings are saved:

```python
# Get result from orchestrator
result = await orchestrator.run_scan(...)

# Save findings to database
for finding_data in result["findings"]:
    finding = Finding(
        id=str(uuid.uuid4()),
        pentest_job_id=job_id,
        title=finding_data["title"],
        description=finding_data["description"],
        severity=finding_data["severity"],
        vulnerability_type=finding_data["vulnerability_type"],
        url=finding_data["affected_url"],
        payload=finding_data.get("payload", ""),
        poc_code=finding_data.get("evidence", ""),
        discovered_by=finding_data.get("discovered_by", "unknown"),
        discovered_at=datetime.utcnow()
    )
    db.add(finding)

# Update job status
job.status = JobStatus.COMPLETED
job.completed_at = datetime.utcnow()
job.total_findings = len(result["findings"])

# Count by severity
from collections import Counter
severity_counts = Counter(f["severity"] for f in result["findings"])
job.critical_count = severity_counts.get("CRITICAL", 0)
job.high_count = severity_counts.get("HIGH", 0)
job.medium_count = severity_counts.get("MEDIUM", 0)
job.low_count = severity_counts.get("LOW", 0)

db.commit()
```

### Phase 5: Results Retrieval

**Get Scan Status:**
```bash
GET /scan/job_abc123
Authorization: Bearer fb_live_kX9d...
```

**Response:**
```json
{
  "id": "job_abc123",
  "name": "Scan of https://shop.acme.com",
  "target": "https://shop.acme.com",
  "status": "completed",
  "attack_ip": "52.123.45.67",
  "total_findings": 12,
  "critical_count": 2,
  "high_count": 5,
  "medium_count": 4,
  "low_count": 1,
  "created_at": "2025-11-09T12:34:56Z",
  "started_at": "2025-11-09T12:35:01Z",
  "completed_at": "2025-11-09T12:42:33Z",
  "execution_time_seconds": 452
}
```

**Get Detailed Findings:**
```bash
GET /scan/job_abc123/findings
Authorization: Bearer fb_live_kX9d...
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "total": 12,
  "findings": [
    {
      "id": "finding_1",
      "title": "Critical: Database Credentials Exposed via API",
      "severity": "CRITICAL",
      "vulnerability_type": "INFORMATION_DISCLOSURE",
      "url": "https://shop.acme.com/api/config",
      "description": "The /api/config endpoint returns sensitive environment variables...",
      "payload": "GET /api/config",
      "discovered_by": "API Security Agent",
      "discovered_at": "2025-11-09T12:38:15Z"
    },
    {
      "id": "finding_2",
      "title": "SQL Injection in User Search",
      "severity": "HIGH",
      "vulnerability_type": "SQL_INJECTION",
      "url": "https://shop.acme.com/api/v1/users?search=test",
      "payload": "search=' OR '1'='1",
      "discovered_by": "SQL Injection Agent",
      "discovered_at": "2025-11-09T12:39:22Z"
    }
  ]
}
```

**Get Execution Logs:**
```bash
GET /scan/job_abc123/logs
Authorization: Bearer fb_live_kX9d...
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "logs": [
    {
      "timestamp": "2025-11-09T12:35:01Z",
      "agent": "Root Coordinator",
      "action": "Created Recon Agent",
      "details": "Starting reconnaissance phase"
    },
    {
      "timestamp": "2025-11-09T12:36:45Z",
      "agent": "Recon Agent",
      "action": "Completed HTTP scan",
      "details": "Found 23 endpoints, 3 forms, MySQL database"
    },
    {
      "timestamp": "2025-11-09T12:37:12Z",
      "agent": "Root Coordinator",
      "action": "Created API Security Agent",
      "details": "Testing API endpoints"
    }
  ]
}
```

**Generate Report:**
```bash
GET /scan/job_abc123/report/html
Authorization: Bearer fb_live_kX9d...
```

Returns professional HTML report with:
- Executive summary
- Findings by severity
- Technical details
- Remediation recommendations
- Color-coded risk matrix

---

## Key Architectural Patterns

### 1. Dynamic Agent Creation

**Problem:** Fixed bots can't adapt to unique target characteristics

**Solution:** Root agent dynamically creates specialized agents based on discoveries

**Example:**
```
Target: E-commerce site

Recon discovers:
✓ REST API with JWT authentication
✓ GraphQL endpoint
✓ MongoDB database
✓ React SPA with CSP headers

Root creates:
→ "API Security Agent" (modules: api_testing)
→ "GraphQL Testing Agent" (modules: api_testing)
→ "NoSQL Injection Agent" (modules: sql_injection)
→ "SPA Security Agent" (modules: xss)

Result: Targeted, efficient testing with specialized expertise
```

### 2. Prompt Module System

**Problem:** Single monolithic prompt becomes unwieldy

**Solution:** Modular expertise via Jinja2 templates

**Architecture:**
```
Base System Prompt
    ├─ Agent role & capabilities
    ├─ Tool descriptions
    └─ General instructions

         +

Loaded Modules (if specified)
    ├─ sql_injection.jinja → SQL injection expertise
    ├─ api_testing.jinja → API security expertise
    └─ xss.jinja → XSS testing expertise

         =

Agent-Specific Prompt (sent to Claude)
```

**Benefits:**
- **Composable:** Mix and match expertise modules
- **Maintainable:** Update one module without affecting others
- **Scalable:** Add new modules without code changes
- **Specialized:** Each agent has deep expertise in its domain

### 3. Tool Registry Pattern

**Problem:** Hard to manage and document available tools

**Solution:** Decorator-based registration with automatic schema generation

```python
@register_tool(
    sandbox_execution=True,
    description="Test for SQL injection vulnerabilities"
)
async def sql_injection_test(
    url: str,
    parameter: str,
    technique: str = "boolean_based"
) -> Dict[str, Any]:
    """
    Test specific parameter for SQL injection

    Args:
        url: Target URL
        parameter: Parameter to test
        technique: Injection technique (boolean_based, time_based, error_based)

    Returns:
        Dict with vulnerability status and evidence
    """
    # Implementation
```

**Auto-generated schema for LLM:**
```json
{
  "name": "sql_injection_test",
  "description": "Test for SQL injection vulnerabilities",
  "parameters": {
    "type": "object",
    "properties": {
      "url": {
        "type": "string",
        "description": "Target URL"
      },
      "parameter": {
        "type": "string",
        "description": "Parameter to test"
      },
      "technique": {
        "type": "string",
        "description": "Injection technique",
        "enum": ["boolean_based", "time_based", "error_based"],
        "default": "boolean_based"
      }
    },
    "required": ["url", "parameter"]
  }
}
```

### 4. Agent Graph & Coordination

**Problem:** Track relationships between agents and route messages

**Solution:** Singleton AgentGraph maintains global registry

```python
class AgentGraph:
    """Global agent registry (singleton)"""

    nodes: Dict[str, Dict]  # agent_id → agent info
    edges: List[Dict]        # parent-child relationships
    messages: List[Dict]     # inter-agent messages
    agents: Dict[str, Any]   # agent_id → agent instance

    def add_agent(self, agent_id, parent_id, info):
        """Register new agent"""
        self.nodes[agent_id] = info
        if parent_id:
            self.edges.append({
                "source": parent_id,
                "target": agent_id
            })

    def send_message(self, sender_id, recipient_id, message):
        """Route message between agents"""
        self.messages.append({
            "from": sender_id,
            "to": recipient_id,
            "content": message,
            "timestamp": datetime.utcnow()
        })

    def get_children(self, agent_id):
        """Get all child agents"""
        return [
            edge["target"]
            for edge in self.edges
            if edge["source"] == agent_id
        ]
```

**Visualization:**
```
Root Agent (job_abc123)
├─ Recon Agent (agent_001)
│  └─ Status: completed
│  └─ Findings: 0
│  └─ Messages sent: 1
│
├─ API Security Agent (agent_002)
│  └─ Status: completed
│  └─ Findings: 3
│  └─ Tools used: api_fuzzing, detect_exposed_env_vars, api_idor_test
│
├─ SQL Injection Agent (agent_003)
│  └─ Status: completed
│  └─ Findings: 2
│  └─ Tools used: sql_injection_test, sqlmap_test
│
└─ XSS Testing Agent (agent_004)
   └─ Status: completed
   └─ Findings: 1
   └─ Tools used: xss_test
```

### 5. Dual Execution Model

**Problem:** Some operations need isolation, others need access to system state

**Solution:** Two execution modes

**Sandbox Execution (sandbox_execution=True):**
- Scanning tools (nmap, sqlmap, etc.)
- Execute in Kali Docker container
- Isolated from main process
- Resource controlled
- Can't access agent state directly

**Local Execution (sandbox_execution=False):**
- Coordination tools
- Execute in main Python process
- Direct access to agent state
- Can modify agent graph
- Examples: create_agent, finish_scan, send_message

### 6. Conversation-Based Agent State

**Problem:** Agents need memory across iterations

**Solution:** Maintain full conversation history

```python
class AgentState:
    conversation_history: List[Dict] = [
        {
            "role": "system",
            "content": "You are an API Security Testing Expert..."
        },
        {
            "role": "user",
            "content": "Test APIs at /api/v1/users for vulnerabilities"
        },
        {
            "role": "assistant",
            "content": "I'll start by fuzzing the endpoint...\n<function=api_fuzzing>..."
        },
        {
            "role": "tool_result",
            "content": "Found SQL injection vulnerability: ' OR 1=1--"
        },
        {
            "role": "assistant",
            "content": "Confirmed SQLi. Now testing IDOR...\n<function=api_idor_test>..."
        }
    ]
```

**Benefits:**
- Agent remembers previous actions
- Can reference earlier findings
- LLM has full context
- Enables iterative refinement

---

## Database Schema Detailed

### Organization Table
```sql
CREATE TABLE organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    admin_email VARCHAR(255) NOT NULL,
    api_key VARCHAR(128) NOT NULL UNIQUE,

    -- AWS Resources (Optional)
    ec2_instance_id VARCHAR(100) UNIQUE,
    elastic_ip VARCHAR(45) UNIQUE,
    elastic_ip_allocation_id VARCHAR(100),

    -- Status
    active BOOLEAN DEFAULT TRUE,
    ec2_running BOOLEAN DEFAULT FALSE,

    -- Limits
    max_concurrent_scans INTEGER DEFAULT 3,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### User Table
```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) REFERENCES organizations(id),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    full_name VARCHAR(255),

    -- Permissions
    is_admin BOOLEAN DEFAULT FALSE,
    active BOOLEAN DEFAULT TRUE,

    -- Audit
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### PentestJob Table
```sql
CREATE TABLE pentest_jobs (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) REFERENCES organizations(id),

    name VARCHAR(255) NOT NULL,
    target VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'queued',

    attack_ip VARCHAR(45),

    -- Finding Counts
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,

    -- Reports
    report_url VARCHAR(500),

    -- NEW: Execution logs (JSON)
    execution_logs JSON
);
```

### Finding Table
```sql
CREATE TABLE findings (
    id VARCHAR(36) PRIMARY KEY,
    pentest_job_id VARCHAR(36) REFERENCES pentest_jobs(id),

    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    vulnerability_type VARCHAR(100),

    url VARCHAR(1000),
    payload TEXT,
    poc_code TEXT,
    screenshot_url VARCHAR(500),

    discovered_by VARCHAR(50),
    discovered_at TIMESTAMP DEFAULT NOW()
);
```

### Key Relationships

**One Organization → Many Users**
- Each user belongs to one organization
- Users share organization's API quota and resources

**One Organization → Many PentestJobs**
- Organization can run multiple scans
- Concurrent scans limited by `max_concurrent_scans`

**One PentestJob → Many Findings**
- Each finding linked to specific job
- Findings aggregated for severity counts

---

## Configuration & Environment

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Redis
REDIS_URL=redis://redis:6379/0

# AI - REQUIRED
ANTHROPIC_API_KEY=sk-ant-api03-...

# AWS - Optional (for EC2 deployment)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_VPC_ID=vpc-12345678
AWS_SUBNET_ID=subnet-12345678
AWS_SECURITY_GROUP_ID=sg-12345678
AWS_KEY_PAIR_NAME=fetchbot-key
AWS_S3_BUCKET=fetchbot-evidence

# Security
JWT_SECRET=change-this-to-random-64-character-string-in-production
SECRET_KEY=another-random-secret-for-sessions

# Orchestration Mode
USE_DYNAMIC_AGENTS=true   # Enable dynamic multi-agent system
NUM_KALI_AGENTS=3         # Number of Kali containers (if using multi-kali)

# Kali Agent
KALI_AGENT_URL=http://kali-agent-1:9000
KALI_AGENT_TOKEN=secure-token-here
```

### Docker Compose Services

```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: fetchbot
      POSTGRES_USER: fetchbot
      POSTGRES_PASSWORD: fetchbot123
    ports:
      - "5432:5432"
    volumes:
      - ./data/postgres:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - USE_DYNAMIC_AGENTS=true
      - DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot
      - REDIS_URL=redis://redis:6379/0
    env_file:
      - .env
    depends_on:
      - postgres
      - redis
    command: python main.py

  # Legacy specialized bots (if USE_DYNAMIC_AGENTS=false)
  network-bot:
    build: ./bots/network-bot
    ports:
      - "8002:8002"

  ui-bot:
    build: ./bots/ui-bot
    ports:
      - "8001:8001"

  db-bot:
    build: ./bots/db-bot
    ports:
      - "8003:8003"

  # Kali agent for tool execution
  kali-agent-1:
    image: kalilinux/kali-rolling
    ports:
      - "9000:9000"
    volumes:
      - ./kali-agent:/opt/agent
    command: python /opt/agent/server.py
```

---

## Operational Modes

### Mode 1: Local Development (Docker Compose)

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api
```

**Architecture:**
- API on localhost:8000
- PostgreSQL on localhost:5432
- Redis on localhost:6379
- Bots on localhost:8001-8003 (if legacy mode)
- No AWS infrastructure

### Mode 2: Multi-Kali (High Performance)

```bash
# Set number of Kali containers
export NUM_KALI_AGENTS=5

# Start with multi-kali orchestration
docker-compose -f docker-compose-multi-kali.yml up -d
```

**Features:**
- Load balancing across multiple Kali containers
- Parallel tool execution
- Better resource isolation
- Suitable for multiple concurrent scans

### Mode 3: AWS EC2 Deployment (Production)

```bash
# Deploy to AWS
bash deploy-ec2-kali.sh

# Each organization gets:
# - Dedicated EC2 instance
# - Elastic IP
# - Isolated environment
```

**Benefits:**
- True multi-tenancy
- Dedicated resources per customer
- Persistent attack IP per organization
- Scales horizontally

---

## Testing & Verification

### Verify Setup

```bash
cd fetchbot-platform
bash verify-setup.sh
```

**Checks:**
- ✅ Core infrastructure files
- ✅ Agent system components
- ✅ Tool registry
- ✅ Prompt modules
- ✅ Python dependencies
- ❌ Environment configuration

### Run Individual Bot

```bash
# Test network bot
curl -X POST http://localhost:8002/scan \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com", "scan_type": "quick"}'
```

### Test Dynamic Agents

```bash
# Start scan
SCAN_ID=$(curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com"}' | jq -r '.id')

# Monitor status
watch -n 2 "curl -s http://localhost:8000/scan/$SCAN_ID \
  -H 'Authorization: Bearer $API_KEY' | jq '.status, .total_findings'"

# Get results
curl http://localhost:8000/scan/$SCAN_ID/findings \
  -H "Authorization: Bearer $API_KEY" | jq
```

---

## Security Considerations

### Authentication & Authorization

1. **API Key Authentication:**
   - Format: `fb_live_<48-char-random-token>`
   - Stored securely in database
   - One key per organization
   - Keys can be rotated

2. **JWT Token Authentication:**
   - For user login
   - 7-day expiration
   - Includes user_id and organization_id
   - Signed with SECRET_KEY

3. **Multi-Tenancy Enforcement:**
   - All queries filtered by organization_id
   - Users can only access their organization's data
   - API keys scoped to single organization

### Tool Execution Safety

1. **Sandbox Isolation:**
   - Scanning tools run in Docker containers
   - No direct filesystem access
   - Network isolated (can only reach target)
   - Resource limits enforced

2. **Input Validation:**
   - All parameters validated via Pydantic
   - URL validation for targets
   - Payload sanitization
   - Command injection prevention

3. **Rate Limiting:**
   - Max concurrent scans per organization
   - Tool execution timeouts
   - LLM API rate limits

### Legal & Ethical

**User Agreement:**
- Users must have authorization to scan targets
- Platform logs all scanning activity
- Audit trail maintained
- Terms of service enforcement

**Responsible Disclosure:**
- Findings are private to organization
- Encourages responsible disclosure practices
- Provides remediation guidance

---

## Performance Characteristics

### Scan Duration

**Quick Scan (~5-10 minutes):**
- Top 1000 ports
- Basic web crawling
- Standard injection tests
- Suitable for rapid assessment

**Full Scan (~30-60 minutes):**
- All 65535 ports
- Deep web crawling
- Comprehensive SQL injection (SQLMap)
- API fuzzing with extensive payloads
- Suitable for thorough pentesting

### Resource Usage

**Per Scan:**
- Memory: ~500MB (API) + ~1GB per Kali container
- CPU: 2-4 cores (parallel agent execution)
- Storage: ~100MB per scan (findings + logs)
- LLM API Calls: 50-200 calls per scan

**Concurrency:**
- Default: 3 concurrent scans per organization
- With multi-kali: 10+ concurrent scans
- With AWS EC2: Unlimited (isolated instances)

### Cost Optimization

**LLM Costs:**
- Average scan: $2-5 in Claude API costs
- Prompt caching can reduce by 50%
- Longer scans = more agent iterations = higher cost

**Infrastructure:**
- Local Docker: Free
- AWS EC2: ~$0.10/hour per t3.medium instance
- Storage: ~$0.023/GB/month for findings

---

## Troubleshooting

### Common Issues

**1. "ANTHROPIC_API_KEY not found"**
```bash
# Solution: Set in .env file
echo "ANTHROPIC_API_KEY=your-key-here" >> .env
```

**2. "Database connection failed"**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Restart database
docker-compose restart postgres
```

**3. "Agent not finishing"**
```bash
# Check agent logs in execution_logs
curl http://localhost:8000/scan/{job_id}/logs \
  -H "Authorization: Bearer $API_KEY"

# Look for:
# - Tool execution failures
# - Max iterations reached
# - LLM API errors
```

**4. "Kali container unreachable"**
```bash
# Check container status
docker ps | grep kali

# Check network
docker network inspect fetchbot-network

# Restart Kali agent
docker-compose restart kali-agent-1
```

---

## Future Enhancements

### Planned Features

1. **Real-time Progress Updates:**
   - WebSocket for live scan updates
   - Progress bar in frontend
   - Stream agent logs

2. **Prompt Caching:**
   - Cache base system prompts
   - Reduce LLM costs by 50%
   - Faster agent initialization

3. **More Expertise Modules:**
   - `wordpress_security.jinja`
   - `cloud_misconfig.jinja`
   - `mobile_api.jinja`
   - `blockchain.jinja`

4. **Agent Learning:**
   - Store successful attack patterns
   - Learn from past scans
   - Improve over time

5. **Frontend Dashboard:**
   - React-based UI
   - Real-time agent visualization
   - Interactive report viewer

6. **Integration APIs:**
   - Webhook notifications
   - Slack/Discord alerts
   - Jira ticket creation
   - GitHub issue creation

---

## Summary

FetchBot.ai represents a paradigm shift in automated security testing:

**Traditional Scanners:**
```
Fixed scripts → Predefined tests → Static results
```

**FetchBot.ai:**
```
AI Reconnaissance → Dynamic Agent Creation → Adaptive Testing → Comprehensive Results
```

**Key Differentiators:**

1. **Intelligent Orchestration:** Claude decides what to test based on discoveries
2. **Specialized Expertise:** Each agent has deep knowledge via prompt modules
3. **True Parallelism:** Multiple agents work simultaneously
4. **Adaptive Strategy:** System adapts to unique target characteristics
5. **Extensible Architecture:** Add new capabilities via prompt modules, not code changes

The platform successfully combines the flexibility of AI-driven decision-making with the power of battle-tested security tools, creating a system that is both intelligent and effective.

---

**Current Status:** Production-ready with dynamic multi-agent system fully operational

**Last Updated:** November 9, 2025

**Version:** 1.0 (Dynamic Agent Architecture)
