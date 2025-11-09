# Dynamic Multi-Agent System - Usage Guide

## Overview

The dynamic multi-agent system transforms FetchBot from fixed bot orchestration to intelligent, adaptive security testing where Claude AI decides what agents to create based on what it discovers.

## Activation

### Environment Variable

```bash
export USE_DYNAMIC_AGENTS=true
export ANTHROPIC_API_KEY=your_api_key_here
```

### Docker Compose

```yaml
api:
  environment:
    - USE_DYNAMIC_AGENTS=true
    - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
```

## How It Works

### 1. Traditional Bot System (OLD)

```
User → API → Claude Decision → "Run network-bot, ui-bot, db-bot"
              ↓
    Fixed bots execute in parallel
              ↓
         Results returned
```

**Limitations:**
- Always runs same 3 bots
- No adaptation to target type
- Generic testing approach
- Wastes resources on irrelevant tests

### 2. Dynamic Agent System (NEW)

```
User → API → Root Coordinator Agent
                    ↓
              Claude analyzes target
                    ↓
         "Create Recon Agent" (no modules)
                    ↓
         Recon discovers: APIs, forms, database
                    ↓
    Root creates specialized agents:
    ├─ API Fuzzing Agent (api_testing module)
    ├─ SQL Injection Agent (sql_injection module)
    ├─ XSS Agent (xss module)
                    ↓
         Each agent runs independently
                    ↓
    API agent finds .env exposure → Reports critical finding
    SQL agent validates injection → Creates proof-of-concept
    XSS agent finds no vulnerabilities → Finishes quickly
                    ↓
         Root aggregates all findings
```

**Advantages:**
- Adaptive: Different agents for different targets
- Specialized: Deep expertise via prompt modules
- Efficient: Only tests relevant attack vectors
- Intelligent: Claude makes continuous decisions

## Example Scenarios

### Scenario 1: E-commerce Website

**Target:** `https://shop.example.com`

**Agent Creation Flow:**

1. **Root Coordinator** starts scan
2. **Recon Agent** discovers:
   - Login form at `/login`
   - Product search API at `/api/products/search`
   - Shopping cart at `/cart`
   - MySQL database detected
3. **Root creates:**
   - **API Security Agent** (modules: `api_testing`)
     - Task: Test `/api/products/search` for fuzzing, IDOR, rate limiting
   - **SQL Injection Agent** (modules: `sql_injection`)
     - Task: Test search parameter for SQL injection
   - **XSS Agent** (modules: `xss`)
     - Task: Test product review form for XSS
   - **Auth Testing Agent** (modules: `authentication`)
     - Task: Test login brute force resistance, session management

4. **API Agent discovers:**
   - `/api/config` endpoint exposed
   - Contains: `DATABASE_URL`, `STRIPE_SECRET_KEY`
   - Creates CRITICAL vulnerability report

5. **SQL Agent finds:**
   - Search parameter vulnerable to Boolean-based SQLi
   - Extracts database version
   - Creates HIGH vulnerability report

6. **XSS Agent:**
   - Tests 15 XSS payloads
   - All blocked by CSP
   - Finishes with no findings

7. **Auth Agent:**
   - No rate limiting on login
   - Creates MEDIUM vulnerability report

**Final Result:**
- 1 CRITICAL (env vars exposed)
- 1 HIGH (SQL injection)
- 1 MEDIUM (no rate limiting)
- 4 agents created dynamically
- Scan completed in ~8 minutes

### Scenario 2: REST API Only

**Target:** `https://api.service.com`

**Agent Creation Flow:**

1. **Root Coordinator** starts scan
2. **Recon Agent** discovers:
   - Pure REST API (no HTML forms)
   - OpenAPI docs at `/api-docs`
   - Authentication via JWT
3. **Root creates:**
   - **API Fuzzing Agent** (modules: `api_testing`)
     - Task: Comprehensive API testing
4. **API Agent performs:**
   - Endpoint enumeration from OpenAPI
   - JWT analysis (weak secret detected)
   - Method fuzzing (DELETE allowed without auth!)
   - Mass assignment testing
   - Environment variable scanning

**Final Result:**
- 2 CRITICAL (weak JWT secret, unprotected DELETE)
- Only 1 specialized agent needed
- No wasted effort on XSS/SQLi testing

### Scenario 3: GraphQL API

**Target:** `https://app.example.com/graphql`

**Agent Creation Flow:**

1. **Recon Agent** identifies GraphQL endpoint
2. **Root creates:**
   - **GraphQL Security Agent** (modules: `api_testing`)
3. **Agent discovers:**
   - Introspection enabled
   - Extracts full schema
   - Finds admin-only mutations exposed
   - Tests query depth limits (none!)
   - Batch query DoS possible

**Final Result:**
- Highly targeted testing
- GraphQL-specific vulnerabilities found
- Traditional web tests skipped

## API Endpoints

### Start Dynamic Scan

```bash
POST /scan
Content-Type: application/json
Authorization: Bearer <token>

{
  "target": "https://example.com",
  "organization_id": 123
}
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "status": "running",
  "message": "Dynamic security assessment started"
}
```

### Check Scan Status

```bash
GET /scan/job_abc123
Authorization: Bearer <token>
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "status": "completed",
  "target": "https://example.com",
  "findings": [...],
  "agents_created": [
    {
      "name": "Recon Agent",
      "modules": [],
      "status": "completed",
      "findings_count": 0
    },
    {
      "name": "API Security Agent",
      "modules": ["api_testing"],
      "status": "completed",
      "findings_count": 3
    },
    {
      "name": "SQL Injection Agent",
      "modules": ["sql_injection"],
      "status": "completed",
      "findings_count": 1
    }
  ],
  "total_findings": 4,
  "critical_findings": 1,
  "high_findings": 1
}
```

### View Agent Graph (NEW)

```bash
GET /scan/job_abc123/agent-graph
Authorization: Bearer <token>
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "graph": {
    "nodes": [
      {
        "id": "root-abc123",
        "name": "Root Coordinator",
        "parent_id": null,
        "status": "completed"
      },
      {
        "id": "agent-xyz",
        "name": "API Security Agent",
        "parent_id": "root-abc123",
        "modules": ["api_testing"],
        "status": "completed",
        "findings_count": 3
      }
    ],
    "edges": [
      {
        "from": "root-abc123",
        "to": "agent-xyz",
        "type": "created"
      }
    ]
  }
}
```

## Available Tools (30+)

### Coordination Tools (LOCAL)
- `create_agent` - Spawn specialized agents
- `send_message_to_agent` - Inter-agent communication
- `view_agent_graph` - See agent hierarchy
- `get_my_agents` - Check child agents
- `agent_finish` - Mark agent complete
- `finish_scan` - Complete entire scan (root only)
- `create_vulnerability_report` - Document findings
- `get_scan_status` - Check progress

### Network Tools (SANDBOX)
- `nmap_scan` - Port scanning
- `dns_enumerate` - DNS enumeration
- `service_detection` - Service/version detection
- `resolve_domain` - Domain to IP resolution

### Web Tools (SANDBOX)
- `http_scan` - Website crawling & structure
- `xss_test` - XSS testing
- `csrf_test` - CSRF testing
- `directory_enumeration` - Dir brute forcing
- `nikto_scan` - Web server scanning
- `security_headers_check` - Header analysis
- `javascript_analysis` - JS file analysis

### Database Tools (SANDBOX)
- `sql_injection_test` - SQL injection
- `sqlmap_test` - Automated SQLi
- `nosql_injection_test` - NoSQL injection
- `database_enumeration` - DB structure extraction

### API Tools (SANDBOX) - NEW!
- `api_fuzzing` - Comprehensive API fuzzing
- `api_brute_force` - Auth brute forcing
- `api_idor_test` - IDOR testing
- `api_rate_limit_test` - Rate limit checks
- `detect_exposed_env_vars` - Find exposed secrets
- `scan_env_files` - .env file detection
- `api_privilege_escalation_test` - Privilege escalation
- `api_method_fuzzing` - HTTP method testing
- `api_mass_assignment_test` - Mass assignment
- `graphql_security_test` - GraphQL testing

## Prompt Modules

Specialized knowledge modules loaded into agents:

### Vulnerability Modules
- `sql_injection` - SQL injection expertise
  - Error-based, Boolean-based, Time-based, Union-based
  - Database-specific payloads
  - Validation requirements
- `xss` - Cross-site scripting
  - Reflected, Stored, DOM-based
  - Context-aware payloads
  - Filter bypasses
- `api_testing` - API security
  - Fuzzing techniques
  - Brute force strategies
  - Environment variable patterns
  - IDOR, Rate limiting, Mass assignment
- `authentication` - Auth/authz
  - Credential testing
  - Session management
  - Password reset flows
  - Privilege escalation

### Framework Modules (Future)
- `wordpress` - WordPress-specific tests
- `django` - Django security
- `nextjs` - Next.js vulnerabilities

## Decision Logic Examples

### When UI Agent Discovers APIs

```
UI Agent: "Found API endpoints: /api/users, /api/products"
          ↓
Root Agent Decision:
  <thinking>
  The target has API endpoints. I should create an API testing agent
  with the api_testing module to perform comprehensive API security tests.
  </thinking>

  <function=create_agent>
  <parameter=task>Test API security at /api/users and /api/products.
  Perform fuzzing, brute force, IDOR testing, and check for exposed
  environment variables.</parameter>
  <parameter=name>API Security Agent</parameter>
  <parameter=prompt_modules>api_testing</parameter>
  </function>
```

### When DB Connection Found

```
Recon Agent: "Database detected: MySQL 5.7"
          ↓
Root Agent Decision:
  <thinking>
  MySQL database is being used. Should create SQL injection testing agent.
  </thinking>

  <function=create_agent>
  <parameter=task>Test for SQL injection vulnerabilities. Target is
  using MySQL 5.7. Test all input parameters discovered.</parameter>
  <parameter=name>SQL Injection Agent</parameter>
  <parameter=prompt_modules>sql_injection</parameter>
  </function>
```

### When .env Variables Exposed

```
API Agent: "Found exposed endpoint: /api/config"
API Agent uses: detect_exposed_env_vars
Result: DATABASE_URL, AWS_SECRET_KEY exposed
          ↓
API Agent creates vulnerability report:
  <function=create_vulnerability_report>
  <parameter=title>Critical: Environment Variables Exposed via API</parameter>
  <parameter=severity>CRITICAL</parameter>
  <parameter=vulnerability_type>INFORMATION_DISCLOSURE</parameter>
  <parameter=description>The /api/config endpoint exposes sensitive
  environment variables including database credentials and AWS keys.</parameter>
  <parameter=evidence>
  Response from /api/config:
  {
    "DATABASE_URL": "postgres://user:pass@db.internal:5432/prod",
    "AWS_SECRET_KEY": "abc123...",
    "STRIPE_SECRET_KEY": "sk_live_..."
  }
  </parameter>
  </function>
```

## Performance Characteristics

### Cost Estimation

**Per Scan (approximate):**
- Root Agent: 10-20 LLM calls (~$0.10-0.20)
- Recon Agent: 5-10 calls (~$0.05-0.10)
- Specialized Agent: 8-15 calls each (~$0.08-0.15)
- Total for typical scan: **$0.30-0.70**

**With Prompt Caching (future):**
- System prompt cached across calls
- Cost reduced by ~50%
- Typical scan: **$0.15-0.35**

### Execution Time

**Typical Scan:**
- Recon phase: 1-2 minutes
- Agent creation: <1 second per agent
- Specialized testing: 3-8 minutes per agent
- Total: **5-15 minutes** (depends on findings)

**Parallel Execution:**
- Agents run concurrently
- 4 agents complete in similar time as 1
- Bounded by longest-running agent

## Comparison: Old vs New

| Aspect | Bot System | Dynamic Agents |
|--------|-----------|----------------|
| **Decision Making** | Pre-defined bots | Claude decides |
| **Adaptability** | Fixed tests | Target-specific |
| **Expertise** | Generic scanning | Specialized modules |
| **Efficiency** | Runs all bots | Only relevant agents |
| **Scalability** | 3-6 containers | Unlimited agents |
| **API Testing** | Basic HTTP scan | Comprehensive fuzzing |
| **Environment Vars** | Not detected | Automatically found |
| **Resource Usage** | 500MB per bot | 10MB per agent |
| **Intelligence** | 5-10 LLM calls | 50-200 LLM calls |
| **Cost per Scan** | ~$0.10 | ~$0.30-0.70 |
| **Findings Quality** | Generic | Validated & specific |

## Migration Path

### Phase 1: Parallel Running (Current)

Both systems available:

```yaml
# Use old system
USE_DYNAMIC_AGENTS=false

# Use new system
USE_DYNAMIC_AGENTS=true
```

### Phase 2: Gradual Adoption

- Test on selected organizations
- Compare finding quality
- Gather performance metrics

### Phase 3: Full Migration

- Set as default
- Deprecate old bots
- Remove legacy code

## Troubleshooting

### "Tool not found" errors

**Cause:** Tools not registered
**Fix:** Ensure `from core import tools` runs on startup

### "Agent graph not updating"

**Cause:** Singleton not initialized
**Fix:** Import agent_graph before creating agents

### "LLM not calling tools"

**Cause:** Tool schemas not in system prompt
**Fix:** Check get_tools_prompt() is called

### High LLM costs

**Solutions:**
- Reduce max_iterations for agents
- Use Haiku model for simple agents
- Enable prompt caching

## Best Practices

### For Root Agent
1. Start with reconnaissance
2. Wait for results before creating agents
3. Create focused agents with specific tasks
4. Don't duplicate agents
5. Use finish_scan when done

### For Specialized Agents
1. Use your expert knowledge modules
2. Validate all findings before reporting
3. Include payloads and evidence
4. Report only confirmed vulnerabilities
5. Call agent_finish when task complete

### For Tool Development
1. Use @register_tool decorator
2. Provide clear descriptions
3. Document parameters thoroughly
4. Mark sandbox_execution correctly
5. Return structured dictionaries

## Future Enhancements

- [ ] Real-time agent graph visualization in UI
- [ ] More specialized prompt modules (frameworks, CMS)
- [ ] Agent performance analytics
- [ ] Custom agent creation via API
- [ ] Agent conversation history export
- [ ] Multi-agent coordination improvements
- [ ] Prompt caching for cost reduction
- [ ] Agent learning from past scans

## Support

For issues or questions:
1. Check agent graph: `/scan/{job_id}/agent-graph`
2. Review logs: Look for agent creation and tool execution
3. Verify environment: `USE_DYNAMIC_AGENTS=true` set
4. Check API key: `ANTHROPIC_API_KEY` configured

---

**The dynamic system makes FetchBot truly intelligent - it thinks, adapts, and improves with every scan.** 🚀
