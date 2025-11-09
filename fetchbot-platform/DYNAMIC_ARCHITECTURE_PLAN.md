# FetchBot.ai → Dynamic Agent Architecture Transformation

## Executive Summary

Transform FetchBot from a **fixed bot orchestration system** to a **dynamic, LLM-driven multi-agent framework** inspired by STRIX architecture.

**Current State:**
- Fixed bots: network-bot, ui-bot, db-bot OR N identical Kali agents
- Claude decides WHICH bots to run
- Tools hardcoded into each bot
- Pre-created Docker containers

**Target State:**
- Dynamic agent creation based on task analysis
- LLM decides WHAT agents to create with WHICH expertise
- Specialized prompt modules for vulnerability types
- Lightweight agents sharing infrastructure
- Tool registry with automatic schema generation

---

## Architecture Comparison

### Current: Fixed Bot Orchestration
```
User Request → API
              ↓
         Claude Decision
              ↓
    "Run network-bot, ui-bot"
              ↓
    HTTP calls to pre-existing containers
              ↓
         Collect results
```

### Target: Dynamic Multi-Agent System
```
User Request → Root Agent (Coordinator)
                    ↓
              Claude analyzes target
                    ↓
         "Create SQL Injection Agent with sql_injection module"
         "Create XSS Agent with xss, dom_xss modules"
                    ↓
         Agents created dynamically
                    ↓
         Each agent runs own loop
                    ↓
         Tools executed via registry
                    ↓
         Results aggregated to root
```

---

## Core Components to Implement

### 1. Tool Registry System
**Purpose:** Centralize all scanning tools with automatic schema generation

**File:** `fetchbot-platform/core/tools/registry.py`

```python
# Decorator-based registration
@register_tool(sandbox_execution=True)
async def nmap_scan(target: str, ports: str = "1-1000") -> dict:
    """
    Scan ports on target using nmap

    Args:
        target: IP address or domain to scan
        ports: Port range (e.g., "80,443" or "1-1000")

    Returns:
        Dict with open ports and service information
    """
    # Implementation
    pass

# Automatic schema generation for LLM
{
    "name": "nmap_scan",
    "description": "Scan ports on target using nmap",
    "parameters": {
        "target": {"type": "string", "description": "IP address or domain to scan"},
        "ports": {"type": "string", "description": "Port range"}
    }
}
```

**Tools to Register:**
- `nmap_scan` - Port scanning
- `dns_enumerate` - DNS enumeration
- `http_scan` - Web crawling
- `sql_injection_test` - SQL injection testing
- `xss_test` - XSS vulnerability testing
- `nikto_scan` - Web server scanning
- `create_agent` - Dynamic agent creation
- `send_message_to_agent` - Inter-agent communication
- `agent_finish` - Agent completion
- `create_vulnerability_report` - Report generation

### 2. Prompt Module System
**Purpose:** Provide specialized knowledge to agents

**File Structure:**
```
fetchbot-platform/core/prompts/
├── __init__.py
├── base_system_prompt.jinja
├── vulnerabilities/
│   ├── sql_injection.jinja
│   ├── xss.jinja
│   ├── csrf.jinja
│   ├── xxe.jinja
│   ├── ssrf.jinja
│   ├── idor.jinja
│   ├── authentication.jinja
│   └── authorization.jinja
├── frameworks/
│   ├── wordpress.jinja
│   ├── django.jinja
│   ├── nextjs.jinja
│   └── fastapi.jinja
└── coordination/
    └── root_agent.jinja
```

**Example Module:** `vulnerabilities/sql_injection.jinja`
```jinja
## SQL Injection Expertise

You are an expert in SQL injection vulnerabilities. Your specialized knowledge:

### Detection Techniques
1. **Error-based:** Inject `'` and `"` to trigger database errors
2. **Boolean-based:** Test `' OR '1'='1` vs `' OR '1'='2`
3. **Time-based:** Use `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`
4. **Union-based:** Determine column count, extract data

### Common Payloads
- MySQL: `' OR 1=1-- -`
- PostgreSQL: `' OR 1=1--`
- MSSQL: `' OR 1=1;--`
- Oracle: `' OR 1=1--`

### Validation Requirements
CRITICAL: Always validate findings with proof-of-concept:
1. Show exact payload that worked
2. Demonstrate data extraction
3. Document database type and version
4. Never report false positives
```

**Module Loading:**
```python
from core.llm.config import LLMConfig

# Agent with SQL injection expertise
config = LLMConfig(prompt_modules=["sql_injection"])

# Agent with XSS + CSRF expertise
config = LLMConfig(prompt_modules=["xss", "csrf"])

# Root coordinator (no modules)
config = LLMConfig(prompt_modules=[])
```

### 3. Base Agent Class
**Purpose:** Core agent loop that all agents inherit

**File:** `fetchbot-platform/core/agents/base_agent.py`

```python
class BaseAgent:
    def __init__(self, config: dict):
        self.agent_id = uuid.uuid4()
        self.llm_config = config["llm_config"]
        self.max_iterations = config.get("max_iterations", 50)
        self.state = AgentState()
        self.tools = get_tool_registry()

    async def agent_loop(self, task: str) -> dict:
        """
        Main agent execution loop

        1. Initialize state with task
        2. Loop:
           a. Check messages from other agents
           b. Make LLM request with conversation history
           c. Parse tool invocations from response
           d. Execute tools
           e. Add results to conversation history
           f. Check if should finish
        3. Return final result
        """
        self.state.add_message("user", task)

        for iteration in range(self.max_iterations):
            # Check for messages from other agents
            self._check_agent_messages()

            # Generate LLM response
            response = await self.llm.generate(
                self.state.get_conversation_history()
            )

            # Parse tool invocations
            tool_calls = self._parse_tool_calls(response.content)

            # Execute tools
            should_finish = await self._execute_tools(tool_calls)

            if should_finish:
                return self.state.final_result

        return {"error": "Max iterations reached"}
```

### 4. Root Coordinator Agent
**Purpose:** Analyzes target and creates specialized sub-agents

**File:** `fetchbot-platform/core/agents/root_agent.py`

```python
class RootAgent(BaseAgent):
    def __init__(self):
        # NO prompt modules = coordinator role
        llm_config = LLMConfig(prompt_modules=[])

        super().__init__({
            "llm_config": llm_config,
            "max_iterations": 100,
        })

    async def coordinate_scan(self, target: str) -> dict:
        """
        Coordinate entire penetration test

        Process:
        1. Analyze target (URL, domain, or code repo)
        2. Create reconnaissance agent
        3. Based on recon results, create specialized agents:
           - SQL Injection Agent (if database detected)
           - XSS Agent (if forms/inputs found)
           - CSRF Agent (if authenticated endpoints)
           - etc.
        4. Collect and aggregate all findings
        5. Generate final report
        """
        task = f"""
        Conduct a comprehensive security assessment of: {target}

        You are the root coordinator. Your job:
        1. Understand the target type
        2. Create specialized agents for each attack vector
        3. Monitor their progress
        4. Aggregate findings
        5. Generate final report

        Available tools:
        - create_agent: Create a new specialized agent
        - view_agent_graph: See all active agents
        - send_message_to_agent: Communicate with agents
        - finish_scan: Complete the assessment
        """

        return await self.agent_loop(task)
```

### 5. Agent Graph System
**Purpose:** Track relationships and enable coordination

**File:** `fetchbot-platform/core/agents/agent_graph.py`

```python
class AgentGraph:
    def __init__(self):
        self.nodes = {}  # agent_id -> agent info
        self.edges = []  # relationships
        self.messages = []  # inter-agent messages

    def add_agent(self, agent_id: str, parent_id: str, name: str, modules: list):
        """Register new agent in graph"""
        self.nodes[agent_id] = {
            "id": agent_id,
            "parent_id": parent_id,
            "name": name,
            "modules": modules,
            "status": "running",
            "created_at": datetime.utcnow()
        }

        if parent_id:
            self.edges.append({
                "from": parent_id,
                "to": agent_id,
                "type": "created"
            })

    def send_message(self, from_id: str, to_id: str, content: str):
        """Enable agent-to-agent communication"""
        self.messages.append({
            "from": from_id,
            "to": to_id,
            "content": content,
            "timestamp": datetime.utcnow()
        })

    def get_agent_messages(self, agent_id: str) -> list:
        """Get unread messages for agent"""
        return [m for m in self.messages if m["to"] == agent_id]
```

### 6. LLM Integration with Tool Schemas
**Purpose:** Enable Claude to call tools dynamically

**File:** `fetchbot-platform/core/llm/llm.py`

```python
class LLM:
    def __init__(self, config: LLMConfig):
        self.client = anthropic.Anthropic()
        self.config = config
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """
        Build system prompt with:
        1. Base instructions
        2. Loaded prompt modules
        3. Available tools
        """
        env = Environment(loader=FileSystemLoader("core/prompts"))
        template = env.get_template("base_system_prompt.jinja")

        # Load specialized modules
        module_content = {}
        for module_name in self.config.prompt_modules:
            module_template = env.get_template(f"{module_name}.jinja")
            module_content[module_name] = module_template.render()

        # Get tool schemas
        tool_schemas = get_tool_schemas()

        return template.render(
            modules=module_content,
            tools=tool_schemas
        )

    async def generate(self, conversation_history: list) -> LLMResponse:
        """
        Make LLM request with tool use

        Claude response format:
        <thinking>I need to scan for SQL injection...</thinking>

        <function=sql_injection_test>
        <parameter=target>https://example.com/login</parameter>
        <parameter=payload>' OR 1=1--</parameter>
        </function>
        """
        messages = [
            {"role": "system", "content": self.system_prompt},
            *conversation_history
        ]

        response = await self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            messages=messages,
            max_tokens=4000
        )

        # Parse tool invocations
        tool_calls = parse_tool_invocations(response.content)

        return LLMResponse(
            content=response.content,
            tool_invocations=tool_calls
        )
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)
**Goal:** Build core infrastructure

1. **Tool Registry** (`core/tools/registry.py`)
   - Decorator for tool registration
   - Schema generation for LLM
   - Tool execution routing

2. **Prompt Module System** (`core/prompts/`)
   - Base system prompt template
   - 5 vulnerability modules (SQL, XSS, CSRF, IDOR, Auth)
   - Module loading infrastructure

3. **Agent State Management** (`core/agents/state.py`)
   - Conversation history tracking
   - Findings aggregation
   - Iteration counting

### Phase 2: Agent System (Week 2)
**Goal:** Implement agent architecture

1. **Base Agent Class** (`core/agents/base_agent.py`)
   - Agent loop implementation
   - Tool execution
   - LLM integration

2. **Root Coordinator Agent** (`core/agents/root_agent.py`)
   - Task analysis
   - Agent creation orchestration
   - Result aggregation

3. **Agent Graph** (`core/agents/agent_graph.py`)
   - Node/edge management
   - Message passing
   - Status tracking

### Phase 3: Tool Migration (Week 3)
**Goal:** Convert existing bots into tools

1. **Network Tools** (from network-bot)
   - `@register_tool` for nmap_scan
   - `@register_tool` for dns_enumerate
   - `@register_tool` for port_service_detection

2. **Web Tools** (from ui-bot)
   - `@register_tool` for http_scan
   - `@register_tool` for xss_test
   - `@register_tool` for csrf_test
   - `@register_tool` for nikto_scan

3. **Database Tools** (from db-bot)
   - `@register_tool` for sql_injection_test
   - `@register_tool` for nosql_injection_test

4. **Coordination Tools**
   - `@register_tool` for create_agent
   - `@register_tool` for send_message_to_agent
   - `@register_tool` for view_agent_graph
   - `@register_tool` for agent_finish

### Phase 4: API Integration (Week 4)
**Goal:** Update API to use new architecture

1. **New Orchestrator** (`core/orchestrator.py`)
   - Replace BotOrchestrator with RootAgent
   - Keep same API interface for compatibility

2. **Endpoint Updates** (`api.py`)
   - `/scan` uses RootAgent
   - Add `/agent-graph` endpoint for visualization
   - Add `/scan/{job_id}/agents` to see agent hierarchy

3. **Database Updates** (`models.py`)
   - Add `Agent` model (tracks all created agents)
   - Add `agent_id` to Finding model
   - Add `agent_hierarchy` JSON field to PentestJob

---

## Example Execution Flow

### User Request
```bash
POST /scan
{
  "target": "https://shop.example.com",
  "organization_id": 123
}
```

### Root Agent Analysis
```
ITERATION 1:
Task: "Conduct security assessment of https://shop.example.com"

<thinking>
This is an e-commerce website. I should:
1. First do reconnaissance to understand the tech stack
2. Check for common web vulnerabilities
3. Test authentication and session management
4. Look for business logic flaws

Let me start by creating a reconnaissance agent.
</thinking>

<function=create_agent>
<parameter=task>Perform reconnaissance on https://shop.example.com. Identify technology stack, endpoints, and attack surface.</parameter>
<parameter=name>Recon Agent</parameter>
<parameter=prompt_modules></parameter>
</function>
```

### Recon Agent Execution
```
ITERATION 1:
<function=http_scan>
<parameter=target>https://shop.example.com</parameter>
</function>

ITERATION 2:
<function=dns_enumerate>
<parameter=domain>example.com</parameter>
</function>

ITERATION 3:
<thinking>
Found:
- Login form at /login
- Product search at /search?q=
- Shopping cart at /cart
- Tech: PHP, MySQL, jQuery

Let me report back to root agent.
</thinking>

<function=agent_finish>
<parameter=result>
{
  "findings": {
    "technology": "PHP 7.4, MySQL, jQuery 3.6",
    "endpoints": ["/login", "/search", "/cart", "/checkout"],
    "attack_vectors": [
      "SQL injection in search",
      "XSS in product reviews",
      "CSRF in checkout"
    ]
  }
}
</parameter>
</function>
```

### Root Agent Creates Specialized Agents
```
ITERATION 2:
<thinking>
Recon agent found SQL, XSS, and CSRF vectors.
I'll create three specialized agents.
</thinking>

<function=create_agent>
<parameter=task>Test SQL injection in search functionality at /search?q=</parameter>
<parameter=name>SQL Injection Agent</parameter>
<parameter=prompt_modules>sql_injection</parameter>
</function>

<function=create_agent>
<parameter=task>Test XSS in product review form</parameter>
<parameter=name>XSS Agent</parameter>
<parameter=prompt_modules>xss</parameter>
</function>

<function=create_agent>
<parameter=task>Test CSRF protection on checkout flow</parameter>
<parameter=name>CSRF Agent</parameter>
<parameter=prompt_modules>csrf</parameter>
</function>
```

### SQL Injection Agent (with specialized module)
```
ITERATION 1:
<thinking>
I have deep SQL injection expertise from my loaded module.
Let me test the search parameter systematically.
</thinking>

<function=sql_injection_test>
<parameter=target>https://shop.example.com/search</parameter>
<parameter=parameter>q</parameter>
<parameter=payload>' OR 1=1--</parameter>
</function>

ITERATION 2:
<thinking>
Got different response! Looks vulnerable.
Let me validate with data extraction.
</thinking>

<function=sql_injection_test>
<parameter=target>https://shop.example.com/search</parameter>
<parameter=parameter>q</parameter>
<parameter=payload>' UNION SELECT table_name FROM information_schema.tables--</parameter>
</function>

ITERATION 3:
<thinking>
Confirmed! I can extract table names.
Creating vulnerability report.
</thinking>

<function=create_vulnerability_report>
<parameter=title>SQL Injection in Product Search</parameter>
<parameter=severity>CRITICAL</parameter>
<parameter=description>The search parameter is vulnerable to SQL injection...</parameter>
<parameter=payload>' UNION SELECT table_name FROM information_schema.tables--</parameter>
<parameter=evidence>
Extracted tables: users, products, orders, credit_cards
</parameter>
</function>

<function=agent_finish>
<parameter=result>{"vulnerabilities_found": 1}</parameter>
</function>
```

### Final Result
```json
{
  "job_id": "job_123",
  "status": "completed",
  "agents_created": [
    {
      "name": "Recon Agent",
      "modules": [],
      "status": "completed"
    },
    {
      "name": "SQL Injection Agent",
      "modules": ["sql_injection"],
      "status": "completed",
      "findings": 1
    },
    {
      "name": "XSS Agent",
      "modules": ["xss"],
      "status": "completed",
      "findings": 0
    },
    {
      "name": "CSRF Agent",
      "modules": ["csrf"],
      "status": "completed",
      "findings": 1
    }
  ],
  "total_findings": 2,
  "critical": 1,
  "high": 1
}
```

---

## Benefits Over Current Architecture

### 1. **Adaptability**
- **Current:** Fixed bots, same tests every time
- **New:** LLM decides what to test based on target
- **Example:** WordPress site → creates "WordPress Security Agent" with wordpress module

### 2. **Expertise**
- **Current:** Generic scanning logic
- **New:** Specialized modules provide deep expertise
- **Example:** SQL agent knows error-based vs time-based vs union-based injection

### 3. **Efficiency**
- **Current:** Run all bots even if irrelevant
- **New:** Only create agents for detected attack vectors
- **Example:** No database? No SQL injection agent created

### 4. **Scalability**
- **Current:** Adding new test requires new bot container
- **New:** Just add @register_tool and optional prompt module
- **Example:** Add XXE testing: create xxe_test tool + xxe.jinja module

### 5. **Intelligence**
- **Current:** Claude makes one decision: which bots
- **New:** Claude makes continuous decisions at every step
- **Example:** SQL agent decides to create validation sub-agent for PoC

### 6. **Coordination**
- **Current:** Bots run independently, no communication
- **New:** Agents can message each other, share findings
- **Example:** Recon agent tells SQL agent about database type

---

## Migration Strategy

### Option 1: Parallel Development (RECOMMENDED)
Keep existing bot system, build new system alongside:

```python
# api.py
if os.getenv("USE_DYNAMIC_AGENTS") == "true":
    orchestrator = DynamicOrchestrator()  # New system
else:
    orchestrator = BotOrchestrator()  # Legacy system
```

**Benefits:**
- No disruption to current users
- Gradual migration
- A/B testing possible

### Option 2: Complete Replacement
Replace bot orchestrator entirely:

**Benefits:**
- Cleaner codebase
- Force adoption of new system

**Risks:**
- All features must work before deployment
- No fallback option

---

## Infrastructure Considerations

### Docker Architecture
**Current:** 3-6 containers (postgres + redis + 1-4 bots)

**New Option A - Lightweight:**
- postgres (same)
- redis (same)
- api (runs root agent + all sub-agents in-process)
- kali-tools (single container with all tools, API calls it)

**New Option B - Hybrid:**
- postgres (same)
- redis (same)
- api (runs agents)
- kali-tools-1, kali-tools-2, kali-tools-3 (tool execution pool)

**New Option C - STRIX-style:**
- postgres (same)
- redis (same)
- api (coordinator only)
- dynamic-agent-runtime (single Kali container, agents share it)

**Recommendation:** Option A for simplicity, Option C for STRIX parity

### Resource Usage
- **Current:** Each bot = full container (~500MB)
- **New:** Each agent = Python thread (~10MB)
- **Savings:** Can run 50+ agents with same memory as 3 bots

---

## Code Organization

### New Directory Structure
```
fetchbot-platform/
├── main.py
├── api.py (updated)
├── config.py (same)
├── models.py (add Agent model)
│
├── core/                              # NEW
│   ├── __init__.py
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base_agent.py             # BaseAgent class
│   │   ├── root_agent.py             # RootAgent coordinator
│   │   ├── state.py                  # AgentState management
│   │   └── agent_graph.py            # Agent graph coordination
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── registry.py               # @register_tool decorator
│   │   ├── executor.py               # Tool execution routing
│   │   ├── network_tools.py          # nmap, dns, etc.
│   │   ├── web_tools.py              # http_scan, xss, csrf
│   │   ├── database_tools.py         # SQL injection tests
│   │   └── coordination_tools.py     # create_agent, etc.
│   │
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── config.py                 # LLMConfig class
│   │   ├── llm.py                    # LLM class for Claude
│   │   └── parsers.py                # Parse tool invocations
│   │
│   ├── prompts/
│   │   ├── __init__.py
│   │   ├── base_system_prompt.jinja
│   │   ├── vulnerabilities/
│   │   │   ├── sql_injection.jinja
│   │   │   ├── xss.jinja
│   │   │   ├── csrf.jinja
│   │   │   └── ...
│   │   ├── frameworks/
│   │   │   ├── wordpress.jinja
│   │   │   ├── django.jinja
│   │   │   └── ...
│   │   └── coordination/
│   │       └── root_agent.jinja
│   │
│   └── orchestrator.py               # DynamicOrchestrator (replaces BotOrchestrator)
│
├── bots/                              # LEGACY (keep for now)
│   ├── network-bot/
│   ├── ui-bot/
│   └── db-bot/
│
├── kali-agent/                        # REPURPOSE (tool execution only)
│   └── tools_server.py               # HTTP API for tool execution
│
└── docker-compose-dynamic.yml         # NEW docker config
```

---

## Testing Strategy

### Unit Tests
```python
# tests/core/agents/test_base_agent.py
async def test_agent_loop():
    agent = BaseAgent({"llm_config": LLMConfig()})
    result = await agent.agent_loop("Test task")
    assert result["status"] == "completed"

# tests/core/tools/test_registry.py
def test_tool_registration():
    @register_tool()
    def test_tool(param: str) -> str:
        return param

    schema = get_tool_schema("test_tool")
    assert schema["name"] == "test_tool"
```

### Integration Tests
```python
# tests/integration/test_dynamic_scan.py
async def test_full_scan():
    orchestrator = DynamicOrchestrator()
    result = await orchestrator.run_scan("https://example.com")

    assert result["agents_created"] > 0
    assert "findings" in result
```

### Comparison Tests
```python
# Compare old vs new system on same target
async def test_architecture_comparison():
    target = "https://testphp.vulnweb.com"

    old_results = await BotOrchestrator().run_scan(target)
    new_results = await DynamicOrchestrator().run_scan(target)

    # New system should find same or more vulnerabilities
    assert len(new_results["findings"]) >= len(old_results["findings"])
```

---

## Performance Considerations

### LLM API Costs
- **Current:** ~5-10 LLM calls per scan (orchestration only)
- **New:** ~50-200 LLM calls per scan (each agent makes calls)
- **Mitigation:**
  - Use prompt caching (Anthropic supports this)
  - Set max_iterations per agent
  - Use cheaper models for simple tasks

### Execution Time
- **Current:** Parallel bot execution
- **New:** Agents can run in parallel too
- **Implementation:** Use `asyncio.gather()` for concurrent agents

### Cost Optimization
```python
# Use different models for different agent types
class LLMConfig:
    def __init__(self, prompt_modules, model="claude-3-5-sonnet-20241022"):
        self.model = model

# Root agent: full Sonnet
root_config = LLMConfig([], model="claude-3-5-sonnet-20241022")

# Simple recon agent: cheaper Haiku
recon_config = LLMConfig([], model="claude-3-haiku-20240307")
```

---

## Success Metrics

### Functionality
- ✅ Can create agents dynamically
- ✅ Agents can use specialized prompt modules
- ✅ Tools registered and executable
- ✅ Agent coordination works (message passing)
- ✅ Findings match or exceed current system

### Performance
- ⏱️ Scan completion time ≤ current system
- 💰 LLM cost per scan ≤ $2.00 (with caching)
- 🔍 Vulnerability detection rate ≥ current system

### Code Quality
- 📝 80%+ test coverage
- 🔧 Modular, extensible architecture
- 📚 Comprehensive documentation

---

## Next Steps

1. **Review this plan** - Discuss any concerns or modifications
2. **Start Phase 1** - Build tool registry and prompt system
3. **Create prototype** - Simple agent that can execute one tool
4. **Expand incrementally** - Add more tools and modules
5. **Parallel deployment** - Run alongside existing system
6. **Gradual migration** - Switch users to new system
7. **Deprecate old bots** - Remove legacy bot containers

---

## Questions to Consider

1. **Cost tolerance:** How many LLM calls per scan is acceptable?
2. **Tool execution:** Keep Kali containers or run tools directly in API container?
3. **Agent limits:** Max agents per scan? Max iterations per agent?
4. **Storage:** Store agent conversation history in database?
5. **Visualization:** Build UI to show agent graph in real-time?

---

## Conclusion

This transformation will make FetchBot:
- **Smarter** - LLM makes decisions at every level
- **More capable** - Specialized expertise for each vulnerability type
- **Adaptive** - Different approach for each target
- **Scalable** - Easy to add new tests and modules
- **Efficient** - Only test relevant attack vectors

The architecture follows STRIX's proven design while maintaining FetchBot's strengths (multi-tenancy, AWS deployment, reporting).

Ready to build! 🚀
