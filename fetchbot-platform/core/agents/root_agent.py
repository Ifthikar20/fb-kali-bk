"""
Root Coordinator Agent

The root agent is responsible for:
1. Analyzing the target
2. Creating specialized sub-agents dynamically based on what's discovered
3. Coordinating between agents
4. Aggregating findings
5. Generating final report

This agent has NO specialized knowledge modules - it's a pure coordinator.
Claude decides what agents to create based on reconnaissance.
"""

import logging
from typing import Dict, Any
from .base_agent import BaseAgent
from ..llm.config import LLMConfig

logger = logging.getLogger(__name__)


class RootAgent(BaseAgent):
    """
    Root coordinator agent

    This agent orchestrates the entire security assessment by:
    - Creating specialized sub-agents
    - Monitoring their progress
    - Aggregating findings
    - Making strategic decisions

    Example Flow:
    1. UI agent discovers API endpoints → Creates API fuzzing agent
    2. API agent finds database connection → Creates SQL injection agent
    3. Network agent finds open ports → Creates service-specific agents
    """

    def __init__(self, target: str, job_id: str, db_url: str = None):
        """
        Initialize root coordinator agent

        Args:
            target: Target URL, domain, or IP to assess
            job_id: Unique job identifier for this assessment
            db_url: Database URL for execution logging (optional)
        """
        # Root agent has NO prompt modules (empty list)
        llm_config = LLMConfig(prompt_modules=[])

        config = {
            "llm_config": llm_config,
            "max_iterations": 100,  # Root agent can run longer
            "sandbox_url": "http://kali-agent-1:9000",
            "db_url": db_url,
            "job_id": job_id,
            "target": target  # Target URL/domain
        }

        # Create explicit task with target emphasized
        task = f"""
You are the ROOT COORDINATOR for a comprehensive security assessment.

TARGET: {target}

CRITICAL: You MUST use this EXACT target URL in ALL operations:
- When creating agents, pass them this target: {target}
- When agents call tools, they should use this target: {target}
- DO NOT use example.com, betterandbliss.com, or any other URL
- The ONLY valid target for this scan is: {target}

Your job:
1. Perform initial reconnaissance to understand the target
2. Create specialized agents based on what you discover
3. Coordinate agents and aggregate their findings
4. Generate final security assessment report

Remember: ALWAYS use {target} - no other URL is valid for this scan.
"""

        super().__init__(
            config=config,
            agent_id=job_id,  # Use job_id as root agent ID
            parent_id=None,  # No parent - this is root
            name="Root Coordinator",
            task=task
        )

        self.target = target
        self.job_id = job_id
        self.db_url = db_url

        logger.info(f"Root coordinator initialized for target: {target}")

    async def run_assessment(self) -> Dict[str, Any]:
        """
        Run complete security assessment

        Returns:
            Dictionary with:
            - status: Assessment status
            - findings: All findings from all agents
            - agents_created: List of agents that were created
            - summary: Executive summary
        """
        task = self._build_coordinator_task()

        result = await self.agent_loop(task)

        # Collect findings from all agents
        from .agent_graph import get_agent_graph
        graph = get_agent_graph()
        all_agents = graph.get_all_agents()

        # Aggregate findings
        all_findings = self.state.get_findings()

        # Add findings from child agents
        for agent_id, agent_info in all_agents.items():
            if agent_id != self.agent_id:  # Skip self
                agent_instance = graph.agents.get(agent_id)
                if agent_instance:
                    all_findings.extend(agent_instance.get_findings())

        return {
            "status": "completed",
            "target": self.target,
            "job_id": self.job_id,
            "findings": all_findings,
            "agents_created": [
                {
                    "id": agent_id,
                    "name": info["name"],
                    "modules": info["prompt_modules"],
                    "status": info["status"],
                    "findings_count": info["findings_count"]
                }
                for agent_id, info in all_agents.items()
                if agent_id != self.agent_id
            ],
            "total_findings": len(all_findings),
            "critical_findings": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high_findings": len([f for f in all_findings if f.get("severity") == "HIGH"])
        }

    def _build_coordinator_task(self) -> str:
        """
        Build the initial task prompt for the root coordinator

        This tells Claude what to do and gives it context
        """
        task = f"""
You are the ROOT COORDINATOR for a comprehensive security assessment.

TARGET: {self.target}
JOB ID: {self.job_id}

YOUR MISSION:
Conduct a THOROUGH, METHODICAL security assessment. Take your time. Be complete.
You do NOT perform scans directly - you delegate to specialized agents.

CRITICAL: PACE AND VISIBILITY

This is NOT a race. The user wants to SEE what's happening at each step.

DO:
✅ Run one major phase at a time (recon, then discovery, then testing)
✅ WAIT for each agent to complete before moving to next decision
✅ Let long-running tools finish (nmap can take minutes, fuzzing can take longer)
✅ Show progress: "Started X", "X is running...", "X completed, found Y"
✅ Explore ALL discovered attack surface before finishing
✅ Only call finish_scan when you've tested EVERYTHING

DON'T:
❌ Rush through the scan
❌ Create too many agents at once
❌ Move to next step before current agents finish
❌ Finish scan while there are still untested areas
❌ Skip opportunities because they "might not have vulns"

THINK LIKE A REAL PENTESTER:

Real pentesters work methodically:
1. Run tool → WAIT for it to complete → Review results carefully
2. Find something interesting → Plan investigation → Execute → WAIT
3. Get results → Analyze thoroughly → Decide what's next → Execute
4. Repeat until ALL possibilities exhausted

Example of CORRECT pacing:

PHASE 1: RECONNAISSANCE (Day 1)
→ Create recon agent with task: "Run nmap on {self.target}, discover open ports and services"
→ WAIT (nmap takes time, let it run)
→ Receive message: "nmap complete - found ports 22 (SSH), 80 (HTTP), 443 (HTTPS)"
→ Think: "Web services on 80/443 are high-value targets. SSH on 22 could be bruteforced"

PHASE 2: WEB DISCOVERY (Day 2)
→ Create mapping agent: "Map web application structure on port 80/443"
→ Agent uses http_scan, discovers: Apache, /admin, /api, /uploads, /login
→ WAIT for mapping to complete
→ Think: "/api is promising (data endpoints), /admin is sensitive, /uploads could allow malicious files"

PHASE 3: DIRECTORY FUZZING (Day 3)
→ Create fuzzing agent: "Run directory fuzzing on /api to find all endpoints"
→ WAIT (fuzzing takes time - could be 5-10 minutes)
→ UI shows: "🔍 Directory fuzzing in progress on /api..."
→ Agent completes: "Found /api/v1/users, /api/v1/auth, /api/v1/posts, /api/admin"
→ Think: "/api/admin is unusual, /api/v1/users handles user data (IDOR risk)"

PHASE 4: RECURSIVE DISCOVERY (Day 4)
→ Create agent: "Recursively fuzz /api/admin to find sub-paths"
→ WAIT for recursive fuzzing
→ Results: "/api/admin/users, /api/admin/settings, /api/admin/logs"
→ Think: "Admin endpoints found, these need security testing"

PHASE 5: VULNERABILITY TESTING (Day 5+)
→ Create focused agents for each finding:
  - "Test /api/v1/users for IDOR vulnerability"
  - "Test /api/admin for authentication bypass"
  - "Test /uploads for malicious file upload"
  - "Test /login for SQL injection"
→ WAIT for each test to complete
→ Review results from each agent
→ If vulnerability found → Document it
→ If nothing found → Move on

PHASE 6: FOLLOW-UP (Day 6+)
→ If IDOR found in /api/v1/users → Test other endpoints for same issue
→ If auth bypass found → Test what actions possible
→ If file upload vulnerable → Test for RCE
→ Keep investigating until ALL leads exhausted

PHASE 7: FINAL CHECKS (Day 7)
→ Review everything tested
→ Check if any areas missed
→ Run final verification tests
→ ONLY THEN call finish_scan

YOUR WORKFLOW:

Step 1: INITIAL RECONNAISSANCE (Start here, wait for completion)
Create agent: "Perform initial reconnaissance - nmap scan, service detection, basic http_scan"
WAIT for completion.
When done, you'll receive a message with results.

Step 2: ANALYZE RESULTS (Think deeply)
- What ports are open? What services?
- Is there a web app? What technology?
- Any interesting paths discovered?
- What are the high-value targets?

Step 3: DEEP DISCOVERY (One area at a time)
Based on what was found, create focused agents:
- If web app exists → "Map all directories and endpoints"
  WAIT for mapping to complete
- If API found → "Enumerate all API endpoints"
  WAIT for enumeration
- If specific path interesting (like /login) → "Recursively explore /login"
  WAIT for recursive exploration

Step 4: VULNERABILITY TESTING (Methodical and complete)
For EACH interesting finding, create a testing agent:
- "Test /api/users?id= for SQL injection"
  WAIT for test to complete, review results
- "Test /api/users for IDOR by accessing different user IDs"
  WAIT for test to complete, review results
- "Test /login form for authentication bypass"
  WAIT for test to complete, review results

Create ONE or TWO testing agents at a time (not 10 at once).
Let them finish. Review results. Then create more.

Step 5: FOLLOW-UP INVESTIGATION (Based on findings)
If tests discover vulnerabilities:
- Create follow-up agents to understand full impact
- Test related endpoints for similar issues
- Verify exploitability

If tests find nothing:
- Move to next attack surface
- Don't give up too early

Step 6: EXHAUSTIVE COVERAGE (Be thorough)
Before finishing, ask yourself:
- Did we test ALL discovered endpoints?
- Did we try ALL relevant attack types?
- Are there any untested directories?
- Did we follow up on ALL interesting findings?
- Have we exhausted every possibility?

Step 7: FINISH ONLY WHEN COMPLETE
Call finish_scan ONLY when:
✅ All discovered attack surface has been tested
✅ All interesting findings have been investigated
✅ No more agents are running
✅ You've done everything a thorough pentester would do

COMMUNICATION WITH UI:

The user is watching the UI. They want to see progress:
- "🔍 Starting nmap scan..."
- "⏳ Nmap in progress (may take 2-5 minutes)..."
- "✅ Nmap complete: Found 3 open ports"
- "🌐 Mapping web application structure..."
- "⏳ Directory fuzzing in progress..."
- "✅ Found 15 directories, analyzing..."

Agents automatically log their actions. Your job: WAIT and let them complete.

IMPORTANT RULES:

1. **PATIENCE** - Don't rush. Scans take time. Wait for completion.
2. **SEQUENTIAL** - Finish one phase before starting next
3. **THOROUGH** - Test everything before finishing
4. **VISIBLE** - User sees each step in UI via agent logs
5. **METHODICAL** - One discovery leads to next investigation
6. **COMPLETE** - Only finish_scan when nothing left to test

AVAILABLE TOOLS FOR AGENTS:
- Reconnaissance: nmap_scan, http_scan, dns_enumerate, service_detection
- Discovery: directory fuzzing, subdomain enumeration
- Testing: sql_injection_test, xss_test, api_fuzzing, api_idor_test, auth testing
- Analysis: javascript_analysis, security_headers_check

AVAILABLE PROMPT MODULES:
Give agents expertise: sql_injection, xss, api_testing, authentication

BEGIN by creating ONE reconnaissance agent. Wait for their results. Then think carefully about what to do next.

Remember: THOROUGH and VISIBLE beats FAST and HIDDEN.
"""

        return task
