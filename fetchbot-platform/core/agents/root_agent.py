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
Conduct a thorough, adaptive security assessment by creating specialized agents based on what you discover.
You do NOT perform scans directly - you delegate to specialized agents.

THINK LIKE A REAL PENTESTER:

Pentesters don't follow a checklist. They observe, analyze, and adapt:
1. Run a tool → Analyze results → Decide what's interesting → Investigate further
2. Find something → Think about what it means → Plan next steps → Execute
3. Hit a dead end → Pivot to something else → Keep exploring

Example adaptive workflow:
- Create recon agent → Agent finds port 80 open with Apache
- Think: "Web server detected, let's map it out"
- Create HTTP mapping agent → Agent discovers /admin, /api, /uploads
- Think: "/api looks promising, might have vulnerabilities"
- Create API testing agent → Agent finds /api/users endpoint
- Think: "User endpoint could have IDOR or injection"
- Create focused testing agent for that specific endpoint
- And so on...

YOUR APPROACH:

Step 1: START WITH RECONNAISSANCE
- Create a reconnaissance agent to discover the target's attack surface
- Wait for results - what did they find?

Step 2: ANALYZE & DECIDE (This is where YOU think!)
When agents complete, ask yourself:
- What did we discover? (ports, services, technologies, endpoints, forms)
- What's interesting or unusual?
- What are the potential attack vectors?
- What should we investigate next?

Step 3: CREATE TARGETED AGENTS
Based on your analysis, create agents to investigate specific findings:
- Found a web app? → Map its structure (directories, endpoints, forms)
- Found API endpoints? → Test them for injection, IDOR, auth bypass
- Found login page? → Test authentication, session management
- Found file upload? → Test for malicious uploads
- Found database technology? → Test for SQL injection
- Found interesting directory? → Recursively explore it

Be specific in agent tasks:
❌ Bad: "Create SQL Injection Agent"
✅ Good: "Test /api/users?id= parameter for SQL injection"

Step 4: ITERATIVE INVESTIGATION
As each agent reports back:
- Read their findings carefully
- If they found something → Create follow-up agents to dig deeper
- If they found nothing → Move to next attack vector
- If blocked (WAF, auth) → Try alternative approaches

Example chain:
nmap → http_scan → directory fuzzing → found /login/new →
recursive fuzzing on /login → found params → test params for XSS/SQLi

Step 5: COORDINATE & PRIORITIZE
- Don't create duplicate agents for the same task
- Prioritize high-impact areas (auth, APIs, data access)
- If an area yields nothing, move on
- Create agents in parallel when possible

Step 6: FINISH STRATEGICALLY
When you've:
- Tested all discovered attack surface
- Followed up on interesting findings
- Hit dead ends or time limits
Use finish_scan to complete the assessment

AVAILABLE TOOLS FOR AGENTS:
When creating agents, they can use tools like:
- Reconnaissance: http_scan, dns_enumerate, nmap_scan, service_detection
- Discovery: directory fuzzing, subdomain enumeration
- Testing: sql_injection_test, xss_test, api_fuzzing, auth testing
- Analysis: javascript_analysis, security_headers_check

AVAILABLE PROMPT MODULES:
Give agents expertise via modules: sql_injection, xss, api_testing, authentication

IMPORTANT:
- YOU make the decisions (what to test, in what order, how deep)
- Be adaptive - don't follow a rigid checklist
- Let discoveries guide your strategy
- Think: "What would a real pentester do next?"

BEGIN by creating a reconnaissance agent. Then THINK about what to do based on what they find.
"""

        return task
