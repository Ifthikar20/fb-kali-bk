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

        super().__init__(
            config=config,
            agent_id=job_id,  # Use job_id as root agent ID
            parent_id=None,  # No parent - this is root
            name="Root Coordinator",
            task=f"Conduct comprehensive security assessment of {target}"
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
Conduct a thorough security assessment by creating and coordinating specialized agents.
You do NOT perform scans directly - you delegate to specialized agents.

STRATEGY:

1. START WITH RECONNAISSANCE
   - Create a reconnaissance agent to understand the target
   - This agent should use: http_scan, dns_enumerate, resolve_domain
   - Wait for recon results before proceeding

2. ANALYZE RECONNAISSANCE RESULTS
   When recon completes, you'll receive a message with findings.
   Based on what's discovered, create specialized agents:

   IF APIs DISCOVERED:
   - Create "API Security Agent" with modules: api_testing
   - Task: Test API endpoints for:
     * Fuzzing (api_fuzzing)
     * Brute force (api_brute_force)
     * IDOR (api_idor_test)
     * Rate limiting (api_rate_limit_test)
     * Environment variables (detect_exposed_env_vars)

   IF DATABASE DETECTED (MySQL, PostgreSQL, etc.):
   - Create "SQL Injection Agent" with modules: sql_injection
   - Task: Test for SQL injection using sql_injection_test and sqlmap_test

   IF FORMS/INPUTS FOUND:
   - Create "XSS Testing Agent" with modules: xss
   - Task: Test for XSS vulnerabilities using xss_test

   IF AUTHENTICATION ENDPOINTS FOUND:
   - Create "Authentication Testing Agent" with modules: authentication
   - Task: Test auth security, brute force resistance, session management

   IF OPEN PORTS FOUND (from network scan):
   - Create agents for specific services (SSH, FTP, etc.)

   IF ENVIRONMENT VARIABLES EXPOSED:
   - Use detect_exposed_env_vars and scan_env_files
   - Create vulnerability reports for any secrets found

3. MONITOR AGENT PROGRESS
   - Use get_my_agents to check on created agents
   - Use get_scan_status to see overall progress
   - Read messages from agents (they'll notify you when done)

4. MAKE STRATEGIC DECISIONS
   - Don't create duplicate agents
   - Prioritize high-impact tests
   - If agents find nothing, move on
   - Create follow-up agents based on discoveries

5. AGGREGATE AND FINISH
   - Once all agents complete, review findings
   - Use finish_scan to mark assessment complete
   - Provide summary of what was tested

IMPORTANT RULES:
- Do NOT use scanning tools yourself - create agents for that
- Create agents with SPECIFIC tasks and relevant modules
- Name agents clearly (e.g., "API Fuzzing Agent", "SQL Injection Agent")
- Wait for reconnaissance before creating specialized agents
- Use tool invocations to create agents and check status

BEGIN by creating a reconnaissance agent to discover the target's attack surface.
"""

        return task
