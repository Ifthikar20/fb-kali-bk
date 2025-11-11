"""
Specialized Agent Orchestrator

Coordinates multiple specialized agents to perform comprehensive security testing
without duplication.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

from .work_queue import WorkQueue
from .specialized_agent_base import AgentType

logger = logging.getLogger(__name__)


class SpecializedAgentOrchestrator:
    """
    Orchestrator that coordinates specialized security testing agents

    Responsibilities:
    - Distribute work to appropriate agent types
    - Prevent duplicate testing via work queue
    - Aggregate findings from all agents
    - Monitor agent health
    - Generate comprehensive reports
    """

    def __init__(self, target: str, job_id: str):
        """
        Initialize orchestrator

        Args:
            target: Target URL/domain to scan
            job_id: Unique job identifier
        """
        self.target = target
        self.job_id = job_id
        self.work_queue = WorkQueue()

        # Findings from all agents
        self.findings: List[Dict[str, Any]] = []

        # Agent registry: {agent_id: agent_info}
        self.agents: Dict[str, Dict[str, Any]] = {}

        # Metrics
        self.start_time = None
        self.end_time = None

        logger.info(
            f"Initialized orchestrator for target: {target} (job_id: {job_id})"
        )

    async def initialize_scan(self) -> Dict[str, Any]:
        """
        Initialize the security scan by creating initial work items

        Returns:
            Initialization status
        """
        self.start_time = datetime.utcnow()
        logger.info(f"Initializing scan for {self.target}")

        # Phase 1: Network Reconnaissance
        await self._queue_network_scan()

        # Phase 2: Web Reconnaissance
        await self._queue_web_recon()

        # Phase 3: Will be populated based on Phase 1 & 2 discoveries
        # (APIs, forms, endpoints discovered will generate more work)

        status = await self.work_queue.get_queue_status()

        logger.info(
            f"Scan initialized with {status['total_added']} initial work items"
        )

        return {
            "status": "initialized",
            "target": self.target,
            "job_id": self.job_id,
            "initial_work_items": status['total_added'],
            "work_distribution": status['pending_by_type']
        }

    async def _queue_network_scan(self):
        """Queue network reconnaissance work items"""
        # Nmap quick scan
        await self.work_queue.add_work(
            agent_type=AgentType.NETWORK.value,
            tool="nmap_scan",
            params={
                "target": self.target,
                "ports": "1-1000",
                "scan_type": "quick"
            },
            priority=10  # High priority - foundation for other scans
        )

        # DNS enumeration
        await self.work_queue.add_work(
            agent_type=AgentType.NETWORK.value,
            tool="dns_enumerate",
            params={"domain": self.target},
            priority=9
        )

    async def _queue_web_recon(self):
        """Queue web reconnaissance work items"""
        # Determine URL format
        target_url = self.target
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'

        # HTTP scan
        await self.work_queue.add_work(
            agent_type=AgentType.RECON.value,
            tool="http_scan",
            params={
                "url": target_url,
                "crawl_depth": 2,
                "extract_apis": True,
                "extract_forms": True
            },
            priority=9
        )

        # JavaScript analysis
        await self.work_queue.add_work(
            agent_type=AgentType.RECON.value,
            tool="javascript_analysis",
            params={"url": target_url},
            priority=8
        )

        # Security headers check
        await self.work_queue.add_work(
            agent_type=AgentType.RECON.value,
            tool="security_headers_check",
            params={"url": target_url},
            priority=7
        )

        # Environment variable detection
        await self.work_queue.add_work(
            agent_type=AgentType.RECON.value,
            tool="detect_exposed_env_vars",
            params={"api_url": target_url},
            priority=8
        )

    async def queue_followup_work(
        self,
        discoveries: Dict[str, Any]
    ):
        """
        Queue follow-up work based on discoveries

        Args:
            discoveries: Dictionary of discovered endpoints, APIs, forms, etc.
        """
        # Queue fuzzing for discovered endpoints
        if "endpoints" in discoveries:
            for endpoint in discoveries["endpoints"]:
                await self._queue_fuzzing_work(endpoint)

        # Queue SQL injection testing for forms with inputs
        if "forms" in discoveries:
            for form in discoveries["forms"]:
                await self._queue_sqli_work(form)

        # Queue XSS testing for forms
        if "forms" in discoveries:
            for form in discoveries["forms"]:
                await self._queue_xss_work(form)

        # Queue API security testing for discovered APIs
        if "apis" in discoveries:
            for api in discoveries["apis"]:
                await self._queue_api_security_work(api)

        # Queue authentication testing if login endpoints found
        if "auth_endpoints" in discoveries:
            for endpoint in discoveries["auth_endpoints"]:
                await self._queue_auth_work(endpoint)

    async def _queue_fuzzing_work(self, endpoint: Dict[str, Any]):
        """Queue fuzzing work for an endpoint"""
        await self.work_queue.add_work(
            agent_type=AgentType.FUZZING.value,
            tool="api_fuzzing",
            params={
                "api_url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameters": endpoint.get("params", {}),
                "fuzz_type": "comprehensive"
            },
            priority=5
        )

    async def _queue_sqli_work(self, form: Dict[str, Any]):
        """Queue SQL injection testing for a form"""
        for input_field in form.get("inputs", []):
            await self.work_queue.add_work(
                agent_type=AgentType.SQL_INJECTION.value,
                tool="sql_injection_test",
                params={
                    "url": form["action_url"],
                    "parameter": input_field["name"],
                    "technique": "error_based"
                },
                priority=7
            )

    async def _queue_xss_work(self, form: Dict[str, Any]):
        """Queue XSS testing for a form"""
        for input_field in form.get("inputs", []):
            await self.work_queue.add_work(
                agent_type=AgentType.XSS.value,
                tool="xss_test",
                params={
                    "url": form["action_url"],
                    "parameter": input_field["name"]
                },
                priority=6
            )

    async def _queue_api_security_work(self, api: Dict[str, Any]):
        """Queue API security testing"""
        # IDOR testing
        if "id_param" in api:
            await self.work_queue.add_work(
                agent_type=AgentType.AUTH.value,
                tool="api_idor_test",
                params={
                    "api_url": api["url"],
                    "id_parameter": api["id_param"],
                    "authenticated": True
                },
                priority=7
            )

        # Rate limiting test
        await self.work_queue.add_work(
            agent_type=AgentType.AUTH.value,
            tool="api_rate_limit_test",
            params={
                "api_url": api["url"],
                "method": api.get("method", "GET"),
                "request_count": 100
            },
            priority=5
        )

    async def _queue_auth_work(self, endpoint: Dict[str, Any]):
        """Queue authentication testing"""
        await self.work_queue.add_work(
            agent_type=AgentType.AUTH.value,
            tool="api_brute_force",
            params={
                "api_url": endpoint["url"],
                "username_field": "username",
                "password_field": "password",
                "password_list": "common"
            },
            priority=4
        )

    async def add_finding(
        self,
        agent_id: str,
        finding: Dict[str, Any]
    ):
        """
        Add a security finding from an agent

        Args:
            agent_id: ID of the agent that found the issue
            finding: Finding dictionary with title, severity, etc.
        """
        finding["agent_id"] = agent_id
        finding["discovered_at"] = datetime.utcnow().isoformat()
        finding["job_id"] = self.job_id

        self.findings.append(finding)

        logger.info(
            f"New finding from {agent_id}: {finding['title']} "
            f"({finding.get('severity', 'unknown')})"
        )

    async def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        tools: List[str]
    ):
        """
        Register an agent with the orchestrator

        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent (network, fuzzing, etc.)
            tools: List of tools the agent can execute
        """
        self.agents[agent_id] = {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "tools": tools,
            "registered_at": datetime.utcnow().isoformat(),
            "work_items_completed": 0,
            "status": "active"
        }

        logger.info(
            f"Registered {agent_type} agent: {agent_id} with {len(tools)} tools"
        )

    async def get_status(self) -> Dict[str, Any]:
        """
        Get orchestrator status

        Returns:
            Status dictionary with queue status, agents, findings, etc.
        """
        queue_status = await self.work_queue.get_queue_status()

        # Calculate execution time
        execution_time = None
        if self.start_time:
            end = self.end_time or datetime.utcnow()
            execution_time = (end - self.start_time).total_seconds()

        # Group findings by severity
        findings_by_severity = defaultdict(int)
        for finding in self.findings:
            severity = finding.get("severity", "unknown")
            findings_by_severity[severity] += 1

        # Group findings by agent type
        findings_by_agent_type = defaultdict(int)
        for finding in self.findings:
            for agent_id, agent_info in self.agents.items():
                if agent_id == finding.get("agent_id"):
                    findings_by_agent_type[agent_info["agent_type"]] += 1
                    break

        return {
            "job_id": self.job_id,
            "target": self.target,
            "status": "completed" if self.end_time else "running",
            "execution_time_seconds": execution_time,
            "queue_status": queue_status,
            "agents": {
                "total": len(self.agents),
                "by_type": self._count_agents_by_type(),
                "active": sum(
                    1 for a in self.agents.values()
                    if a["status"] == "active"
                )
            },
            "findings": {
                "total": len(self.findings),
                "by_severity": dict(findings_by_severity),
                "by_agent_type": dict(findings_by_agent_type)
            },
            "efficiency_metrics": {
                "duplicates_prevented": queue_status["duplicates_prevented"],
                "efficiency_percentage": queue_status["efficiency"]
            }
        }

    def _count_agents_by_type(self) -> Dict[str, int]:
        """Count agents by type"""
        counts = defaultdict(int)
        for agent in self.agents.values():
            counts[agent["agent_type"]] += 1
        return dict(counts)

    async def finalize_scan(self) -> Dict[str, Any]:
        """
        Finalize the scan and generate final report

        Returns:
            Final scan report
        """
        self.end_time = datetime.utcnow()

        logger.info(
            f"Finalizing scan for {self.target}. "
            f"Total findings: {len(self.findings)}"
        )

        # Get final status
        status = await self.get_status()

        # Add findings to status
        status["findings_details"] = self.findings

        return status

    async def get_work_for_agent(
        self,
        agent_id: str,
        agent_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get next work item for an agent

        Args:
            agent_id: ID of the requesting agent
            agent_type: Type of the requesting agent

        Returns:
            Work item or None if no work available
        """
        work_item = await self.work_queue.get_work(agent_type)

        if work_item:
            logger.info(
                f"Assigned {work_item['tool']} to agent {agent_id}"
            )

        return work_item

    async def report_work_completion(
        self,
        agent_id: str,
        work_item: Dict[str, Any],
        result: Dict[str, Any]
    ):
        """
        Report work item completion from an agent

        Args:
            agent_id: ID of the agent
            work_item: The completed work item
            result: Result of the work item
        """
        # Mark work as completed in queue
        await self.work_queue.mark_completed(work_item, result)

        # Update agent stats
        if agent_id in self.agents:
            self.agents[agent_id]["work_items_completed"] += 1

        # Extract and store findings
        if "findings" in result:
            for finding in result["findings"]:
                await self.add_finding(agent_id, finding)

        # Check if result includes discoveries that need follow-up work
        if "discoveries" in result:
            await self.queue_followup_work(result["discoveries"])

    async def report_work_failure(
        self,
        agent_id: str,
        work_item: Dict[str, Any],
        error: str
    ):
        """
        Report work item failure from an agent

        Args:
            agent_id: ID of the agent
            work_item: The failed work item
            error: Error message
        """
        logger.warning(
            f"Work item failed by agent {agent_id}: {work_item['tool']}: {error}"
        )

        # Mark as failed with retry
        await self.work_queue.mark_failed(work_item, error, retry=True)

    def __repr__(self) -> str:
        return (
            f"<SpecializedAgentOrchestrator "
            f"target={self.target} job_id={self.job_id} "
            f"agents={len(self.agents)} findings={len(self.findings)}>"
        )
