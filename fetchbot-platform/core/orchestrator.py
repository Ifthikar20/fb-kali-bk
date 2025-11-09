"""
Dynamic Orchestrator

Replaces BotOrchestrator with dynamic multi-agent architecture
"""

import asyncio
import logging
from typing import Dict, Any, List
from datetime import datetime

from .agents.root_agent import RootAgent
from .agents.agent_graph import get_agent_graph
from .utils.logging import log_scan_status

logger = logging.getLogger(__name__)


class DynamicOrchestrator:
    """
    Dynamic orchestrator using multi-agent architecture

    Key Differences from BotOrchestrator:
    - No fixed bots (network, ui, db)
    - Claude decides what agents to create
    - Agents created dynamically based on discoveries
    - Each agent has specialized expertise via prompt modules
    """

    def __init__(self, org_elastic_ip: str = None):
        """
        Initialize dynamic orchestrator

        Args:
            org_elastic_ip: Organization's elastic IP (for compatibility with existing API)
        """
        self.org_elastic_ip = org_elastic_ip
        logger.info("Dynamic orchestrator initialized")

    async def run_scan(
        self,
        target: str,
        job_id: str,
        organization_id: int = None,
        db_url: str = None
    ) -> Dict[str, Any]:
        """
        Run complete security assessment using dynamic agents

        Args:
            target: Target URL, domain, or IP
            job_id: Unique job identifier
            organization_id: Organization ID (optional)
            db_url: Database URL for logging (optional)

        Returns:
            Dictionary with:
            - status: Scan status
            - findings: All discovered vulnerabilities
            - agents_created: List of agents that were created
            - execution_time: How long the scan took
        """
        start_time = datetime.utcnow()

        logger.info(f"Starting dynamic scan for target: {target} (job_id: {job_id})")

        # Log scan start
        log_scan_status(
            job_id=job_id,
            status="started",
            details=f"Initializing security assessment for {target}",
            db_url=db_url
        )

        try:
            # Create root coordinator agent
            root_agent = RootAgent(target=target, job_id=job_id, db_url=db_url)

            log_scan_status(
                job_id=job_id,
                status="running",
                details="Root coordinator agent created, beginning analysis",
                db_url=db_url
            )

            # Run assessment
            result = await root_agent.run_assessment()

            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            # Log scan completion
            log_scan_status(
                job_id=job_id,
                status="completed",
                details=f"Assessment complete. Found {result['total_findings']} vulnerabilities "
                       f"({result['critical_findings']} critical, {result['high_findings']} high) "
                       f"in {execution_time:.1f}s",
                db_url=db_url
            )

            # Format result
            return {
                "status": "completed",
                "target": target,
                "job_id": job_id,
                "findings": result["findings"],
                "agents_created": result["agents_created"],
                "total_findings": result["total_findings"],
                "critical_findings": result["critical_findings"],
                "high_findings": result["high_findings"],
                "execution_time_seconds": execution_time,
                "completed_at": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Dynamic scan failed for {target}: {e}", exc_info=True)

            # Log scan failure
            log_scan_status(
                job_id=job_id,
                status="failed",
                details=f"Assessment failed: {str(e)}",
                db_url=db_url
            )

            return {
                "status": "failed",
                "target": target,
                "job_id": job_id,
                "error": str(e),
                "findings": [],
                "execution_time_seconds": (datetime.utcnow() - start_time).total_seconds()
            }

    async def get_agent_graph(self, job_id: str) -> Dict[str, Any]:
        """
        Get agent graph for visualization

        Args:
            job_id: Job identifier

        Returns:
            Agent graph with nodes and edges
        """
        graph = get_agent_graph()

        return {
            "job_id": job_id,
            "graph": graph.to_dict(),
            "hierarchy": graph.get_agent_hierarchy(job_id) if job_id in graph.nodes else None
        }

    async def get_agent_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get current status of all agents for a job

        Args:
            job_id: Job identifier

        Returns:
            Status of all agents
        """
        graph = get_agent_graph()
        all_agents = graph.get_all_agents()

        # Filter agents for this job (root agent ID = job_id)
        job_agents = {
            agent_id: info
            for agent_id, info in all_agents.items()
            if agent_id == job_id or info.get("parent_id") == job_id
        }

        return {
            "job_id": job_id,
            "agents": list(job_agents.values()),
            "total_agents": len(job_agents),
            "running": len([a for a in job_agents.values() if a["status"] == "running"]),
            "completed": len([a for a in job_agents.values() if a["status"] == "completed"]),
            "failed": len([a for a in job_agents.values() if a["status"] == "failed"])
        }

    def _format_findings_for_db(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format findings for database storage

        Args:
            findings: Raw findings from agents

        Returns:
            Formatted findings compatible with existing Finding model
        """
        formatted = []

        for finding in findings:
            formatted.append({
                "title": finding.get("title", "Untitled Finding"),
                "severity": finding.get("severity", "MEDIUM"),
                "type": finding.get("type", "UNKNOWN"),
                "description": finding.get("description", ""),
                "affected_url": finding.get("affected_url", ""),
                "payload": finding.get("payload", ""),
                "evidence": finding.get("evidence", ""),
                "remediation": finding.get("remediation", ""),
                "discovered_at": finding.get("discovered_at", datetime.utcnow().isoformat())
            })

        return formatted
