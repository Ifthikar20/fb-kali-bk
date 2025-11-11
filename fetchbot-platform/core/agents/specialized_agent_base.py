"""
Base class for specialized security testing agents

Each specialized agent focuses on one domain (network, fuzzing, SQLi, etc.)
and only has access to tools relevant to its specialty.
"""

import asyncio
import logging
import httpx
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AgentType(Enum):
    """Types of specialized agents"""
    NETWORK = "network"
    FUZZING = "fuzzing"
    SQL_INJECTION = "sqli"
    NOSQL_INJECTION = "nosqli"
    XSS = "xss"
    AUTH = "auth"
    RECON = "recon"
    WEB_VULN = "webvuln"
    API_SECURITY = "apisec"


class WorkItemStatus(Enum):
    """Status of work items"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class BaseSpecializedAgent(ABC):
    """
    Base class for all specialized security testing agents

    Each agent:
    - Has a specific agent_type (network, fuzzing, sqli, etc.)
    - Only executes tools relevant to its specialty
    - Reports findings back to orchestrator
    - Pulls work from orchestrator's work queue
    - Avoids duplicate testing via orchestrator coordination
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        orchestrator_url: str,
        tools: List[str]
    ):
        """
        Initialize specialized agent

        Args:
            agent_id: Unique identifier for this agent instance
            agent_type: Type of specialized agent
            orchestrator_url: URL of the orchestrator service
            tools: List of tool names this agent can execute
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.orchestrator_url = orchestrator_url
        self.tools = set(tools)
        self.running = False
        self.work_items_completed = 0
        self.findings = []

        logger.info(
            f"Initialized {agent_type.value} agent: {agent_id} with tools: {tools}"
        )

    @abstractmethod
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a specific tool with given parameters

        Args:
            tool_name: Name of the tool to execute
            params: Parameters for the tool

        Returns:
            Dictionary with tool execution results
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Get the system prompt for this specialized agent

        Returns:
            System prompt describing agent's expertise and capabilities
        """
        pass

    async def start(self):
        """
        Start the agent's work loop

        Agent will continuously:
        1. Pull work from orchestrator
        2. Execute work items
        3. Report findings
        4. Request more work
        """
        self.running = True
        logger.info(f"[{self.agent_id}] Starting work loop")

        while self.running:
            try:
                # Pull next work item from orchestrator
                work_response = await self._get_work()

                if not work_response or not work_response.get("work_item"):
                    # No work available - check if scans are active
                    scan_active = work_response.get("scan_active", False) if work_response else False

                    if scan_active:
                        # Scans are active but no work for us yet - poll actively
                        await asyncio.sleep(2)
                    else:
                        # No active scans - enter idle mode (poll every 30s)
                        logger.debug(f"[{self.agent_id}] No active scans, entering idle mode...")
                        await asyncio.sleep(30)

                    continue

                work_item = work_response["work_item"]

                # Execute work item
                logger.info(
                    f"[{self.agent_id}] Executing work item: {work_item['tool']}"
                )

                result = await self._execute_work_item(work_item)

                # Report completion and findings
                await self._report_completion(work_item, result)

                self.work_items_completed += 1

            except Exception as e:
                logger.error(f"[{self.agent_id}] Error in work loop: {e}", exc_info=True)
                await asyncio.sleep(1)

    async def stop(self):
        """Stop the agent's work loop"""
        logger.info(f"[{self.agent_id}] Stopping...")
        self.running = False

    async def _get_work(self) -> Optional[Dict[str, Any]]:
        """
        Pull next work item from orchestrator

        Returns:
            Response dict with work_item and scan status, or None on error
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.orchestrator_url}/work/get",
                    json={
                        "agent_id": self.agent_id,
                        "agent_type": self.agent_type.value
                    }
                )

                if response.status_code == 200:
                    # Return full response (includes work_item, active_scans, scan_active)
                    return response.json()
                elif response.status_code == 204:
                    # No work available
                    return {"work_item": None, "scan_active": False}
                else:
                    logger.error(
                        f"[{self.agent_id}] Failed to get work: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"[{self.agent_id}] Error getting work: {e}")
            return None

    async def _execute_work_item(self, work_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a work item

        Args:
            work_item: Work item containing tool and params

        Returns:
            Result dictionary with findings
        """
        tool_name = work_item["tool"]
        params = work_item.get("params", {})

        # Verify tool is in our toolkit
        if tool_name not in self.tools:
            logger.error(
                f"[{self.agent_id}] Cannot execute {tool_name} - not in toolkit"
            )
            return {
                "success": False,
                "error": f"Tool {tool_name} not available to {self.agent_type.value} agent"
            }

        try:
            # Execute the tool
            result = await self.execute_tool(tool_name, params)

            # Extract findings if any
            findings = self._extract_findings(tool_name, result)

            return {
                "success": True,
                "tool": tool_name,
                "params": params,
                "result": result,
                "findings": findings,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(
                f"[{self.agent_id}] Error executing {tool_name}: {e}",
                exc_info=True
            )
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def _extract_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract security findings from tool result

        Args:
            tool_name: Name of the tool that was executed
            result: Raw tool result

        Returns:
            List of findings
        """
        # Default implementation - subclasses can override
        findings = []

        # Check for common finding patterns
        if result.get("vulnerable"):
            findings.append({
                "title": f"Vulnerability found by {tool_name}",
                "severity": result.get("severity", "medium"),
                "type": tool_name,
                "description": result.get("description", ""),
                "evidence": result.get("evidence", {}),
                "agent_id": self.agent_id,
                "agent_type": self.agent_type.value
            })

        return findings

    async def _report_completion(
        self,
        work_item: Dict[str, Any],
        result: Dict[str, Any]
    ):
        """
        Report work item completion to orchestrator

        Args:
            work_item: The completed work item
            result: Result of executing the work item
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{self.orchestrator_url}/work/complete",
                    json={
                        "agent_id": self.agent_id,
                        "agent_type": self.agent_type.value,
                        "work_item": work_item,
                        "result": result
                    }
                )

            logger.info(
                f"[{self.agent_id}] Reported completion of {work_item['tool']}"
            )

        except Exception as e:
            logger.error(
                f"[{self.agent_id}] Error reporting completion: {e}"
            )

    async def health_check(self) -> Dict[str, Any]:
        """
        Return agent health status

        Returns:
            Health status dictionary
        """
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "status": "running" if self.running else "stopped",
            "work_items_completed": self.work_items_completed,
            "findings_count": len(self.findings),
            "tools": list(self.tools)
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"id={self.agent_id} type={self.agent_type.value} "
            f"tools={len(self.tools)}>"
        )
