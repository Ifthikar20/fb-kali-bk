"""
Agent State Management

Manages the state of each agent including conversation history, findings, and metadata
"""

import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AgentState:
    """
    Manages state for a single agent

    Tracks:
    - Conversation history with LLM
    - Findings/vulnerabilities discovered
    - Iteration count
    - Metadata (agent_id, parent_id, etc.)
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        task: str = "",
        sandbox_url: str = "http://kali-agent-1:9000",
        auth_token: Optional[str] = None,
        db_url: Optional[str] = None,
        job_id: Optional[str] = None,
        target: Optional[str] = None,
        sandbox_urls: Optional[list] = None
    ):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.parent_id = parent_id
        self.task = task
        self.sandbox_url = sandbox_url
        self.sandbox_urls = sandbox_urls or [sandbox_url]  # Store all available URLs
        self.auth_token = auth_token or self._generate_token()
        self.db_url = db_url
        self.job_id = job_id or agent_id  # Default job_id to agent_id
        self.target = target  # Target URL/domain for this scan

        # Conversation history with LLM
        self.conversation_history: List[Dict[str, str]] = []

        # Findings discovered by this agent
        self.findings: List[Dict[str, Any]] = []

        # Iteration tracking
        self.iteration = 0
        self.max_iterations = 50

        # Status
        self.status = "running"  # running, completed, failed
        self.final_result: Optional[Dict[str, Any]] = None

        # Metadata
        self.created_at = datetime.utcnow()
        self.metadata: Dict[str, Any] = {}

    def _generate_token(self) -> str:
        """Generate auth token for sandbox communication"""
        return str(uuid.uuid4())

    def add_message(self, role: str, content: str):
        """
        Add message to conversation history

        Args:
            role: "user" or "assistant"
            content: Message content
        """
        self.conversation_history.append({
            "role": role,
            "content": content
        })

    def get_conversation_history(self) -> List[Dict[str, str]]:
        """Get complete conversation history"""
        return self.conversation_history

    def increment_iteration(self):
        """Increment iteration counter"""
        self.iteration += 1

    def should_stop(self) -> bool:
        """Check if agent should stop (max iterations reached)"""
        return self.iteration >= self.max_iterations

    def add_finding(self, finding: Dict[str, Any]):
        """
        Add a vulnerability finding

        Args:
            finding: Dictionary with keys:
                - title: Finding title
                - severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
                - type: Vulnerability type (SQL_INJECTION, XSS, etc.)
                - description: Detailed description
                - payload: Attack payload used
                - evidence: Proof of exploitation
                - remediation: Fix recommendations
        """
        finding["discovered_by"] = self.agent_id
        finding["discovered_at"] = datetime.utcnow().isoformat()
        self.findings.append(finding)
        logger.info(f"Agent {self.agent_id} added finding: {finding['title']}")

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings discovered by this agent"""
        return self.findings

    def set_final_result(self, result: Dict[str, Any]):
        """
        Set final result when agent completes

        Args:
            result: Final result dictionary
        """
        self.final_result = result
        self.status = "completed"

    def set_failed(self, error: str):
        """Mark agent as failed"""
        self.status = "failed"
        self.final_result = {"error": error}

    def get(self, key: str, default=None):
        """Get state value by key (for compatibility with dict-like access)"""
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary"""
        return {
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "task": self.task,
            "status": self.status,
            "iteration": self.iteration,
            "findings_count": len(self.findings),
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }
