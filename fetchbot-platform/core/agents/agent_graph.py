"""
Agent Graph System

Manages relationships between agents and enables inter-agent communication
"""

import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AgentGraph:
    """
    Global agent graph for coordinating multiple agents

    Tracks:
    - All active agents (nodes)
    - Parent-child relationships (edges)
    - Messages between agents
    - Agent status
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern - only one graph per application"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the graph (only once)"""
        if self._initialized:
            return

        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []
        self.messages: List[Dict[str, Any]] = []
        self.agents: Dict[str, Any] = {}  # agent_id -> agent instance

        # Task deduplication tracking
        # Format: task_key -> {"agent_id": str, "timestamp": str, "result": Any}
        self.executed_tasks: Dict[str, Dict[str, Any]] = {}

        self._initialized = True

        logger.info("Agent graph initialized")

    def add_agent(
        self,
        agent_id: str,
        parent_id: Optional[str],
        name: str,
        task: str,
        prompt_modules: List[str],
        agent_instance=None
    ):
        """
        Register a new agent in the graph

        Args:
            agent_id: Unique agent identifier
            parent_id: ID of parent agent (None for root agent)
            name: Human-readable agent name
            task: Task assigned to this agent
            prompt_modules: Specialized knowledge modules loaded
            agent_instance: Reference to actual agent object
        """
        self.nodes[agent_id] = {
            "id": agent_id,
            "parent_id": parent_id,
            "name": name,
            "task": task,
            "prompt_modules": prompt_modules,
            "status": "running",
            "created_at": datetime.utcnow().isoformat(),
            "findings_count": 0
        }

        if agent_instance:
            self.agents[agent_id] = agent_instance

        # Add edge to parent
        if parent_id:
            self.edges.append({
                "from": parent_id,
                "to": agent_id,
                "type": "created",
                "created_at": datetime.utcnow().isoformat()
            })

        logger.info(f"Added agent to graph: {name} (id={agent_id}, parent={parent_id})")

    def update_agent_status(self, agent_id: str, status: str, findings_count: int = 0):
        """
        Update agent status

        Args:
            agent_id: Agent to update
            status: New status (running, completed, failed)
            findings_count: Number of findings discovered
        """
        if agent_id in self.nodes:
            self.nodes[agent_id]["status"] = status
            self.nodes[agent_id]["findings_count"] = findings_count
            logger.info(f"Updated agent {agent_id}: status={status}, findings={findings_count}")

    def send_message(self, from_id: str, to_id: str, content: str, message_type: str = "info"):
        """
        Send message from one agent to another

        Args:
            from_id: Sender agent ID
            to_id: Recipient agent ID
            content: Message content
            message_type: Type of message (info, finding, request, etc.)
        """
        message = {
            "from": from_id,
            "to": to_id,
            "content": content,
            "type": message_type,
            "timestamp": datetime.utcnow().isoformat(),
            "read": False
        }

        self.messages.append(message)

        # Add edge for message
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "type": "message",
            "created_at": datetime.utcnow().isoformat()
        })

        logger.info(f"Message sent: {from_id} -> {to_id}")

    def get_agent_messages(self, agent_id: str, mark_read: bool = True) -> List[Dict[str, Any]]:
        """
        Get unread messages for an agent

        Args:
            agent_id: Agent to get messages for
            mark_read: If True, mark messages as read

        Returns:
            List of message dictionaries
        """
        agent_messages = [m for m in self.messages if m["to"] == agent_id and not m.get("read", False)]

        if mark_read:
            for msg in agent_messages:
                msg["read"] = True

        return agent_messages

    def get_children(self, agent_id: str) -> List[str]:
        """
        Get IDs of all child agents

        Args:
            agent_id: Parent agent ID

        Returns:
            List of child agent IDs
        """
        return [edge["to"] for edge in self.edges if edge["from"] == agent_id and edge["type"] == "created"]

    def get_all_agents(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all agents"""
        return self.nodes

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific agent"""
        return self.nodes.get(agent_id)

    def get_root_agents(self) -> List[Dict[str, Any]]:
        """Get all root agents (agents with no parent)"""
        return [node for node in self.nodes.values() if node["parent_id"] is None]

    def to_dict(self) -> Dict[str, Any]:
        """
        Export graph as dictionary for visualization or storage

        Returns:
            Dictionary with nodes and edges
        """
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "message_count": len(self.messages)
        }

    def get_agent_hierarchy(self, root_id: str) -> Dict[str, Any]:
        """
        Get hierarchical structure starting from a root agent

        Args:
            root_id: Root agent ID

        Returns:
            Nested dictionary showing agent hierarchy
        """
        def build_tree(agent_id: str) -> Dict[str, Any]:
            node = self.nodes.get(agent_id, {})
            children = self.get_children(agent_id)

            return {
                "id": agent_id,
                "name": node.get("name", "Unknown"),
                "status": node.get("status", "unknown"),
                "findings": node.get("findings_count", 0),
                "children": [build_tree(child_id) for child_id in children]
            }

        return build_tree(root_id)

    def _make_task_key(self, tool_name: str, params: Dict[str, Any]) -> str:
        """
        Create a unique key for a task based on tool name and parameters

        Args:
            tool_name: Name of the tool
            params: Tool parameters

        Returns:
            Unique task key string
        """
        import json
        import hashlib

        # Sort params to ensure consistent hashing
        sorted_params = json.dumps(params, sort_keys=True)
        param_hash = hashlib.md5(sorted_params.encode()).hexdigest()[:8]

        return f"{tool_name}:{param_hash}"

    def is_task_already_executed(self, tool_name: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if this task has already been executed by another agent

        Args:
            tool_name: Name of the tool
            params: Tool parameters

        Returns:
            Task execution info if already executed, None otherwise
        """
        task_key = self._make_task_key(tool_name, params)
        return self.executed_tasks.get(task_key)

    def register_task_execution(
        self,
        tool_name: str,
        params: Dict[str, Any],
        agent_id: str,
        result: Any = None
    ):
        """
        Register that a task has been executed

        Args:
            tool_name: Name of the tool executed
            params: Tool parameters
            agent_id: ID of agent that executed the task
            result: Task execution result (optional)
        """
        task_key = self._make_task_key(tool_name, params)

        self.executed_tasks[task_key] = {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "agent_name": self.nodes.get(agent_id, {}).get("name", "Unknown"),
            "timestamp": datetime.utcnow().isoformat(),
            "result_available": result is not None
        }

        logger.debug(f"Registered task execution: {task_key} by agent {agent_id}")

    def get_task_execution_stats(self) -> Dict[str, Any]:
        """Get statistics about task executions"""
        return {
            "total_tasks_executed": len(self.executed_tasks),
            "unique_tools_used": len(set(t["tool_name"] for t in self.executed_tasks.values()))
        }

    def clear(self):
        """Clear the graph (for testing or reset)"""
        self.nodes.clear()
        self.edges.clear()
        self.messages.clear()
        self.agents.clear()
        self.executed_tasks.clear()
        logger.info("Agent graph cleared")


# Global instance
_graph = AgentGraph()


def get_agent_graph() -> AgentGraph:
    """Get the global agent graph instance"""
    return _graph
