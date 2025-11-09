"""
Base Agent Class

Core agent implementation with continuous execution loop
"""

import asyncio
import logging
from typing import Dict, Any, Optional
import uuid

from .state import AgentState
from .agent_graph import get_agent_graph
from ..llm.config import LLMConfig
from ..llm.llm import LLM
from ..tools.executor import process_tool_invocations

logger = logging.getLogger(__name__)


class BaseAgent:
    """
    Base agent with continuous execution loop

    All agents (root coordinator and specialized agents) inherit from this class.

    The agent loop:
    1. Check for messages from other agents
    2. Make LLM request with conversation history
    3. Parse tool invocations from response
    4. Execute tools
    5. Add results to conversation history
    6. Repeat until completion or max iterations
    """

    def __init__(
        self,
        config: Dict[str, Any],
        agent_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        name: str = "Agent",
        task: str = ""
    ):
        """
        Initialize agent

        Args:
            config: Agent configuration dict with:
                - llm_config: LLMConfig instance
                - max_iterations: Max loop iterations (default: 50)
                - sandbox_url: Docker container URL for tool execution
            agent_id: Unique agent ID (generated if not provided)
            parent_id: Parent agent ID (None for root agent)
            name: Human-readable agent name
            task: Task assigned to this agent
        """
        self.agent_id = agent_id or str(uuid.uuid4())
        self.parent_id = parent_id
        self.name = name
        self.task = task

        # Extract configuration
        self.llm_config: LLMConfig = config["llm_config"]
        self.max_iterations = config.get("max_iterations", 50)
        sandbox_url = config.get("sandbox_url", "http://kali-agent-1:9000")

        # Initialize state
        self.state = AgentState(
            agent_id=self.agent_id,
            parent_id=self.parent_id,
            task=task,
            sandbox_url=sandbox_url
        )
        self.state.max_iterations = self.max_iterations

        # Initialize LLM
        self.llm = LLM(self.llm_config)

        # Register in agent graph
        graph = get_agent_graph()
        graph.add_agent(
            agent_id=self.agent_id,
            parent_id=self.parent_id,
            name=self.name,
            task=self.task,
            prompt_modules=self.llm_config.prompt_modules,
            agent_instance=self
        )

        logger.info(
            f"Initialized agent: {self.name} "
            f"(id={self.agent_id}, modules={self.llm_config.prompt_modules})"
        )

    async def agent_loop(self, task: str) -> Dict[str, Any]:
        """
        Main agent execution loop

        Args:
            task: Task description for this agent

        Returns:
            Final result dictionary with findings and status
        """
        # Add initial task to conversation
        self.state.add_message("user", task)
        self.state.task = task

        logger.info(f"Agent {self.name} starting task: {task[:100]}...")

        try:
            while True:
                # Check if should stop
                if self.state.should_stop():
                    logger.warning(f"Agent {self.name} reached max iterations")
                    self.state.set_final_result({
                        "status": "max_iterations",
                        "findings": self.state.get_findings(),
                        "message": "Reached maximum iteration limit"
                    })
                    break

                # Check for messages from other agents
                self._check_agent_messages()

                # Increment iteration
                self.state.increment_iteration()
                logger.debug(
                    f"Agent {self.name} iteration {self.state.iteration}/{self.max_iterations}"
                )

                # Generate LLM response
                try:
                    response = await self.llm.generate(
                        self.state.get_conversation_history(),
                        scan_id=str(self.agent_id),
                        step_number=self.state.iteration
                    )

                    # Add assistant response to history
                    self.state.add_message("assistant", response.content)

                    # Log thinking if present
                    if response.thinking:
                        logger.debug(f"Agent {self.name} thinking: {response.thinking[:200]}...")

                    # Process tool invocations
                    should_finish = await process_tool_invocations(
                        response.tool_invocations,
                        self.state.conversation_history,
                        self.state
                    )

                    if should_finish:
                        logger.info(f"Agent {self.name} completed task")
                        break

                except Exception as e:
                    logger.error(f"Agent {self.name} LLM request failed: {e}")
                    self.state.set_failed(str(e))
                    break

        except Exception as e:
            logger.error(f"Agent {self.name} execution failed: {e}", exc_info=True)
            self.state.set_failed(str(e))

        # Update agent graph
        graph = get_agent_graph()
        graph.update_agent_status(
            self.agent_id,
            self.state.status,
            len(self.state.get_findings())
        )

        return self.state.final_result or {
            "status": self.state.status,
            "findings": self.state.get_findings(),
            "iterations": self.state.iteration
        }

    def _check_agent_messages(self):
        """
        Check for messages from other agents and add to conversation history
        """
        graph = get_agent_graph()
        messages = graph.get_agent_messages(self.agent_id, mark_read=True)

        for msg in messages:
            message_content = f"""<agent_message>
<from>{msg['from']}</from>
<type>{msg['type']}</type>
<content>{msg['content']}</content>
</agent_message>"""

            self.state.add_message("user", message_content)
            logger.debug(f"Agent {self.name} received message from {msg['from']}")

    async def run(self, task: str) -> Dict[str, Any]:
        """
        Run the agent with a task (public interface)

        Args:
            task: Task description

        Returns:
            Final result dictionary
        """
        return await self.agent_loop(task)

    def get_state(self) -> AgentState:
        """Get current agent state"""
        return self.state

    def get_findings(self) -> list:
        """Get all findings discovered by this agent"""
        return self.state.get_findings()

    def add_finding(self, finding: Dict[str, Any]):
        """Add a vulnerability finding"""
        self.state.add_finding(finding)

        # Update agent graph
        graph = get_agent_graph()
        graph.update_agent_status(
            self.agent_id,
            self.state.status,
            len(self.state.get_findings())
        )

    def to_dict(self) -> Dict[str, Any]:
        """Export agent info as dictionary"""
        return {
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "task": self.task,
            "status": self.state.status,
            "prompt_modules": self.llm_config.prompt_modules,
            "iterations": self.state.iteration,
            "findings_count": len(self.state.get_findings())
        }
