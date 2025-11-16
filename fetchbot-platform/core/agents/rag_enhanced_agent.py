"""
RAG-Enhanced Agent Wrapper

Adds intelligent context retrieval and tool suggestion capabilities to agents.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .base_agent import BaseAgent
from ..rag.models import ScanContext, ToolSuggestion
from ..rag.retrieval_service import get_rag_service
from ..rag.embeddings_service import get_embeddings_service
from ..rag.vector_store import get_vector_store
from config import get_settings

logger = logging.getLogger(__name__)


class RAGEnhancedAgent(BaseAgent):
    """
    Agent with RAG (Retrieval-Augmented Generation) capabilities.

    Enhances the base agent with:
    - Context-aware tool suggestions
    - Historical execution pattern matching
    - Intelligent prompt augmentation
    - Automatic learning from execution results
    """

    def __init__(
        self,
        config: Dict[str, Any],
        agent_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        name: str = "RAG Agent",
        task: str = "",
        enable_rag: Optional[bool] = None
    ):
        """
        Initialize RAG-enhanced agent.

        Args:
            config: Agent configuration
            agent_id: Agent ID
            parent_id: Parent agent ID
            name: Agent name
            task: Task description
            enable_rag: Override to enable/disable RAG (defaults to config setting)
        """
        super().__init__(config, agent_id, parent_id, name, task)

        # RAG configuration
        settings = get_settings()
        self.rag_enabled = enable_rag if enable_rag is not None else settings.rag_enabled

        if self.rag_enabled:
            try:
                # Initialize RAG services
                self.embeddings_service = get_embeddings_service(
                    model_name=settings.rag_embedding_model,
                    use_openai=settings.rag_use_openai_embeddings,
                    openai_api_key=settings.openai_api_key
                )
                self.vector_store = get_vector_store(
                    persist_directory=settings.rag_chroma_persist_dir
                )
                self.rag_service = get_rag_service(
                    embeddings_service=self.embeddings_service,
                    vector_store=self.vector_store,
                    confidence_threshold=settings.rag_confidence_threshold
                )

                logger.info(f"RAG enabled for agent {self.name}")

            except Exception as e:
                logger.error(f"Failed to initialize RAG services: {e}")
                self.rag_enabled = False
        else:
            logger.info(f"RAG disabled for agent {self.name}")

        # Track RAG suggestions for feedback
        self.rag_suggestions: List[ToolSuggestion] = []
        self.tools_used_history: List[str] = []

    async def agent_loop(self, task: str) -> Dict[str, Any]:
        """
        Enhanced agent loop with RAG integration.

        Args:
            task: Task description

        Returns:
            Final result dictionary
        """
        # Add initial task to conversation
        self.state.add_message("user", task)
        self.state.task = task

        logger.info(f"Agent {self.name} starting task with RAG: {task[:100]}...")

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

                # RAG: Retrieve relevant context before LLM call
                rag_context = None
                if self.rag_enabled:
                    try:
                        rag_context = await self._retrieve_rag_context()
                    except Exception as e:
                        logger.error(f"RAG context retrieval failed: {e}")

                # Generate LLM response (with RAG-enhanced prompt if available)
                try:
                    # Build enhanced system prompt if RAG context exists
                    system_prompt_override = None
                    if rag_context and len(rag_context) > 0:
                        system_prompt_override = await self.rag_service.augment_agent_prompt(
                            base_prompt=self.llm._build_system_prompt(),
                            retrieved_contexts=rag_context
                        )

                    response = await self.llm.generate(
                        self.state.get_conversation_history(),
                        scan_id=str(self.agent_id),
                        step_number=self.state.iteration,
                        system_prompt_override=system_prompt_override
                    )

                    # Add assistant response to history
                    self.state.add_message("assistant", response.content)

                    # Log thinking if present
                    if response.thinking:
                        logger.debug(f"Agent {self.name} thinking: {response.thinking[:200]}...")

                    # Process tool invocations
                    from ..tools.executor import process_tool_invocations
                    should_finish = await process_tool_invocations(
                        response.tool_invocations,
                        self.state.conversation_history,
                        self.state
                    )

                    # RAG: Store tool executions for future learning
                    if self.rag_enabled and response.tool_invocations:
                        try:
                            await self._store_tool_executions(response.tool_invocations)
                        except Exception as e:
                            logger.error(f"Failed to store tool executions in RAG: {e}")

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
        from .agent_graph import get_agent_graph
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

    async def _retrieve_rag_context(self) -> List[Any]:
        """
        Retrieve relevant context from RAG knowledge base.

        Returns:
            List of retrieval results
        """
        if not self.rag_enabled:
            return []

        try:
            # Build scan context
            scan_context = self._build_scan_context()

            # Get tool suggestions
            suggestions = await self.rag_service.suggest_tools(
                scan_context=scan_context,
                max_suggestions=5
            )

            # Store suggestions for potential feedback
            self.rag_suggestions = suggestions

            # Log suggestions
            if suggestions:
                logger.info(f"RAG suggested {len(suggestions)} tools:")
                for i, suggestion in enumerate(suggestions[:3], 1):
                    logger.info(
                        f"  {i}. {suggestion.tool_name} "
                        f"(confidence: {suggestion.confidence:.2f})"
                    )

            # Query general tool knowledge
            query = scan_context.to_query_text()
            tool_knowledge = await self.rag_service.query_tool_knowledge(
                query=query,
                target_info={"url": self.state.target},
                current_findings=[f.to_dict() if hasattr(f, 'to_dict') else f for f in self.state.get_findings()],
                agent_context={"name": self.name, "modules": self.llm_config.prompt_modules},
                top_k=5
            )

            # Combine all contexts
            all_contexts = tool_knowledge

            return all_contexts

        except Exception as e:
            logger.error(f"Failed to retrieve RAG context: {e}")
            return []

    def _build_scan_context(self) -> ScanContext:
        """
        Build current scan context for RAG queries.

        Returns:
            ScanContext object
        """
        # Extract tech stack from metadata
        tech_stack = self.state.metadata.get("tech_stack_detected", [])

        # Get findings
        findings = [
            {
                "severity": f.get("severity", "unknown"),
                "type": f.get("vulnerability_type", "unknown"),
                "title": f.get("title", "")
            }
            for f in self.state.get_findings()
        ]

        # Get tools used (from conversation history)
        tools_used = self._extract_tools_from_history()

        return ScanContext(
            target_url=self.state.target or "",
            current_findings=findings,
            tech_stack_detected=tech_stack,
            previous_tools_used=tools_used,
            agent_specialization=self.llm_config.prompt_modules,
            scan_id=self.state.job_id,
            organization_id=None  # Would need to be passed in config
        )

    def _extract_tools_from_history(self) -> List[str]:
        """
        Extract tool names from conversation history.

        Returns:
            List of tool names used
        """
        tools = []

        for message in self.state.conversation_history:
            if message.get("role") == "assistant":
                # Look for tool use in content
                # This is simplified - in practice would parse tool_use blocks
                content = str(message.get("content", ""))
                # Basic extraction (would be more sophisticated in practice)
                if "tool_use" in content.lower():
                    # Extract tool names from tool_use blocks
                    pass

        return tools

    async def _store_tool_executions(self, tool_invocations: List[Any]):
        """
        Store tool execution results in RAG database for future learning.

        Args:
            tool_invocations: List of tool invocations with results
        """
        if not self.rag_enabled:
            return

        for invocation in tool_invocations:
            try:
                # Extract execution data
                execution_data = {
                    "tool_name": invocation.get("tool_name", "unknown"),
                    "target_url": self.state.target,
                    "parameters": invocation.get("input", {}),
                    "result": invocation.get("result", ""),
                    "success": invocation.get("success", False),
                    "findings": self._extract_findings_from_invocation(invocation),
                    "execution_time": invocation.get("execution_time", 0.0),
                    "agent_name": self.name,
                    "scan_id": str(self.agent_id),
                    "timestamp": datetime.utcnow().isoformat(),
                    "tech_stack": self.state.metadata.get("tech_stack_detected", [])
                }

                # Calculate severity distribution
                findings = execution_data["findings"]
                severity_dist = {}
                for finding in findings:
                    severity = finding.get("severity", "info")
                    severity_dist[severity] = severity_dist.get(severity, 0) + 1

                execution_data["severity_distribution"] = severity_dist
                execution_data["findings_count"] = len(findings)

                # Store in RAG database
                doc_id = await self.rag_service.store_execution(execution_data)

                logger.debug(f"Stored tool execution {doc_id} in RAG database")

            except Exception as e:
                logger.error(f"Failed to store tool execution in RAG: {e}")

    def _extract_findings_from_invocation(self, invocation: Dict[str, Any]) -> List[Dict]:
        """
        Extract findings from tool invocation result.

        Args:
            invocation: Tool invocation data

        Returns:
            List of finding dictionaries
        """
        # This would parse the tool result and extract any new findings
        # For now, return empty list
        # In practice, would parse result text/JSON for vulnerability indicators
        return []


def create_rag_agent(
    config: Dict[str, Any],
    agent_id: Optional[str] = None,
    parent_id: Optional[str] = None,
    name: str = "RAG Agent",
    task: str = ""
) -> RAGEnhancedAgent:
    """
    Factory function to create RAG-enhanced agent.

    Args:
        config: Agent configuration
        agent_id: Agent ID
        parent_id: Parent agent ID
        name: Agent name
        task: Task description

    Returns:
        RAGEnhancedAgent instance
    """
    return RAGEnhancedAgent(
        config=config,
        agent_id=agent_id,
        parent_id=parent_id,
        name=name,
        task=task
    )
