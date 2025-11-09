"""
Tool Execution System

Handles executing tools either locally (coordination tools) or in sandbox (scanning tools)
"""

import httpx
import asyncio
import logging
from typing import Dict, Any, Optional
from .registry import get_tool, _TOOL_REGISTRY
from ..utils.logging import log_tool_execution
from ..agents.agent_graph import get_agent_graph

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Raised when tool execution fails"""
    pass


async def execute_tool(
    tool_name: str,
    agent_state,
    **kwargs
) -> Any:
    """
    Execute a tool by name with given parameters

    Args:
        tool_name: Name of the tool to execute
        agent_state: Current agent state (for context)
        **kwargs: Tool-specific parameters

    Returns:
        Tool execution result

    Raises:
        ToolExecutionError: If tool not found or execution fails
    """
    tool_info = get_tool(tool_name)

    if not tool_info:
        raise ToolExecutionError(f"Tool '{tool_name}' not found in registry")

    sandbox_execution = tool_info.get("sandbox_execution", False)

    # Auto-inject target parameter if not provided and agent has a target
    if sandbox_execution and hasattr(agent_state, 'target') and agent_state.target:
        # If target-like parameter is not already provided, inject it
        if not any(k in kwargs for k in ['target', 'url', 'domain', 'ip', 'host']):
            # Determine the appropriate parameter name for this tool
            # Most tools use 'target', but some use 'url' or 'domain'
            if 'dns' in tool_name.lower():
                kwargs['domain'] = agent_state.target
            elif 'resolve' in tool_name.lower():
                kwargs['domain'] = agent_state.target
            elif 'http' in tool_name.lower() or 'api' in tool_name.lower():
                kwargs['url'] = agent_state.target
            else:
                kwargs['target'] = agent_state.target

            logger.debug(f"Auto-injected target '{agent_state.target}' into tool '{tool_name}'")

    try:
        # Log tool execution for sandbox tools (security scanning tools)
        if sandbox_execution and hasattr(agent_state, 'job_id') and hasattr(agent_state, 'db_url'):
            # Get agent name for logging
            graph = get_agent_graph()
            agent_info = graph.get_agent_info(agent_state.agent_id)
            agent_name = agent_info.get("name", "Unknown") if agent_info else "Unknown"

            # Get target from kwargs (now includes auto-injected target)
            target = kwargs.get("target") or kwargs.get("url") or kwargs.get("domain") or agent_state.target or "target"

            # Log the tool execution
            log_tool_execution(
                job_id=agent_state.job_id,
                tool_name=tool_name,
                agent_name=agent_name,
                target=target,
                db_url=agent_state.db_url
            )

        if sandbox_execution:
            # Execute in Docker container
            result = await _execute_in_sandbox(tool_name, agent_state, **kwargs)
        else:
            # Execute locally (coordination tools)
            result = await _execute_locally(tool_name, agent_state, **kwargs)

        logger.info(f"Tool '{tool_name}' executed successfully")
        return result

    except Exception as e:
        logger.error(f"Tool '{tool_name}' execution failed: {e}")
        raise ToolExecutionError(f"Failed to execute {tool_name}: {str(e)}")


async def _execute_locally(
    tool_name: str,
    agent_state,
    **kwargs
) -> Any:
    """
    Execute tool locally in the main process

    Used for coordination tools like:
    - create_agent
    - send_message_to_agent
    - agent_finish
    - create_vulnerability_report
    """
    tool_info = get_tool(tool_name)
    func = tool_info["function"]

    # Inject agent_state if function expects it
    import inspect
    sig = inspect.signature(func)
    if "agent_state" in sig.parameters:
        kwargs["agent_state"] = agent_state

    # Execute the function
    if asyncio.iscoroutinefunction(func):
        result = await func(**kwargs)
    else:
        result = func(**kwargs)

    return result


async def _execute_in_sandbox(
    tool_name: str,
    agent_state,
    **kwargs
) -> Any:
    """
    Execute tool in Docker sandbox

    Makes HTTP request to kali-agent tool server
    """
    # Get sandbox info from agent state
    sandbox_url = agent_state.get("sandbox_url", "http://kali-agent-1:9000")
    auth_token = agent_state.get("auth_token")

    # Make HTTP request to tool server
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            response = await client.post(
                f"{sandbox_url}/execute_tool",
                json={
                    "tool_name": tool_name,
                    "parameters": kwargs
                },
                headers={
                    "Authorization": f"Bearer {auth_token}" if auth_token else ""
                }
            )

            response.raise_for_status()
            result = response.json()

            return result

        except httpx.HTTPError as e:
            raise ToolExecutionError(f"Sandbox execution failed: {e}")


async def process_tool_invocations(
    tool_invocations: list,
    conversation_history: list,
    agent_state
) -> bool:
    """
    Process multiple tool invocations from LLM response

    Args:
        tool_invocations: List of tool calls parsed from LLM response
        conversation_history: Agent's conversation history
        agent_state: Current agent state

    Returns:
        bool: True if agent should finish, False otherwise
    """
    should_finish = False

    for tool_inv in tool_invocations:
        tool_name = tool_inv.get("toolName")
        args = tool_inv.get("args", {})

        logger.info(f"Executing tool: {tool_name}")

        try:
            # Execute the tool
            result = await execute_tool(tool_name, agent_state, **args)

            # Format result as XML for LLM
            observation_xml = f"""<tool_result>
<tool_name>{tool_name}</tool_name>
<result>{result}</result>
</tool_result>"""

            # Add to conversation history
            conversation_history.append({
                "role": "user",
                "content": observation_xml
            })

            # Check if this is a finish tool
            if tool_name in ("finish_scan", "agent_finish"):
                should_finish = True

        except ToolExecutionError as e:
            # Add error to conversation history so LLM can handle it
            error_xml = f"""<tool_result>
<tool_name>{tool_name}</tool_name>
<error>{str(e)}</error>
</tool_result>"""

            conversation_history.append({
                "role": "user",
                "content": error_xml
            })

    return should_finish
