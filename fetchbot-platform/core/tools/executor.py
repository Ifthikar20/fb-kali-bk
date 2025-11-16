"""
Tool Execution System

Handles executing tools either locally (coordination tools) or in sandbox (scanning tools)
Supports both HTTP and MCP (Model Context Protocol) execution modes.
"""

import httpx
import asyncio
import logging
import os
from typing import Dict, Any, Optional
from .registry import get_tool, _TOOL_REGISTRY
from ..utils.logging import log_tool_execution
from ..agents.agent_graph import get_agent_graph

logger = logging.getLogger(__name__)

# Check if MCP mode is enabled
USE_MCP = os.getenv('USE_MCP', 'false').lower() == 'true'

if USE_MCP:
    try:
        from .mcp_executor import execute_tool_via_mcp
        logger.info("MCP mode enabled - will use Model Context Protocol for tool execution")
    except ImportError:
        logger.warning("MCP mode requested but mcp_executor not available, falling back to HTTP")
        USE_MCP = False


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
    Execute tool in Docker sandbox or via MCP

    Uses MCP (Model Context Protocol) if USE_MCP=true, otherwise HTTP to kali-agent tool server
    """
    # Use MCP protocol if enabled
    if USE_MCP:
        logger.debug(f"Routing {tool_name} to MCP server")
        return await execute_tool_via_mcp(tool_name, agent_state, **kwargs)

    # Otherwise use HTTP (existing implementation)
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
    import re

    # Get actual target URL from agent state
    actual_target = getattr(agent_state, 'target', None)

    # Common placeholder URLs that LLM hallucinates
    placeholder_patterns = [
        r'https?://(?:www\.)?example\.com',
        r'https?://(?:www\.)?test\.com',
        r'https?://(?:api\.)?example\.com',
        r'https?://target\.com',
        r'https?://example\.org',
        r'https?://test\.example\.com',
        r'\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.16\.\d+\.\d+)\b',  # Private IPs
    ]

    def auto_fix_url_params(args: dict, target: str) -> dict:
        """Auto-replace placeholder URLs with actual target"""
        if not target:
            return args

        fixed_args = {}
        for key, value in args.items():
            if isinstance(value, str):
                # Replace any placeholder URL with actual target
                fixed_value = value
                for pattern in placeholder_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        # Extract the path/query from placeholder if present
                        match = re.match(r'https?://[^/]+(/.*)$', value)
                        path = match.group(1) if match else ''

                        # Replace with actual target + path
                        fixed_value = target.rstrip('/') + path

                        logger.warning(
                            f"🔧 Auto-fixed placeholder URL in parameter '{key}': "
                            f"{value} → {fixed_value}"
                        )
                        break

                fixed_args[key] = fixed_value
            else:
                fixed_args[key] = value

        return fixed_args

    should_finish = False

    # Import agent graph for task deduplication
    from core.agents.agent_graph import get_agent_graph

    for tool_inv in tool_invocations:
        tool_name = tool_inv.get("toolName")
        args = tool_inv.get("args", {})

        # Auto-fix any placeholder URLs in arguments
        args = auto_fix_url_params(args, actual_target)

        # Check for task deduplication (skip for coordination tools)
        # Coordination tools should always execute (finish_scan, create_agent, etc.)
        coordination_tools = {
            "finish_scan", "agent_finish", "create_agent", "send_message",
            "get_my_agents", "get_scan_status", "create_vulnerability_report"
        }

        if tool_name not in coordination_tools:
            graph = get_agent_graph()
            previous_execution = graph.is_task_already_executed(tool_name, args)

            if previous_execution:
                logger.warning(
                    f"⚠️ Task '{tool_name}' already executed by {previous_execution['agent_name']} "
                    f"at {previous_execution['timestamp']} - skipping duplicate work"
                )

                # Add skip notification to conversation history
                skip_xml = f"""<tool_result>
<tool_name>{tool_name}</tool_name>
<skipped>true</skipped>
<reason>Task already executed by {previous_execution['agent_name']} at {previous_execution['timestamp']}</reason>
<message>Skipping duplicate work - results should be available from previous execution</message>
</tool_result>"""

                conversation_history.append({
                    "role": "user",
                    "content": skip_xml
                })

                continue  # Skip this tool execution

        logger.info(f"Executing tool: {tool_name}")

        try:
            # Execute the tool
            result = await execute_tool(tool_name, agent_state, **args)

            # Track successful tool execution
            agent_state.track_tool_execution(tool_name, success=True, result=result)

            # Register task execution in graph for deduplication (skip coordination tools)
            if tool_name not in coordination_tools:
                graph.register_task_execution(
                    tool_name=tool_name,
                    params=args,
                    agent_id=agent_state.agent_id,
                    result=result
                )

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

            # Check if this is a finish tool AND it succeeded
            if tool_name in ("finish_scan", "agent_finish"):
                # Only finish if the tool returned success status
                # finish_scan returns {"status": "scan_complete"} on success
                # or {"status": "error"} if agents still running
                if isinstance(result, dict):
                    if tool_name == "finish_scan" and result.get("status") == "scan_complete":
                        should_finish = True
                        logger.info("✅ finish_scan succeeded - agent will complete")
                    elif tool_name == "agent_finish" and result.get("status") != "error":
                        should_finish = True
                        logger.info("✅ agent_finish succeeded - agent will complete")
                    else:
                        logger.warning(
                            f"⚠️ {tool_name} called but returned error status - "
                            "agent will continue running"
                        )
                else:
                    # Backward compatibility: if result is not a dict, finish anyway
                    should_finish = True

        except ToolExecutionError as e:
            # Track failed tool execution
            agent_state.track_tool_execution(tool_name, success=False, result=str(e))

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
