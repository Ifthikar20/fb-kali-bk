"""
MCP-based Tool Executor

Uses Model Context Protocol to execute security tools instead of HTTP.
Benefits: streaming, lower latency, better error handling.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logger = logging.getLogger(__name__)


class MCPToolExecutor:
    """Execute security tools via MCP protocol"""

    def __init__(self, server_path: str = "/app/mcp-security-server/server.py"):
        """
        Initialize MCP client

        Args:
            server_path: Path to MCP server script
        """
        self.server_path = server_path
        self.session: Optional[ClientSession] = None
        self._lock = asyncio.Lock()

    async def connect(self):
        """Connect to MCP server"""
        if self.session:
            return  # Already connected

        async with self._lock:
            if self.session:
                return

            # Start MCP server as subprocess
            server_params = StdioServerParameters(
                command="python3",
                args=[self.server_path],
                env=None
            )

            # Connect via stdio
            self.stdio_transport = await stdio_client(server_params)
            self.read_stream, self.write_stream = self.stdio_transport

            # Create session
            self.session = ClientSession(self.read_stream, self.write_stream)
            await self.session.initialize()

            logger.info("Connected to MCP security tools server")

    async def execute_tool(
        self,
        tool_name: str,
        agent_state,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute security tool via MCP

        Args:
            tool_name: Name of tool to execute
            agent_state: Current agent state
            **kwargs: Tool-specific parameters

        Returns:
            Tool execution result
        """
        # Ensure connected
        await self.connect()

        # Auto-inject target if needed
        if hasattr(agent_state, 'target') and agent_state.target:
            if not any(k in kwargs for k in ['target', 'url', 'domain']):
                if 'dns' in tool_name.lower():
                    kwargs['domain'] = agent_state.target
                elif 'http' in tool_name.lower() or 'api' in tool_name.lower():
                    kwargs['url'] = agent_state.target
                else:
                    kwargs['target'] = agent_state.target

        logger.info(f"Executing MCP tool: {tool_name} with args: {list(kwargs.keys())}")

        try:
            # Call tool via MCP
            result = await self.session.call_tool(tool_name, arguments=kwargs)

            # Extract text content from MCP response
            if result.content:
                text_content = []
                for content in result.content:
                    if hasattr(content, 'text'):
                        text_content.append(content.text)

                output = "\n".join(text_content)

                return {
                    "success": True,
                    "tool_name": tool_name,
                    "result": output,
                    "raw_result": output
                }
            else:
                return {
                    "success": False,
                    "tool_name": tool_name,
                    "error": "No content in response"
                }

        except Exception as e:
            logger.error(f"MCP tool {tool_name} failed: {e}")
            return {
                "success": False,
                "tool_name": tool_name,
                "error": str(e)
            }

    async def list_tools(self) -> list:
        """List available tools from MCP server"""
        await self.connect()

        tools_list = await self.session.list_tools()
        return tools_list.tools

    async def disconnect(self):
        """Disconnect from MCP server"""
        if self.session:
            await self.session.close()
            self.session = None
            logger.info("Disconnected from MCP server")


# Global MCP executor instance
_mcp_executor: Optional[MCPToolExecutor] = None


def get_mcp_executor() -> MCPToolExecutor:
    """Get or create global MCP executor"""
    global _mcp_executor
    if _mcp_executor is None:
        _mcp_executor = MCPToolExecutor()
    return _mcp_executor


async def execute_tool_via_mcp(
    tool_name: str,
    agent_state,
    **kwargs
) -> Dict[str, Any]:
    """
    Execute tool via MCP (convenience function)

    Args:
        tool_name: Tool to execute
        agent_state: Agent state
        **kwargs: Tool parameters

    Returns:
        Tool result
    """
    executor = get_mcp_executor()
    return await executor.execute_tool(tool_name, agent_state, **kwargs)
