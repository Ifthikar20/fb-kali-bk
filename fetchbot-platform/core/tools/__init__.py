"""
Tools Package

Imports all tool modules to ensure they register with the tool registry
"""

# Import registry first
from .registry import (
    register_tool,
    get_tool_registry,
    get_tool,
    get_tool_schemas,
    get_tools_prompt,
    list_tools
)

# Import executor
from .executor import execute_tool, process_tool_invocations

# Import all tool modules to trigger registration
from . import coordination_tools
from . import network_tools
from . import web_tools
from . import database_tools
from . import api_tools

__all__ = [
    "register_tool",
    "get_tool_registry",
    "get_tool",
    "get_tool_schemas",
    "get_tools_prompt",
    "list_tools",
    "execute_tool",
    "process_tool_invocations"
]
