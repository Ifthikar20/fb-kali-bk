"""
Tool Registry System

This module provides decorator-based tool registration with automatic schema generation.
Tools registered here are automatically available to all agents.
"""

import inspect
import asyncio
from typing import Dict, Any, Callable, Optional, List
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Global tool registry
_TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_tool(
    sandbox_execution: bool = False,
    description: Optional[str] = None
):
    """
    Decorator to register a tool for agent use

    Args:
        sandbox_execution: If True, tool should be executed in Docker container
                          If False, tool runs in main process (for coordination tools)
        description: Optional description override (defaults to docstring)

    Example:
        @register_tool(sandbox_execution=True)
        async def nmap_scan(target: str, ports: str = "1-1000") -> dict:
            '''Scan ports on target using nmap'''
            # Implementation
            pass
    """
    def decorator(func: Callable):
        tool_name = func.__name__

        # Extract function signature for schema generation
        sig = inspect.signature(func)
        parameters = {}

        for param_name, param in sig.parameters.items():
            # Skip agent_state parameter (injected automatically)
            if param_name == "agent_state":
                continue

            param_info = {
                "type": _python_type_to_schema_type(param.annotation),
                "required": param.default == inspect.Parameter.empty
            }

            # Extract description from type hints or docstring
            if func.__doc__:
                param_desc = _extract_param_description(func.__doc__, param_name)
                if param_desc:
                    param_info["description"] = param_desc

            parameters[param_name] = param_info

        # Generate tool schema for LLM
        tool_schema = {
            "name": tool_name,
            "description": description or (func.__doc__ or "").strip().split("\n")[0],
            "parameters": parameters,
            "sandbox_execution": sandbox_execution,
            "function": func
        }

        # Register tool
        _TOOL_REGISTRY[tool_name] = tool_schema

        logger.info(f"Registered tool: {tool_name} (sandbox={sandbox_execution})")

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Execute the tool
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


def _python_type_to_schema_type(py_type) -> str:
    """Convert Python type annotation to schema type"""
    type_mapping = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object"
    }

    if py_type == inspect.Parameter.empty:
        return "string"

    # Handle Optional types
    if hasattr(py_type, "__origin__"):
        if py_type.__origin__ is list:
            return "array"
        if py_type.__origin__ is dict:
            return "object"

    return type_mapping.get(py_type, "string")


def _extract_param_description(docstring: str, param_name: str) -> Optional[str]:
    """Extract parameter description from docstring"""
    lines = docstring.split("\n")
    for i, line in enumerate(lines):
        if param_name in line and ":" in line:
            # Format: "param_name: description"
            parts = line.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return None


def get_tool_registry() -> Dict[str, Dict[str, Any]]:
    """Get the complete tool registry"""
    return _TOOL_REGISTRY


def get_tool(tool_name: str) -> Optional[Dict[str, Any]]:
    """Get a specific tool by name"""
    return _TOOL_REGISTRY.get(tool_name)


def get_tool_schemas() -> List[Dict[str, Any]]:
    """
    Get tool schemas formatted for LLM consumption

    Returns list of tool schemas without the function reference
    """
    schemas = []
    for tool_name, tool_info in _TOOL_REGISTRY.items():
        schema = {
            "name": tool_info["name"],
            "description": tool_info["description"],
            "parameters": tool_info["parameters"]
        }
        schemas.append(schema)

    return schemas


def get_tools_prompt() -> str:
    """
    Generate a formatted prompt section describing all available tools

    This is used in the system prompt to tell Claude what tools it can use
    """
    if not _TOOL_REGISTRY:
        return "No tools available."

    prompt = "# Available Tools\n\n"
    prompt += "You can use the following tools by invoking them in your response:\n\n"

    for tool_name, tool_info in sorted(_TOOL_REGISTRY.items()):
        prompt += f"## {tool_name}\n"
        prompt += f"{tool_info['description']}\n\n"

        if tool_info['parameters']:
            prompt += "Parameters:\n"
            for param_name, param_info in tool_info['parameters'].items():
                required = " (required)" if param_info.get('required', False) else " (optional)"
                desc = param_info.get('description', '')
                prompt += f"- {param_name} ({param_info['type']}){required}: {desc}\n"
        else:
            prompt += "No parameters required.\n"

        prompt += "\n"

    prompt += "\nTo use a tool, format your response like:\n"
    prompt += "<function=tool_name>\n"
    prompt += "<parameter=param_name>value</parameter>\n"
    prompt += "</function>\n\n"

    return prompt


def list_tools(category: Optional[str] = None) -> List[str]:
    """
    List all registered tool names

    Args:
        category: Optional filter (e.g., "network", "web", "coordination")
    """
    tools = list(_TOOL_REGISTRY.keys())

    if category:
        # Filter by category (based on tool name prefix or tags)
        tools = [t for t in tools if category.lower() in t.lower()]

    return sorted(tools)
