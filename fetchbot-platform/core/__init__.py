"""
FetchBot Core - Dynamic Multi-Agent Architecture

This package contains the core infrastructure for dynamic agent-based security testing.
"""

# NOTE: Imports are lazy-loaded to avoid circular dependencies
# and to support both the old system and new specialized agents

__version__ = "2.0.0"

def __getattr__(name):
    """Lazy load modules to avoid circular dependencies"""
    if name == "tools":
        from . import tools
        return tools
    elif name == "BaseAgent":
        from .agents.base_agent import BaseAgent
        return BaseAgent
    elif name == "AgentState":
        from .agents.state import AgentState
        return AgentState
    elif name == "get_agent_graph":
        from .agents.agent_graph import get_agent_graph
        return get_agent_graph
    elif name == "LLMConfig":
        from .llm.config import LLMConfig
        return LLMConfig
    elif name == "LLM":
        from .llm.llm import LLM
        return LLM
    raise AttributeError(f"module 'core' has no attribute '{name}'")
