"""
FetchBot Core - Dynamic Multi-Agent Architecture

This package contains the core infrastructure for dynamic agent-based security testing.
"""

# Import tools first to register them
from . import tools

# Import agents
from .agents.base_agent import BaseAgent
from .agents.state import AgentState
from .agents.agent_graph import get_agent_graph

# Import LLM
from .llm.config import LLMConfig
from .llm.llm import LLM

__version__ = "2.0.0"

__all__ = [
    "BaseAgent",
    "AgentState",
    "get_agent_graph",
    "LLMConfig",
    "LLM",
    "tools"
]
