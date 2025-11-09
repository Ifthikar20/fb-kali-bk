"""
LLM Configuration

Defines configuration for LLM-powered agents
"""

from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class LLMConfig:
    """
    Configuration for LLM integration

    Attributes:
        prompt_modules: List of specialized knowledge modules to load
                       Empty list = root/coordinator agent
                       ["sql_injection"] = SQL injection specialist
                       ["xss", "csrf"] = XSS and CSRF specialist
        model: Claude model to use
        max_tokens: Maximum tokens in response
        temperature: Sampling temperature (0-1)
    """

    prompt_modules: List[str] = field(default_factory=list)
    model: str = "claude-3-5-sonnet-20240620"  # Valid Claude 3.5 Sonnet model
    max_tokens: int = 4000
    temperature: float = 0.7

    def __post_init__(self):
        """Validate configuration"""
        if self.max_tokens > 8192:
            raise ValueError("max_tokens cannot exceed 8192")

        if not 0 <= self.temperature <= 1:
            raise ValueError("temperature must be between 0 and 1")

    def is_root_agent(self) -> bool:
        """Check if this config is for a root/coordinator agent"""
        return len(self.prompt_modules) == 0

    def get_module_list(self) -> List[str]:
        """Get list of prompt modules"""
        return self.prompt_modules.copy()
