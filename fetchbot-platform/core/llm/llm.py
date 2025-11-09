"""
LLM Integration

Manages communication with Claude AI for agent decision-making
"""

import anthropic
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from jinja2 import Environment, FileSystemLoader
import logging

from .config import LLMConfig
from .parsers import parse_tool_invocations, extract_thinking
from ..tools.registry import get_tools_prompt

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM"""
    content: str
    tool_invocations: List[Dict[str, Any]]
    thinking: str
    raw_response: Any


class LLM:
    """
    LLM interface for agent decision-making

    Handles:
    - System prompt generation with loaded modules
    - Tool schema injection
    - Making API requests to Claude
    - Parsing responses
    """

    def __init__(self, config: LLMConfig, prompts_dir: str = None):
        """
        Initialize LLM interface

        Args:
            config: LLM configuration
            prompts_dir: Path to prompts directory (defaults to core/prompts)
        """
        self.config = config

        # Initialize Anthropic client
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        self.client = anthropic.Anthropic(api_key=api_key)

        # Setup Jinja environment for prompt templates
        if prompts_dir is None:
            import os.path as path
            current_dir = path.dirname(path.abspath(__file__))
            prompts_dir = path.join(path.dirname(current_dir), "prompts")

        self.jinja_env = Environment(loader=FileSystemLoader(prompts_dir))

        # Build system prompt
        self.system_prompt = self._build_system_prompt()

        logger.info(f"LLM initialized with model: {config.model}, modules: {config.prompt_modules}")

    def _build_system_prompt(self) -> str:
        """
        Build complete system prompt

        Combines:
        1. Base system prompt
        2. Specialized prompt modules
        3. Available tools
        """
        # Load base template
        template = self.jinja_env.get_template("base_system_prompt.jinja")

        # Load prompt modules
        module_content = {}
        for module_name in self.config.prompt_modules:
            try:
                # Try loading from different directories
                for subdir in ["vulnerabilities", "frameworks", "coordination"]:
                    try:
                        module_template = self.jinja_env.get_template(f"{subdir}/{module_name}.jinja")
                        module_content[module_name] = module_template.render()
                        logger.debug(f"Loaded prompt module: {subdir}/{module_name}")
                        break
                    except:
                        continue
            except Exception as e:
                logger.warning(f"Failed to load prompt module '{module_name}': {e}")

        # Get available tools
        tools_prompt = get_tools_prompt()

        # Render final prompt
        system_prompt = template.render(
            prompt_modules=module_content,
            tools=tools_prompt,
            is_root_agent=self.config.is_root_agent()
        )

        return system_prompt

    async def generate(
        self,
        conversation_history: List[Dict[str, str]],
        scan_id: Optional[str] = None,
        step_number: Optional[int] = None
    ) -> LLMResponse:
        """
        Generate response from LLM

        Args:
            conversation_history: List of messages [{"role": "user", "content": "..."}, ...]
            scan_id: Optional scan ID for logging
            step_number: Optional step number for logging

        Returns:
            LLMResponse with content and parsed tool invocations
        """
        # Build messages
        messages = self._prepare_messages(conversation_history)

        try:
            # Make API request
            response = await self._make_request(messages)

            # Parse response
            content = response.content[0].text

            # Log the raw response for debugging
            logger.debug(f"Raw LLM response: {content[:500]}...")  # First 500 chars

            tool_invocations = parse_tool_invocations(content)
            thinking = extract_thinking(content)

            logger.info(
                f"LLM response generated (scan={scan_id}, step={step_number}): "
                f"{len(tool_invocations)} tool calls"
            )

            return LLMResponse(
                content=content,
                tool_invocations=tool_invocations,
                thinking=thinking,
                raw_response=response
            )

        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise

    def _prepare_messages(self, conversation_history: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Prepare messages for API request

        Adds system prompt and formats conversation history
        """
        # System prompt is passed separately in Anthropic API
        # Just return the conversation history
        return conversation_history

    async def _make_request(self, messages: List[Dict[str, str]]) -> Any:
        """
        Make API request to Claude

        Uses async client for better performance
        """
        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=self.system_prompt,  # System prompt passed here
            messages=messages
        )

        return response

    def get_system_prompt(self) -> str:
        """Get the current system prompt (for debugging)"""
        return self.system_prompt
