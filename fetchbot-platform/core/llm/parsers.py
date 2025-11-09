"""
LLM Response Parsers

Parse tool invocations from Claude's responses
"""

import re
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def parse_tool_invocations(content: str) -> List[Dict[str, Any]]:
    """
    Parse tool invocations from LLM response

    Expected format:
        <function=tool_name>
        <parameter=param1>value1</parameter>
        <parameter=param2>value2</parameter>
        </function>

    Returns:
        List of tool invocations with format:
        [
            {
                "toolName": "tool_name",
                "args": {"param1": "value1", "param2": "value2"}
            }
        ]
    """
    invocations = []

    # Find all function blocks
    function_pattern = r'<function=([^>]+)>(.*?)</function>'
    function_matches = re.finditer(function_pattern, content, re.DOTALL)

    for match in function_matches:
        tool_name = match.group(1).strip()
        function_body = match.group(2)

        # Extract parameters
        param_pattern = r'<parameter=([^>]+)>(.*?)</parameter>'
        param_matches = re.finditer(param_pattern, function_body, re.DOTALL)

        args = {}
        for param_match in param_matches:
            param_name = param_match.group(1).strip()
            param_value = param_match.group(2).strip()
            args[param_name] = param_value

        invocations.append({
            "toolName": tool_name,
            "args": args
        })

        logger.debug(f"Parsed tool invocation: {tool_name} with args: {list(args.keys())}")

    return invocations


def extract_thinking(content: str) -> str:
    """
    Extract thinking blocks from LLM response

    Format: <thinking>...</thinking>
    """
    thinking_pattern = r'<thinking>(.*?)</thinking>'
    matches = re.findall(thinking_pattern, content, re.DOTALL)

    if matches:
        return "\n\n".join(m.strip() for m in matches)

    return ""


def clean_response_for_display(content: str) -> str:
    """
    Remove XML tags from response for clean display

    Keeps: Thinking blocks and main text
    Removes: Function calls and tool results
    """
    # Remove function calls
    content = re.sub(r'<function=.*?</function>', '', content, flags=re.DOTALL)

    # Remove tool results
    content = re.sub(r'<tool_result>.*?</tool_result>', '', content, flags=re.DOTALL)

    # Clean up extra whitespace
    content = re.sub(r'\n\n\n+', '\n\n', content)

    return content.strip()
