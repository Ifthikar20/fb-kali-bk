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

        logger.debug(f"Found function block for: {tool_name}")
        logger.debug(f"Function body: {function_body[:200]}...")  # First 200 chars

        args = {}

        # Try Format 1: <parameter=name>value</parameter> or <parameter=name>value</parameter=name>
        # Claude sometimes uses malformed closing tags like </parameter=name> instead of </parameter>
        param_pattern = r'<parameter=([^>]+)>(.*?)</parameter(?:=[^>]+)?>'
        param_matches = re.finditer(param_pattern, function_body, re.DOTALL)

        for param_match in param_matches:
            param_name = param_match.group(1).strip()
            param_value = param_match.group(2).strip()
            args[param_name] = param_value
            logger.debug(f"  Parsed parameter (format 1): {param_name} = {param_value[:100]}")

        # Try Format 2: <name>value</name> (what Claude actually uses)
        if not args:
            # Match any XML tag that's not "function"
            simple_param_pattern = r'<([a-zA-Z_][a-zA-Z0-9_]*)>(.*?)</\1>'
            simple_param_matches = re.finditer(simple_param_pattern, function_body, re.DOTALL)

            for param_match in simple_param_matches:
                param_name = param_match.group(1).strip()
                param_value = param_match.group(2).strip()
                # Skip if it's a nested function call
                if param_name != 'function':
                    args[param_name] = param_value
                    logger.debug(f"  Parsed parameter (format 2): {param_name} = {param_value[:100]}")

        if not args:
            logger.warning(f"No parameters found for tool {tool_name}. Function body was: {function_body[:300]}")

        invocations.append({
            "toolName": tool_name,
            "args": args
        })

        logger.info(f"Parsed tool invocation: {tool_name} with {len(args)} args: {list(args.keys())}")

    if not invocations and ('<function=' in content):
        logger.error(f"Found <function= tags but failed to parse. Content sample: {content[:1000]}")

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
