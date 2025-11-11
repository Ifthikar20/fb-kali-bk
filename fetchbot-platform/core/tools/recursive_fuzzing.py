"""
Recursive Fuzzing Tools with Claude Analysis

Professional fuzzing tools that:
1. Recursively discover directories and files
2. Analyze responses to identify interesting patterns
3. Send results to Claude via MCP for final vulnerability determination
4. Only create reports when Claude confirms actual security issues
"""

import logging
from typing import Dict, Any, List, Optional
from .registry import register_tool

logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=True, description="Professional recursive web fuzzing with Claude analysis")
async def recursive_fuzz(
    url: str,
    max_depth: int = 3,
    wordlist: str = "common",
    extensions: Optional[str] = None,
    follow_redirects: bool = True
) -> Dict[str, Any]:
    """
    Professional recursive directory and file fuzzing

    This tool:
    - Starts fuzzing at the base URL
    - When a directory is found (200, 301, 302, 403), recursively fuzzes inside it
    - Continues up to max_depth levels
    - Returns ALL discovered paths for Claude to analyze
    - Claude decides which findings are actual vulnerabilities

    Args:
        url: Base URL to fuzz (e.g., "https://example.com")
        max_depth: Maximum recursion depth (1-5 recommended)
        wordlist: Wordlist to use - "common" (4k), "medium" (20k), "large" (custom)
        extensions: File extensions to test (e.g., "php,txt,bak,env,sql")
        follow_redirects: Follow 301/302 redirects when fuzzing

    Returns:
        Dictionary with:
        - discovered_paths: All discovered URLs with status codes
        - interesting_responses: Paths with unusual status codes or sizes
        - depth_map: How deep each path was found
        - total_requests: Number of requests made
        - analysis_needed: Paths that Claude should analyze for vulnerabilities

    Example Usage:
        # Basic fuzzing
        result = recursive_fuzz(url="https://target.com", max_depth=2)

        # Deep fuzzing with extensions
        result = recursive_fuzz(
            url="https://target.com",
            max_depth=3,
            wordlist="medium",
            extensions="php,asp,aspx,jsp,bak,sql,env"
        )

        # After receiving results, Claude analyzes and creates reports:
        # - Exposed admin panels → HIGH severity
        # - Backup files (.bak, .sql) → CRITICAL severity
        # - .env files → CRITICAL severity
        # - Debug/test endpoints → MEDIUM severity
    """
    return {
        "tool": "recursive_fuzz",
        "url": url,
        "max_depth": max_depth,
        "wordlist": wordlist,
        "extensions": extensions,
        "follow_redirects": follow_redirects
    }


@register_tool(sandbox_execution=True, description="Intelligent fuzzing that adapts based on findings")
async def adaptive_fuzz(
    url: str,
    initial_wordlist: str = "common",
    enable_smart_extensions: bool = True,
    stop_on_waf: bool = True
) -> Dict[str, Any]:
    """
    Adaptive fuzzing that intelligently adjusts based on what it finds

    Intelligence features:
    - Detects technology stack (PHP, ASP.NET, Java) and tests relevant extensions
    - Identifies WAF/rate limiting and adapts request patterns
    - Focuses on interesting status codes (403 Forbidden = hidden content)
    - Escalates from small wordlist to larger if findings are sparse
    - Returns results to Claude for security analysis

    Args:
        url: Base URL to test
        initial_wordlist: Starting wordlist ("common" or "medium")
        enable_smart_extensions: Auto-detect and test tech-specific extensions
        stop_on_waf: Stop if WAF/rate limiting detected

    Returns:
        Dictionary with:
        - discovered_content: All discovered paths
        - technology_detected: Detected tech stack (PHP, ASP.NET, etc.)
        - waf_detected: Whether WAF was encountered
        - forbidden_paths: Paths returning 403 (potential hidden admin areas)
        - backup_files: Discovered backup/config files
        - claude_analysis_request: Flag indicating Claude should analyze results

    Workflow:
    1. Tool runs adaptive fuzzing and returns results
    2. Claude analyzes the results:
       - Are 403 paths admin panels? → Create vulnerability report
       - Are backup files exposed? → Create CRITICAL report
       - Is WAF blocking legitimate testing? → Note in scan summary
    3. Only REAL vulnerabilities get reported to UI
    """
    return {
        "tool": "adaptive_fuzz",
        "url": url,
        "initial_wordlist": initial_wordlist,
        "enable_smart_extensions": enable_smart_extensions,
        "stop_on_waf": stop_on_waf
    }


@register_tool(sandbox_execution=True, description="Targeted fuzzing for specific vulnerability types")
async def targeted_fuzz(
    url: str,
    fuzz_type: str,
    custom_payloads: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Targeted fuzzing for specific vulnerability patterns

    Fuzz types:
    - "backup_files": .bak, .sql, .tar.gz, .zip, .old, ~, .swp
    - "config_files": .env, config.php, web.config, application.properties
    - "admin_panels": admin, administrator, wp-admin, cpanel, phpmyadmin
    - "api_endpoints": /api, /v1, /graphql, /rest, /swagger
    - "debug_endpoints": /debug, /test, /_profiler, /actuator
    - "source_disclosure": .git, .svn, .DS_Store, .htaccess

    Args:
        url: Base URL
        fuzz_type: Type of fuzzing to perform (see above)
        custom_payloads: Optional custom payload list to test

    Returns:
        Dictionary with:
        - fuzz_type: Type that was tested
        - findings: All discovered matches
        - security_impact: Estimated impact for each finding
        - claude_confirmation_needed: True (Claude must confirm before reporting)

    Important: This tool discovers POTENTIAL issues. Claude analyzes results
    and only creates vulnerability reports for CONFIRMED security problems.
    """
    return {
        "tool": "targeted_fuzz",
        "url": url,
        "fuzz_type": fuzz_type,
        "custom_payloads": custom_payloads or []
    }
