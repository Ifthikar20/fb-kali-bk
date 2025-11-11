"""
Iterative Analysis Tools - Claude-in-the-Loop Testing

Implements an iterative workflow where:
1. Run initial test (e.g., nmap -sV)
2. Send results to Claude for analysis
3. Claude decides: retry with different params? run deeper scan? report finding?
4. UI shows Claude's decision-making process
5. Repeat until Claude confirms finding or determines no vulnerability

This prevents hallucinated findings and shows transparent decision-making.
"""

import logging
from typing import Dict, Any, Optional
from .registry import register_tool
from ..utils.logging import add_execution_log

logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=False, description="Analyze tool results and decide next steps")
def analyze_and_decide(
    agent_state,
    tool_name: str,
    tool_result: Dict[str, Any],
    question: str,
    context: str = ""
) -> Dict[str, Any]:
    """
    Analyze a tool's output and log the decision-making process to UI

    This tool is called BY Claude to record its analysis of scan results.
    It logs the thought process so users can see how decisions are made.

    Workflow:
    1. Agent runs tool (e.g., nmap_scan)
    2. Agent calls analyze_and_decide with the results
    3. This logs Claude's analysis to the UI
    4. Agent then decides: run another scan? report finding? move on?

    Args:
        tool_name: Name of the tool that was executed
        tool_result: The actual results from the tool
        question: What Claude is trying to determine from this result
        context: Additional context about why this analysis is happening

    Returns:
        Acknowledgment that analysis was logged

    Example Usage:
        # After running nmap
        nmap_result = nmap_scan(target="192.168.1.1", ports="1-1000")

        # Analyze the results
        analyze_and_decide(
            tool_name="nmap_scan",
            tool_result=nmap_result,
            question="Are there any high-risk services exposed?",
            context="Initial port scan showed 15 open ports"
        )

        # Based on analysis, decide next step:
        # - If suspicious service found → run nmap_detailed_scan
        # - If no issues → move to next test
        # - If vulnerability confirmed → create_vulnerability_report
    """
    # Extract key info from result
    result_summary = _summarize_result(tool_name, tool_result)

    # Log the analysis to database for UI display
    analysis_log = f"""
🤔 **Analyzing {tool_name} results**

**Question:** {question}

**Result Summary:**
{result_summary}

{f"**Context:** {context}" if context else ""}

**Next Step:** Claude is now deciding whether to:
- Run a deeper/different scan for more information
- Confirm this as a vulnerability and report it
- Move on to test something else
"""

    add_execution_log(
        job_id=agent_state.job_id,
        action=f"Claude analyzing {tool_name}",
        details=analysis_log,
        agent=agent_state.agent_id,
        db_url=agent_state.db_url
    )

    logger.info(f"Claude analyzing {tool_name}: {question}")

    return {
        "status": "analysis_logged",
        "tool_analyzed": tool_name,
        "message": "Analysis logged to UI. Claude should now decide next step."
    }


@register_tool(sandbox_execution=False, description="Log Claude's decision about next steps")
def log_decision(
    agent_state,
    decision: str,
    reasoning: str,
    next_action: Optional[str] = None
) -> Dict[str, Any]:
    """
    Log Claude's decision-making process to the UI

    Use this after analyze_and_decide to show what Claude decided to do next.

    Args:
        decision: The decision made (e.g., "Run deeper nmap scan", "Report vulnerability", "No issue found")
        reasoning: Why this decision was made
        next_action: What tool/action will be executed next (if any)

    Returns:
        Acknowledgment that decision was logged

    Example:
        log_decision(
            decision="Run aggressive nmap scan",
            reasoning="Initial scan showed SSH on port 22 with unknown version. Need to fingerprint the exact version to check for known exploits.",
            next_action="nmap_detailed_scan with aggressive=True"
        )
    """
    decision_log = f"""
✅ **Decision Made**

**Decision:** {decision}

**Reasoning:**
{reasoning}

{f"**Next Action:** {next_action}" if next_action else "**Next Action:** Analysis complete, moving to next phase"}
"""

    add_execution_log(
        job_id=agent_state.job_id,
        action="Claude's Decision",
        details=decision_log,
        agent=agent_state.agent_id,
        db_url=agent_state.db_url
    )

    logger.info(f"Decision logged: {decision}")

    return {
        "status": "decision_logged",
        "decision": decision,
        "message": "Decision visible in UI logs"
    }


@register_tool(sandbox_execution=False, description="Log that Claude confirmed a finding")
def confirm_finding(
    agent_state,
    finding_summary: str,
    evidence_analysis: str,
    confidence: str = "HIGH"
) -> Dict[str, Any]:
    """
    Log that Claude has confirmed an actual vulnerability after analysis

    Use this BEFORE create_vulnerability_report to show that Claude reviewed
    the evidence and confirmed it's a real security issue.

    Args:
        finding_summary: Brief summary of what was found
        evidence_analysis: Claude's analysis of the evidence
        confidence: Confidence level - HIGH, MEDIUM, LOW

    Returns:
        Acknowledgment that confirmation was logged

    Example:
        confirm_finding(
            finding_summary="Exposed admin panel with default credentials",
            evidence_analysis="Tested wp-admin with admin:admin credentials. Successfully logged in and accessed dashboard. This confirms weak authentication.",
            confidence="HIGH"
        )

        # THEN create the actual vulnerability report
        create_vulnerability_report(...)
    """
    confirmation_log = f"""
🎯 **Vulnerability Confirmed by Claude**

**Finding:** {finding_summary}

**Confidence:** {confidence}

**Evidence Analysis:**
{evidence_analysis}

**Status:** Creating formal vulnerability report...
"""

    add_execution_log(
        job_id=agent_state.job_id,
        action=f"Vulnerability Confirmed ({confidence} confidence)",
        details=confirmation_log,
        agent=agent_state.agent_id,
        db_url=agent_state.db_url
    )

    logger.info(f"Finding confirmed: {finding_summary}")

    return {
        "status": "confirmed",
        "confidence": confidence,
        "message": "Confirmation logged. Now create vulnerability report."
    }


def _summarize_result(tool_name: str, result: Dict[str, Any]) -> str:
    """Generate a human-readable summary of tool results"""

    # Handle different tool result formats
    if tool_name == "nmap_scan" or tool_name == "nmap_detailed_scan":
        open_ports = result.get("open_ports", [])
        if open_ports:
            return f"Found {len(open_ports)} open ports: {', '.join(map(str, open_ports[:5]))}" + \
                   (f" and {len(open_ports) - 5} more..." if len(open_ports) > 5 else "")
        return "No open ports detected"

    elif tool_name == "http_scan":
        endpoints = result.get("endpoints", [])
        forms = result.get("forms", [])
        return f"Found {len(endpoints)} endpoints and {len(forms)} forms"

    elif tool_name == "sql_injection_test":
        if result.get("vulnerable"):
            return f"⚠️ SQL injection detected! Payload: {result.get('payload')}"
        return "No SQL injection vulnerability found"

    elif tool_name == "xss_test":
        if result.get("vulnerable"):
            return f"⚠️ XSS detected! Context: {result.get('context')}"
        return "No XSS vulnerability found"

    elif "fuzz" in tool_name:
        discovered = result.get("discovered_paths", [])
        interesting = result.get("interesting_findings", [])
        return f"Discovered {len(discovered)} paths, {len(interesting)} interesting"

    # Generic summary
    if "error" in result:
        return f"Error: {result['error']}"

    return f"Tool completed. Keys in result: {', '.join(result.keys())}"
