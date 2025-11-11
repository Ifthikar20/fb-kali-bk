"""
Coordination Tools

Tools for agent coordination: creating agents, sending messages, finishing tasks
These tools run locally (not in sandbox) and enable the multi-agent architecture
"""

import asyncio
import threading
import logging
from typing import Dict, Any, Optional

from .registry import register_tool
from ..agents.agent_graph import get_agent_graph
from ..llm.config import LLMConfig
from ..utils.logging import log_agent_created, log_finding_discovered, log_scan_status

logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=False, description="Create a new specialized agent")
def create_agent(
    agent_state,
    task: str,
    name: str,
    prompt_modules: str = "",
    inherit_context: bool = False
) -> Dict[str, Any]:
    """
    Create a new specialized agent to work on a specific task

    Args:
        task: Detailed task description for the new agent
        name: Human-readable name for the agent (e.g., "SQL Injection Agent")
        prompt_modules: Comma-separated list of prompt modules to load
                       Examples: "sql_injection" or "xss,csrf" or "" for generalist
        inherit_context: If True, new agent inherits parent's findings (default: False)

    Returns:
        Dictionary with agent creation status and agent_id

    Example:
        create_agent(
            task="Test SQL injection in login form at /login",
            name="SQL Injection Agent",
            prompt_modules="sql_injection"
        )
    """
    # Import here to avoid circular dependency
    from ..agents.base_agent import BaseAgent

    # Parse prompt modules
    if prompt_modules:
        module_list = [m.strip() for m in prompt_modules.split(",")]
    else:
        module_list = []

    # Create LLM config for new agent
    llm_config = LLMConfig(prompt_modules=module_list)

    # Get next sandbox URL using round-robin distribution
    sandbox_urls = getattr(agent_state, 'sandbox_urls', [agent_state.sandbox_url])
    agent_graph = get_agent_graph()
    num_agents = len(agent_graph.get_all_agents())
    selected_sandbox_url = sandbox_urls[num_agents % len(sandbox_urls)]

    # Create agent configuration (inherit target from parent)
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": 50,
        "sandbox_url": selected_sandbox_url,
        "sandbox_urls": sandbox_urls,  # Pass all URLs to children
        "db_url": agent_state.db_url,
        "job_id": agent_state.job_id,
        "target": agent_state.target  # Propagate target to child agents
    }

    # Enhance task with explicit target URL to prevent LLM from hallucinating example.com
    # Extract domain from target for clarity
    import re
    target_url = agent_state.target
    domain_match = re.search(r'https?://([^/]+)', target_url)
    domain = domain_match.group(1) if domain_match else target_url

    enhanced_task = f"""🎯 TARGET: {target_url}
🎯 DOMAIN: {domain}

{task}

⚠️ CRITICAL INSTRUCTIONS - READ CAREFULLY:

1. The ONLY URL you are authorized to test is: {target_url}
2. When calling ANY security testing tool, you MUST use: {target_url}
3. DO NOT use example.com, test.com, or any fictional URLs
4. DO NOT make up endpoints - use the real target: {target_url}
5. If testing specific paths, use: {target_url}/path (never example.com/path)
6. For domain-based tools (like nmap), use: {domain}

EXAMPLES OF CORRECT USAGE:
✅ http_scan(url="{target_url}")
✅ sql_injection_test(url="{target_url}/api/users")
✅ xss_test(url="{target_url}/search")
✅ nmap_scan(target="{domain}")

EXAMPLES OF INCORRECT USAGE (DO NOT DO THIS):
❌ http_scan(url="https://example.com")
❌ sql_injection_test(url="https://example.com/api/users")
❌ xss_test(url="https://test.com/search")

Your target is: {target_url}
Test ONLY this target. Begin your security testing NOW."""

    # Create new agent
    new_agent = BaseAgent(
        config=agent_config,
        parent_id=agent_state.agent_id,
        name=name,
        task=enhanced_task
    )

    logger.info(
        f"Created agent: {name} with modules {module_list} "
        f"(parent={agent_state.agent_id})"
    )

    # Log agent creation to database
    parent_graph = get_agent_graph()
    parent_info = parent_graph.get_agent_info(agent_state.agent_id)
    parent_name = parent_info.get("name", "Unknown") if parent_info else "Unknown"

    log_agent_created(
        job_id=agent_state.job_id,
        agent_name=name,
        parent_agent=parent_name,
        db_url=agent_state.db_url
    )

    # If inherit_context, copy parent's findings
    if inherit_context:
        parent_findings = agent_state.get_findings()
        for finding in parent_findings:
            new_agent.state.metadata.setdefault("parent_findings", []).append(finding)

    # Run agent in background thread
    def run_agent():
        """Run agent in background"""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Run agent with enhanced task
            result = loop.run_until_complete(new_agent.run(enhanced_task))

            # Send completion message to parent
            graph = get_agent_graph()
            graph.send_message(
                from_id=new_agent.agent_id,
                to_id=agent_state.agent_id,
                content=f"Task completed. Findings: {len(result.get('findings', []))}",
                message_type="completion"
            )

            logger.info(f"Agent {name} completed in background")

        except Exception as e:
            logger.error(f"Background agent {name} failed: {e}", exc_info=True)
            # Notify parent of failure
            graph = get_agent_graph()
            graph.send_message(
                from_id=new_agent.agent_id,
                to_id=agent_state.agent_id,
                content=f"Task failed: {str(e)}",
                message_type="error"
            )

    # Start background thread
    thread = threading.Thread(target=run_agent, daemon=True)
    thread.start()

    return {
        "status": "created",
        "agent_id": new_agent.agent_id,
        "agent_name": name,
        "message": f"Agent '{name}' created and running in background"
    }


@register_tool(sandbox_execution=False, description="Send message to another agent")
def send_message_to_agent(
    agent_state,
    target_agent_id: str,
    message: str,
    message_type: str = "info"
) -> Dict[str, Any]:
    """
    Send a message to another agent

    Args:
        target_agent_id: ID of the agent to send message to
        message: Message content
        message_type: Type of message (info, request, finding, error)

    Returns:
        Status dictionary
    """
    graph = get_agent_graph()

    graph.send_message(
        from_id=agent_state.agent_id,
        to_id=target_agent_id,
        content=message,
        message_type=message_type
    )

    logger.info(f"Message sent from {agent_state.agent_id} to {target_agent_id}")

    return {
        "status": "sent",
        "message": f"Message sent to agent {target_agent_id}"
    }


@register_tool(sandbox_execution=False, description="Get information about all active agents")
def view_agent_graph(agent_state) -> Dict[str, Any]:
    """
    View all active agents and their status

    Returns:
        Dictionary with all agents and their relationships
    """
    graph = get_agent_graph()

    return {
        "agents": graph.get_all_agents(),
        "message_count": len(graph.messages)
    }


@register_tool(sandbox_execution=False, description="Get child agents created by this agent")
def get_my_agents(agent_state) -> Dict[str, Any]:
    """
    Get list of child agents created by this agent

    Returns:
        List of child agent IDs and names
    """
    graph = get_agent_graph()
    children = graph.get_children(agent_state.agent_id)

    child_info = []
    for child_id in children:
        agent_info = graph.get_agent_info(child_id)
        if agent_info:
            child_info.append({
                "agent_id": child_id,
                "name": agent_info["name"],
                "status": agent_info["status"],
                "findings": agent_info["findings_count"]
            })

    return {
        "child_agents": child_info,
        "count": len(child_info)
    }


@register_tool(sandbox_execution=False, description="Mark agent task as complete")
def agent_finish(
    agent_state,
    result: str,
    summary: str = ""
) -> Dict[str, Any]:
    """
    Mark this agent's task as complete

    Args:
        result: Result summary (success, partial, failed)
        summary: Optional detailed summary of what was accomplished

    Returns:
        Completion status
    """
    agent_state.set_final_result({
        "result": result,
        "summary": summary,
        "findings": agent_state.get_findings(),
        "status": "completed"
    })

    logger.info(f"Agent {agent_state.agent_id} finished: {result}")

    return {
        "status": "finished",
        "message": "Agent task marked as complete"
    }


@register_tool(sandbox_execution=False, description="Create detailed vulnerability report with evidence")
def create_vulnerability_report(
    agent_state,
    title: str,
    severity: str,
    vulnerability_type: str,
    description: str,
    payload: str = "",
    evidence: str = "",
    remediation: str = "",
    affected_url: str = ""
) -> Dict[str, Any]:
    """
    Create a detailed vulnerability report with ACTUAL EVIDENCE from your scans

    Args:
        title: Short, specific title (e.g., "SQL Injection in /api/users?id= parameter")
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        vulnerability_type: Type (SQL_INJECTION, XSS, CSRF, IDOR, etc.)
        description: Detailed description explaining:
                    - What you tested
                    - What payload you used
                    - What response you received
                    - Why this is a security issue
        payload: EXACT attack payload that worked (e.g., "' OR '1'='1' --")
        evidence: ACTUAL results from the tool:
                 - HTTP status codes
                 - Error messages returned
                 - Response headers
                 - Database errors
                 - Script execution proof
                 Example: "Server returned: 'mysql error: syntax error near 1=1'"
        remediation: Recommended fix (input validation, parameterized queries, etc.)
        affected_url: Complete URL tested (e.g., "https://target.com/api/users?id=1")

    IMPORTANT: Include REAL scan results, not generic descriptions!

    Returns:
        Report creation status
    """
    # Validate severity
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if severity.upper() not in valid_severities:
        severity = "MEDIUM"

    # CRITICAL: Reject reports without evidence for CRITICAL/HIGH findings
    # This prevents hallucinated vulnerabilities
    if severity.upper() in ["CRITICAL", "HIGH"]:
        if not payload or not evidence:
            error_msg = (
                f"REJECTED: Cannot report {severity} vulnerability without proof!\n"
                f"Missing: {'payload' if not payload else ''} {'evidence' if not evidence else ''}\n"
                f"You MUST include:\n"
                f"  - payload: The exact attack string you used\n"
                f"  - evidence: The actual tool output showing the vulnerability\n"
                f"If you cannot provide these, the vulnerability is not confirmed."
            )
            logger.warning(f"Rejected vulnerability report: {title} - {error_msg}")
            return {
                "status": "rejected",
                "error": error_msg,
                "message": "Vulnerability report rejected due to missing evidence"
            }

        # Validate evidence is not generic/templated
        generic_phrases = [
            "likely vulnerable", "possibly vulnerable", "may be vulnerable",
            "could be exploited", "potentially exploitable", "appears to be",
            "seems to", "might contain", "could contain"
        ]
        evidence_lower = evidence.lower()
        if any(phrase in evidence_lower for phrase in generic_phrases):
            error_msg = (
                f"REJECTED: Evidence contains generic/uncertain language!\n"
                f"Evidence must show ACTUAL tool results, not assumptions.\n"
                f"Include: HTTP status codes, error messages, response bodies, etc."
            )
            logger.warning(f"Rejected vulnerability report: {title} - {error_msg}")
            return {
                "status": "rejected",
                "error": error_msg,
                "message": "Vulnerability report rejected due to generic evidence"
            }

    # CRITICAL: Validate affected_url matches the scan target
    # This prevents reporting vulnerabilities for placeholder/wrong domains
    if affected_url and agent_state.target:
        from urllib.parse import urlparse

        # Extract domain from scan target
        target_domain = urlparse(agent_state.target).netloc.lower()

        # Extract domain from affected URL
        affected_domain = urlparse(affected_url).netloc.lower()

        # Check for placeholder domains that should NEVER appear in reports
        forbidden_domains = [
            "actual-target.com", "actual-target-domain.com",
            "actual-scan-target.com", "example.com", "example.org",
            "betterandbliss.com", "betterandblissnew.com",
            "your-target.com", "target.com", "test.com"
        ]

        if affected_domain in forbidden_domains:
            error_msg = (
                f"REJECTED: Affected URL contains placeholder domain: {affected_domain}\n"
                f"You used: {affected_url}\n"
                f"You MUST use the actual scan target: {agent_state.target}\n"
                f"This is not a real vulnerability - you're reporting against a fake URL!"
            )
            logger.warning(f"Rejected vulnerability report: {title} - {error_msg}")
            return {
                "status": "rejected",
                "error": error_msg,
                "message": "Vulnerability report rejected due to placeholder URL"
            }

        # Validate affected domain matches target domain
        if affected_domain != target_domain:
            error_msg = (
                f"REJECTED: Affected URL domain doesn't match scan target!\n"
                f"Scan target: {agent_state.target} (domain: {target_domain})\n"
                f"Affected URL: {affected_url} (domain: {affected_domain})\n"
                f"You can only report vulnerabilities for the target you're scanning!"
            )
            logger.warning(f"Rejected vulnerability report: {title} - {error_msg}")
            return {
                "status": "rejected",
                "error": error_msg,
                "message": "Vulnerability report rejected due to domain mismatch"
            }

    finding = {
        "title": title,
        "severity": severity.upper(),
        "type": vulnerability_type.upper(),
        "description": description,
        "payload": payload,
        "evidence": evidence,
        "remediation": remediation,
        "affected_url": affected_url
    }

    agent_state.add_finding(finding)

    logger.info(
        f"Vulnerability report created: {title} ({severity}) "
        f"by agent {agent_state.agent_id}"
    )

    # Log finding discovery to database with FULL details
    graph = get_agent_graph()
    agent_info = graph.get_agent_info(agent_state.agent_id)
    agent_name = agent_info.get("name", "Unknown") if agent_info else "Unknown"

    # Create detailed log message with all evidence
    detailed_log = f"""{title}

**Severity:** {severity.upper()}
**Type:** {vulnerability_type}
**Affected URL:** {affected_url or 'N/A'}

**Description:**
{description}

**Payload Used:**
{payload or 'N/A'}

**Evidence:**
{evidence or 'No evidence provided'}

**Remediation:**
{remediation or 'N/A'}
"""

    log_finding_discovered(
        job_id=agent_state.job_id,
        finding_title=title,
        severity=severity,
        agent_name=agent_name,
        finding_details=detailed_log,  # Pass full details
        db_url=agent_state.db_url
    )

    # REAL-TIME DATABASE SAVE: Save finding to database immediately for UI display
    if agent_state.db_url:
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from models import Finding

            engine = create_engine(agent_state.db_url)
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()

            finding_record = Finding(
                pentest_job_id=agent_state.job_id,
                title=title,
                description=description,
                severity=severity.upper(),
                vulnerability_type=vulnerability_type.upper(),
                url=affected_url or "",
                payload=payload or "",
                discovered_by=agent_name
            )
            db.add(finding_record)
            db.commit()
            db.close()

            logger.info(f"✅ Saved finding to database: {title}")
        except Exception as e:
            logger.error(f"Failed to save finding to database: {e}")

    return {
        "status": "created",
        "finding_id": len(agent_state.get_findings()),
        "message": f"Vulnerability '{title}' reported successfully"
    }


@register_tool(sandbox_execution=False, description="Get current scan status and findings")
def get_scan_status(agent_state) -> Dict[str, Any]:
    """
    Get current status of the scan

    Returns:
        Status dictionary with iteration count, findings, etc.
    """
    graph = get_agent_graph()
    all_agents = graph.get_all_agents()

    # Aggregate findings from all agents
    total_findings = sum(agent["findings_count"] for agent in all_agents.values())

    return {
        "current_iteration": agent_state.iteration,
        "max_iterations": agent_state.max_iterations,
        "findings_by_this_agent": len(agent_state.get_findings()),
        "total_findings_all_agents": total_findings,
        "active_agents": len([a for a in all_agents.values() if a["status"] == "running"]),
        "total_agents": len(all_agents)
    }


@register_tool(sandbox_execution=False, description="Finish the entire security scan (root agent only)")
def finish_scan(
    agent_state,
    summary: str,
    total_findings: int = 0,
    all_agents_confirmed_complete: bool = False
) -> Dict[str, Any]:
    """
    Mark the entire security scan as complete (root agent only)

    ⚠️ CRITICAL REQUIREMENTS - Scan will FAIL if not met:
    1. ALL child agents MUST be status="completed"
    2. You MUST have received completion messages from ALL agents
    3. You MUST have analyzed all fuzzing results via Claude/MCP
    4. Findings MUST be confirmed as real vulnerabilities (not assumptions)
    5. Set all_agents_confirmed_complete=True to acknowledge above

    Calling this prematurely will:
    - Shut down Docker containers while agents are running
    - Lose in-progress scan data
    - Create incomplete reports

    Args:
        summary: Executive summary of the assessment
        total_findings: Total number of findings across all agents
        all_agents_confirmed_complete: REQUIRED confirmation that ALL agents finished

    Returns:
        Completion status or error if agents still running
    """
    # SAFETY CHECK: Verify all agents are actually complete
    graph = get_agent_graph()
    all_agents = graph.get_all_agents()

    # Check for running or pending agents
    incomplete_agents = [
        (agent_id, info)
        for agent_id, info in all_agents.items()
        if agent_id != agent_state.agent_id and info["status"] in ["running", "pending"]
    ]

    if incomplete_agents:
        incomplete_list = "\n".join([
            f"  - {agent_id}: {info['name']} (status: {info['status']})"
            for agent_id, info in incomplete_agents
        ])

        error_msg = f"""
❌ CANNOT FINISH SCAN - Agents still running!

The following agents have not completed:
{incomplete_list}

You MUST:
1. Wait for these agents to finish their work
2. Use get_my_agents to check their status
3. Only call finish_scan when ALL agents show status="completed"

⚠️ If you proceed now, containers will shut down and lose their work!
        """

        logger.error(error_msg)
        return {
            "status": "error",
            "error": "Cannot finish scan - agents still running",
            "incomplete_agents": [agent_id for agent_id, _ in incomplete_agents],
            "message": error_msg
        }

    if not all_agents_confirmed_complete:
        return {
            "status": "error",
            "error": "Missing confirmation",
            "message": "You must set all_agents_confirmed_complete=True to confirm all agents have finished"
        }

    # All checks passed - proceed with scan completion
    logger.info("✅ All agents confirmed complete - finishing scan")

    # Count findings by severity
    all_findings = agent_state.get_findings()

    # Add findings from child agents
    for agent_id, agent_info in all_agents.items():
        if agent_id != agent_state.agent_id:  # Skip self
            agent_instance = graph.agents.get(agent_id)
            if agent_instance:
                all_findings.extend(agent_instance.get_findings())

    critical = len([f for f in all_findings if f.get("severity") == "CRITICAL"])
    high = len([f for f in all_findings if f.get("severity") == "HIGH"])
    medium = len([f for f in all_findings if f.get("severity") == "MEDIUM"])
    low = len([f for f in all_findings if f.get("severity") == "LOW"])

    agent_state.set_final_result({
        "status": "completed",
        "summary": summary,
        "total_findings": len(all_findings),
        "findings_by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "agents_created": len(all_agents) - 1,  # Exclude root agent
        "findings": all_findings
    })

    logger.info(
        f"Scan completed by root agent {agent_state.agent_id}: "
        f"{len(all_findings)} total findings"
    )

    return {
        "status": "scan_complete",
        "total_findings": len(all_findings),
        "message": "Security assessment completed successfully"
    }
