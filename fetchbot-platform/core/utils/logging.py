"""
Execution Logging Utilities

Provides functions to log scan execution steps to the database
for real-time UI updates.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)


def add_execution_log(
    job_id: str,
    action: str,
    details: str,
    agent: str = "System",
    db_url: Optional[str] = None
):
    """
    Add an execution log entry to a scan job

    Args:
        job_id: Job/Scan ID
        action: Action being performed (e.g., "Created Agent", "Running Tool")
        details: Detailed description
        agent: Agent performing the action
        db_url: Database URL (if not provided, logs only to console)

    Example:
        add_execution_log(
            job_id="abc-123",
            action="Created Recon Agent",
            details="Starting reconnaissance phase",
            agent="Root Coordinator"
        )
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent": agent,
        "action": action,
        "details": details
    }

    # Always log to console
    logger.info(f"[{agent}] {action}: {details}")

    # If database URL provided, add to execution_logs
    if db_url:
        try:
            from models import PentestJob

            engine = create_engine(db_url)
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()

            job = db.query(PentestJob).filter(PentestJob.id == job_id).first()
            if job:
                # Initialize logs if None
                if job.execution_logs is None:
                    job.execution_logs = []

                # Append new log entry
                job.execution_logs = job.execution_logs + [log_entry]

                db.commit()

            db.close()
        except Exception as e:
            logger.error(f"Failed to add execution log to database: {e}")


def log_agent_created(job_id: str, agent_name: str, parent_agent: str, db_url: Optional[str] = None):
    """Log agent creation with descriptive message"""

    # Map agent types to descriptive purposes
    agent_purposes = {
        "Reconnaissance Agent": "to discover target architecture and technologies",
        "SQL Injection Agent": "to test for SQL injection vulnerabilities",
        "XSS Testing Agent": "to test for cross-site scripting vulnerabilities",
        "API Security Agent": "to test API endpoints for security issues",
        "Authentication Testing Agent": "to test authentication and authorization mechanisms",
        "Focused Reconnaissance Agent": "to perform targeted reconnaissance",
        "Comprehensive Reconnaissance Agent": "to perform deep reconnaissance",
    }

    # Get purpose or use generic message
    purpose = agent_purposes.get(agent_name, "to perform specialized security testing")

    add_execution_log(
        job_id=job_id,
        action=f"🤖 Spawned {agent_name}",
        details=f"Created specialized agent {purpose}",
        agent=parent_agent,
        db_url=db_url
    )


def log_tool_execution(job_id: str, tool_name: str, agent_name: str, target: str, db_url: Optional[str] = None):
    """Log tool execution with user-friendly descriptions"""

    # Map tool names to descriptive actions
    tool_descriptions = {
        "nmap_scan": ("🔍 Port Scanning", f"Scanning {target} to discover open ports and running services"),
        "http_scan": ("🌐 Web Analysis", f"Analyzing website structure and technologies at {target}"),
        "dns_enumerate": ("📡 DNS Discovery", f"Enumerating DNS records and subdomains for {target}"),
        "resolve_domain": ("🔎 Domain Resolution", f"Resolving {target} to IP address"),
        "javascript_analysis": ("📜 JavaScript Scan", f"Analyzing JavaScript files at {target} for sensitive data"),
        "security_headers_check": ("🛡️ Security Headers", f"Checking security headers at {target}"),
        "sql_injection_test": ("💉 SQL Injection Test", f"Testing {target} for SQL injection vulnerabilities"),
        "xss_test": ("⚠️ XSS Testing", f"Testing {target} for cross-site scripting vulnerabilities"),
        "api_fuzzing": ("🎯 API Fuzzing", f"Fuzzing API endpoints at {target} with malicious payloads"),
        "api_brute_force": ("🔐 Auth Testing", f"Testing authentication mechanisms at {target}"),
        "api_idor_test": ("🔓 IDOR Testing", f"Testing for insecure direct object references at {target}"),
        "api_rate_limit_test": ("⏱️ Rate Limit Check", f"Checking rate limiting implementation at {target}"),
        "api_privilege_escalation_test": ("🔺 Privilege Test", f"Testing for privilege escalation at {target}"),
        "detect_exposed_env_vars": ("🔑 Secrets Detection", f"Scanning {target} for exposed environment variables"),
        "service_detection": ("🔧 Service Detection", f"Identifying services running on {target}"),
    }

    # Get description or use default
    action, details = tool_descriptions.get(
        tool_name,
        (f"Running {tool_name}", f"Executing {tool_name} on {target}")
    )

    add_execution_log(
        job_id=job_id,
        action=action,
        details=details,
        agent=agent_name,
        db_url=db_url
    )


def log_finding_discovered(job_id: str, finding_title: str, severity: str, agent_name: str, db_url: Optional[str] = None):
    """Log vulnerability discovered"""

    # Severity emojis for visibility
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "ℹ️"
    }

    icon = severity_icons.get(severity.upper(), "⚠️")

    add_execution_log(
        job_id=job_id,
        action=f"{icon} {severity.upper()} Vulnerability Found",
        details=finding_title,
        agent=agent_name,
        db_url=db_url
    )


def log_scan_status(job_id: str, status: str, details: str, db_url: Optional[str] = None):
    """Log scan status change"""

    # Status emojis
    status_icons = {
        "started": "🚀",
        "running": "⚡",
        "completed": "✅",
        "failed": "❌"
    }

    icon = status_icons.get(status.lower(), "📊")

    add_execution_log(
        job_id=job_id,
        action=f"{icon} Scan {status.title()}",
        details=details,
        agent="System",
        db_url=db_url
    )
