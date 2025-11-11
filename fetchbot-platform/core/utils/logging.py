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
    """Log agent creation"""
    add_execution_log(
        job_id=job_id,
        action=f"Created {agent_name}",
        details=f"Agent spawned by {parent_agent}",
        agent=parent_agent,
        db_url=db_url
    )


def log_tool_execution(job_id: str, tool_name: str, agent_name: str, target: str, db_url: Optional[str] = None):
    """Log tool execution"""
    add_execution_log(
        job_id=job_id,
        action=f"Executing {tool_name}",
        details=f"Running {tool_name} on {target}",
        agent=agent_name,
        db_url=db_url
    )


def log_finding_discovered(
    job_id: str,
    finding_title: str,
    severity: str,
    agent_name: str,
    finding_details: str = None,
    db_url: Optional[str] = None
):
    """
    Log vulnerability discovered with full details

    Args:
        job_id: Scan job ID
        finding_title: Short title of vulnerability
        severity: Severity level (CRITICAL, HIGH, etc.)
        agent_name: Name of agent that found it
        finding_details: Full detailed report (description, evidence, remediation)
        db_url: Database URL
    """
    # Use detailed log if provided, otherwise just title
    details_text = finding_details if finding_details else finding_title

    add_execution_log(
        job_id=job_id,
        action=f"Found {severity.upper()} vulnerability",
        details=details_text,
        agent=agent_name,
        db_url=db_url
    )


def log_scan_status(job_id: str, status: str, details: str, db_url: Optional[str] = None):
    """Log scan status change"""
    add_execution_log(
        job_id=job_id,
        action=f"Scan status: {status}",
        details=details,
        agent="System",
        db_url=db_url
    )
