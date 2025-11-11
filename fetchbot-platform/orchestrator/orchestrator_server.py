"""
Orchestrator FastAPI Server

Coordinates specialized security testing agents and manages work distribution
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

import sys
sys.path.insert(0, '/app')

from core.agents.specialized_orchestrator import SpecializedAgentOrchestrator

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)


# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    job_id: Optional[str] = None


class AgentRegistration(BaseModel):
    agent_id: str
    agent_type: str
    tools: list


class WorkRequest(BaseModel):
    agent_id: str
    agent_type: str


class WorkCompletion(BaseModel):
    agent_id: str
    agent_type: str
    work_item: dict
    result: dict


class WorkFailure(BaseModel):
    agent_id: str
    work_item: dict
    error: str


# FastAPI app
app = FastAPI(
    title="Specialized Agent Orchestrator",
    version="1.0.0",
    description="Coordinates specialized security testing agents"
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",  # Frontend dev server
        "http://localhost:3000",  # Alternative React dev port
        "https://yourdomain.com", # Production frontend
        "*"  # Allow all origins (remove in production)
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Global orchestrator instance (will be set per scan)
active_orchestrators: Dict[str, SpecializedAgentOrchestrator] = {}


@app.post("/scans/start")
async def start_scan(request: ScanRequest):
    """
    Start a new security scan

    Creates an orchestrator instance and initializes the scan
    """
    # Generate job_id if not provided
    job_id = request.job_id or f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    logger.info(f"Starting scan for {request.target} (job_id: {job_id})")

    try:
        # Create orchestrator for this scan
        orchestrator = SpecializedAgentOrchestrator(
            target=request.target,
            job_id=job_id
        )

        # Store orchestrator
        active_orchestrators[job_id] = orchestrator

        # Initialize scan (queue initial work)
        init_result = await orchestrator.initialize_scan()

        logger.info(f"Scan initialized: {job_id}")

        return {
            "status": "started",
            "job_id": job_id,
            "target": request.target,
            "initialization": init_result
        }

    except Exception as e:
        logger.error(f"Error starting scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/{job_id}/status")
async def get_scan_status(job_id: str):
    """Get status of a running scan"""
    if job_id not in active_orchestrators:
        raise HTTPException(status_code=404, detail=f"Scan {job_id} not found")

    orchestrator = active_orchestrators[job_id]

    try:
        status = await orchestrator.get_status()
        return status

    except Exception as e:
        logger.error(f"Error getting status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/{job_id}/finalize")
async def finalize_scan(job_id: str):
    """
    Finalize a scan and generate final report

    Returns complete scan results
    """
    if job_id not in active_orchestrators:
        raise HTTPException(status_code=404, detail=f"Scan {job_id} not found")

    orchestrator = active_orchestrators[job_id]

    try:
        final_report = await orchestrator.finalize_scan()

        logger.info(f"Scan finalized: {job_id}")

        return final_report

    except Exception as e:
        logger.error(f"Error finalizing scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agents/register")
async def register_agent(registration: AgentRegistration):
    """
    Register an agent with the orchestrator

    Agents call this on startup to announce their availability
    """
    logger.info(
        f"Registering agent: {registration.agent_id} "
        f"(type: {registration.agent_type})"
    )

    # Register with all active orchestrators
    for job_id, orchestrator in active_orchestrators.items():
        try:
            await orchestrator.register_agent(
                agent_id=registration.agent_id,
                agent_type=registration.agent_type,
                tools=registration.tools
            )
        except Exception as e:
            logger.warning(
                f"Error registering agent with orchestrator {job_id}: {e}"
            )

    return {
        "status": "registered",
        "agent_id": registration.agent_id,
        "registered_to_scans": len(active_orchestrators)
    }


@app.post("/work/get")
async def get_work(request: WorkRequest):
    """
    Get next work item for an agent

    Called by agents when they're ready for more work
    """
    # Find an active scan that has work for this agent type
    for job_id, orchestrator in active_orchestrators.items():
        try:
            work_item = await orchestrator.get_work_for_agent(
                agent_id=request.agent_id,
                agent_type=request.agent_type
            )

            if work_item:
                # Add job_id to work item so agent knows which scan it belongs to
                work_item["job_id"] = job_id

                return {
                    "work_item": work_item
                }

        except Exception as e:
            logger.error(f"Error getting work from orchestrator {job_id}: {e}")

    # No work available
    return {
        "work_item": None
    }


@app.post("/work/complete")
async def complete_work(completion: WorkCompletion):
    """
    Report work completion from an agent

    Called when an agent finishes a work item
    """
    work_item = completion.work_item
    job_id = work_item.get("job_id")

    if not job_id or job_id not in active_orchestrators:
        logger.warning(f"Received completion for unknown job: {job_id}")
        return {"status": "acknowledged"}

    orchestrator = active_orchestrators[job_id]

    try:
        await orchestrator.report_work_completion(
            agent_id=completion.agent_id,
            work_item=work_item,
            result=completion.result
        )

        logger.info(
            f"Work completed by {completion.agent_id}: {work_item['tool']}"
        )

        return {"status": "completed"}

    except Exception as e:
        logger.error(f"Error reporting completion: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/work/fail")
async def fail_work(failure: WorkFailure):
    """
    Report work failure from an agent

    Called when an agent fails to complete a work item
    """
    work_item = failure.work_item
    job_id = work_item.get("job_id")

    if not job_id or job_id not in active_orchestrators:
        logger.warning(f"Received failure for unknown job: {job_id}")
        return {"status": "acknowledged"}

    orchestrator = active_orchestrators[job_id]

    try:
        await orchestrator.report_work_failure(
            agent_id=failure.agent_id,
            work_item=work_item,
            error=failure.error
        )

        logger.warning(
            f"Work failed by {failure.agent_id}: {work_item['tool']}: {failure.error}"
        )

        return {"status": "acknowledged"}

    except Exception as e:
        logger.error(f"Error reporting failure: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "specialized-agent-orchestrator",
        "active_scans": len(active_orchestrators),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/stats")
async def get_stats():
    """Get orchestrator statistics"""
    stats = {
        "active_scans": len(active_orchestrators),
        "scans": {}
    }

    for job_id, orchestrator in active_orchestrators.items():
        try:
            status = await orchestrator.get_status()
            stats["scans"][job_id] = {
                "target": status["target"],
                "status": status["status"],
                "findings": status["findings"]["total"],
                "queue_status": status["queue_status"]
            }
        except Exception as e:
            logger.error(f"Error getting stats for {job_id}: {e}")

    return stats


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get('ORCHESTRATOR_PORT', 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
