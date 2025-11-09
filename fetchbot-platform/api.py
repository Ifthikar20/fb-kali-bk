"""FetchBot.ai REST API"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
import asyncio
import os

from models import Organization, PentestJob, Finding, JobStatus, init_db, get_db
from config import get_settings

# Detect which orchestrator to use based on environment
USE_DYNAMIC_AGENTS = os.environ.get('USE_DYNAMIC_AGENTS', 'false').lower() == 'true'
USE_MULTI_KALI = os.environ.get('NUM_KALI_AGENTS')

if USE_DYNAMIC_AGENTS:
    from core.orchestrator import DynamicOrchestrator as OrchestratorClass
    NUM_AGENTS = 0
    print("[INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)")
elif USE_MULTI_KALI:
    from multi_kali_orchestrator import MultiKaliOrchestrator as OrchestratorClass
    NUM_AGENTS = int(USE_MULTI_KALI)
    print(f"[INIT] Using Multi-Kali orchestrator with {NUM_AGENTS} agents")
else:
    from bot_orchestrator import BotOrchestrator as OrchestratorClass
    NUM_AGENTS = 0
    print("[INIT] Using specialized bots orchestrator")

app = FastAPI(title="FetchBot.ai API", version="1.0.0")

# Configure CORS to allow frontend on port 8080
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",  # Common React dev port
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allow all headers including Authorization
)

security = HTTPBearer()

# Lazy-load AWS manager only when needed (for EC2 deployments)
_aws_manager = None

def get_aws_manager():
    """Get AWS manager instance (lazy initialization)"""
    global _aws_manager
    if _aws_manager is None:
        from aws_manager import AWSManager
        settings = get_settings()

        # Check if AWS credentials are configured
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            raise HTTPException(
                status_code=500,
                detail="AWS credentials not configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
            )

        _aws_manager = AWSManager()
    return _aws_manager

init_db()

class OrganizationCreate(BaseModel):
    name: str
    admin_email: EmailStr
    allowed_targets: List[str] = []

class PentestJobCreate(BaseModel):
    name: str
    target: str
    mode: str = "discovery"

class ScanCreate(BaseModel):
    target: str
    organization_id: Optional[int] = None

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security), 
                   db: Session = Depends(get_db)) -> Organization:
    """Verify API key"""
    api_key = credentials.credentials
    org = db.query(Organization).filter(Organization.api_key == api_key).first()
    if not org or not org.active:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return org

@app.post("/api/organizations")
async def create_organization(org_data: OrganizationCreate, db: Session = Depends(get_db)):
    """Create organization with AWS EC2 instance"""
    slug = org_data.name.lower().replace(' ', '-')
    
    existing = db.query(Organization).filter(Organization.slug == slug).first()
    if existing:
        raise HTTPException(status_code=400, detail="Organization exists")
    
    org = Organization(
        name=org_data.name,
        slug=slug,
        admin_email=org_data.admin_email
    )
    
    db.add(org)
    db.commit()
    db.refresh(org)
    
    try:
        aws_manager = get_aws_manager()
        infra = aws_manager.create_organization_infrastructure(org.name, org.id)
        
        org.ec2_instance_id = infra['instance_id']
        org.elastic_ip = infra['elastic_ip']
        org.elastic_ip_allocation_id = infra['allocation_id']
        org.ec2_running = True
        
        db.commit()
        db.refresh(org)
        
        return {
            'id': org.id,
            'name': org.name,
            'api_key': org.api_key,
            'elastic_ip': org.elastic_ip,
            'ec2_instance_id': org.ec2_instance_id
        }
        
    except Exception as e:
        db.delete(org)
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/organizations/me")
async def get_my_organization(org: Organization = Depends(verify_api_key)):
    """Get organization details"""
    return {
        'id': org.id,
        'name': org.name,
        'elastic_ip': org.elastic_ip,
        'ec2_running': org.ec2_running
    }

async def run_pentest_job(job_id: str, org_elastic_ip: str, target: str, db_url: str):
    """Background task to run pentest"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    try:
        job = db.query(PentestJob).filter(PentestJob.id == job_id).first()
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        db.commit()

        # Create orchestrator (multi-kali or specialized bots)
        if USE_MULTI_KALI:
            orchestrator = OrchestratorClass(org_elastic_ip, num_agents=NUM_AGENTS)
        else:
            orchestrator = OrchestratorClass(org_elastic_ip)

        # Call the correct method based on orchestrator type
        if USE_DYNAMIC_AGENTS:
            results = await orchestrator.run_scan(target, job_id)
        else:
            results = await orchestrator.execute_pentest(target)
        
        for finding_data in results['findings']:
            finding = Finding(
                pentest_job_id=job_id,
                title=finding_data.get('title', 'Unknown'),
                severity=finding_data.get('severity', 'info'),
                vulnerability_type=finding_data.get('type', 'unknown'),
                url=finding_data.get('url'),
                payload=finding_data.get('payload'),
                discovered_by=finding_data.get('discovered_by', 'unknown')
            )
            db.add(finding)
        
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.utcnow()
        job.total_findings = len(results['findings'])
        
        from collections import Counter
        severity_counts = Counter(f['severity'] for f in results['findings'])
        job.critical_count = severity_counts.get('critical', 0)
        job.high_count = severity_counts.get('high', 0)
        
        db.commit()
        
    except Exception as e:
        print(f"[JOB] Failed: {e}")
        job.status = JobStatus.FAILED
        db.commit()
    finally:
        db.close()

async def run_dynamic_scan(job_id: str, org_elastic_ip: str, target: str, db_url: str):
    """Background task to run dynamic agent scan"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        job = db.query(PentestJob).filter(PentestJob.id == job_id).first()
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        db.commit()

        # Create dynamic orchestrator
        orchestrator = OrchestratorClass(org_elastic_ip)

        # Run dynamic scan
        results = await orchestrator.run_scan(target, job_id)

        # Store findings
        for finding_data in results.get('findings', []):
            finding = Finding(
                pentest_job_id=job_id,
                title=finding_data.get('title', 'Unknown'),
                description=finding_data.get('description', ''),
                severity=finding_data.get('severity', 'info'),
                vulnerability_type=finding_data.get('type', 'unknown'),
                url=finding_data.get('affected_url') or finding_data.get('url'),
                payload=finding_data.get('payload'),
                discovered_by=finding_data.get('discovered_by', 'Dynamic Agent')
            )
            db.add(finding)

        job.status = JobStatus.COMPLETED if results.get('status') == 'completed' else JobStatus.FAILED
        job.completed_at = datetime.utcnow()
        job.total_findings = results.get('total_findings', len(results.get('findings', [])))
        job.critical_count = results.get('critical_findings', 0)
        job.high_count = results.get('high_findings', 0)

        db.commit()

    except Exception as e:
        print(f"[DYNAMIC SCAN] Failed: {e}")
        import traceback
        traceback.print_exc()
        job.status = JobStatus.FAILED
        db.commit()
    finally:
        db.close()

@app.post("/api/pentest")
async def create_pentest_job(
    job_data: PentestJobCreate,
    background_tasks: BackgroundTasks,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Create and start pentest job"""
    from config import get_settings
    settings = get_settings()
    
    job = PentestJob(
        organization_id=org.id,
        name=job_data.name,
        target=job_data.target,
        attack_ip=org.elastic_ip,
        status=JobStatus.QUEUED
    )
    
    db.add(job)
    db.commit()
    db.refresh(job)
    
    background_tasks.add_task(
        run_pentest_job,
        job.id,
        org.elastic_ip,
        job_data.target,
        settings.database_url
    )
    
    return {
        'id': job.id,
        'name': job.name,
        'target': job.target,
        'status': job.status.value,
        'attack_ip': job.attack_ip
    }

@app.get("/api/pentest/{job_id}")
async def get_pentest_job(
    job_id: str,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Get pentest job status"""
    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {
        'id': job.id,
        'name': job.name,
        'target': job.target,
        'status': job.status.value,
        'attack_ip': job.attack_ip,
        'total_findings': job.total_findings,
        'critical_count': job.critical_count,
        'high_count': job.high_count
    }

@app.get("/api/pentest/{job_id}/findings")
async def get_job_findings(
    job_id: str,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Get findings for job"""
    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    findings = db.query(Finding).filter(Finding.pentest_job_id == job_id).all()
    
    return {
        'job_id': job_id,
        'total': len(findings),
        'findings': [
            {
                'id': f.id,
                'title': f.title,
                'severity': f.severity.value,
                'vulnerability_type': f.vulnerability_type,
                'url': f.url,
                'discovered_by': f.discovered_by
            }
            for f in findings
        ]
    }

@app.get("/api/pentest/{job_id}/report/{format}")
async def get_job_report(
    job_id: str,
    format: str,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Generate report for pentest job"""
    from fastapi.responses import HTMLResponse, PlainTextResponse
    from report_generator import ReportGenerator

    # Validate format
    if format not in ['html', 'json', 'markdown']:
        raise HTTPException(status_code=400, detail="Invalid format. Use: html, json, or markdown")

    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Get all findings
    findings = db.query(Finding).filter(Finding.pentest_job_id == job_id).all()

    # Prepare data
    pentest_data = {
        'target': job.target,
        'attack_ip': job.attack_ip,
        'timestamp': job.created_at.isoformat() if job.created_at else None,
        'findings': [
            {
                'title': f.title,
                'description': f.description,
                'severity': f.severity.value,
                'type': f.vulnerability_type,
                'url': f.url,
                'payload': f.payload,
                'discovered_by': f.discovered_by,
                'evidence': f.poc_code
            }
            for f in findings
        ],
        'analysis': f"Security assessment completed for {job.target}. Total findings: {len(findings)}",
        'scan_history': []
    }

    generator = ReportGenerator()

    if format == 'html':
        html_report = generator.generate_html_report(pentest_data)
        return HTMLResponse(content=html_report)

    elif format == 'json':
        json_report = generator.generate_json_report(pentest_data)
        return PlainTextResponse(content=json_report, media_type="application/json")

    elif format == 'markdown':
        md_report = generator.generate_markdown_report(pentest_data)
        return PlainTextResponse(content=md_report, media_type="text/markdown")

@app.post("/scan")
async def start_dynamic_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Start a dynamic multi-agent security scan"""
    from config import get_settings
    settings = get_settings()

    # Create job with generic name
    job = PentestJob(
        organization_id=org.id,
        name=f"Dynamic Scan - {scan_data.target}",
        target=scan_data.target,
        attack_ip=org.elastic_ip,
        status=JobStatus.QUEUED
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    # Start dynamic scan in background
    background_tasks.add_task(
        run_dynamic_scan,
        job.id,
        org.elastic_ip,
        scan_data.target,
        settings.database_url
    )

    return {
        "job_id": job.id,
        "status": job.status.value,
        "message": "Dynamic security assessment started",
        "target": scan_data.target
    }


@app.get("/scan/{job_id}")
async def get_scan_status(
    job_id: str,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Get scan status with findings"""
    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get findings
    findings = db.query(Finding).filter(Finding.pentest_job_id == job_id).all()

    # Format findings
    formatted_findings = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "type": f.vulnerability_type,
            "description": f.description,
            "discovered_by": f.discovered_by,
            "payload": f.payload,
            "evidence": f.poc_code,
            "url": f.url
        }
        for f in findings
    ]

    # Calculate execution time
    execution_time = None
    if job.started_at and job.completed_at:
        execution_time = (job.completed_at - job.started_at).total_seconds()
    elif job.started_at:
        execution_time = (datetime.utcnow() - job.started_at).total_seconds()

    response = {
        "job_id": job.id,
        "status": job.status.value,
        "target": job.target,
        "findings": formatted_findings,
        "total_findings": job.total_findings or len(findings),
        "critical_findings": job.critical_count or 0,
        "high_findings": job.high_count or 0
    }

    if execution_time is not None:
        response["execution_time_seconds"] = execution_time

    # Add agent info placeholder (will be populated from agent graph)
    if job.status.value in ["completed", "running"]:
        response["agents_created"] = []  # Frontend should call /scan/{job_id}/agent-graph for details

    return response


@app.get("/scan/{job_id}/agent-graph")
async def get_agent_graph(
    job_id: str,
    org: Organization = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Get agent hierarchy graph for visualization"""
    # Verify job exists and belongs to organization
    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get agent graph from dynamic orchestrator
    if not USE_DYNAMIC_AGENTS:
        return {
            "job_id": job_id,
            "message": "Agent graph only available for dynamic scans",
            "graph": {"nodes": [], "edges": []}
        }

    try:
        orchestrator = OrchestratorClass(org.elastic_ip)
        graph_data = await orchestrator.get_agent_graph(job_id)
        return graph_data
    except Exception as e:
        return {
            "job_id": job_id,
            "error": str(e),
            "graph": {"nodes": [], "edges": []}
        }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "platform": "FetchBot.ai"}
