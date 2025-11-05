"""FetchBot.ai REST API"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
import asyncio

from models import Organization, PentestJob, Finding, JobStatus, init_db, get_db
from aws_manager import AWSManager
from bot_orchestrator import BotOrchestrator

app = FastAPI(title="FetchBot.ai API", version="1.0.0")
security = HTTPBearer()
aws_manager = AWSManager()

init_db()

class OrganizationCreate(BaseModel):
    name: str
    admin_email: EmailStr
    allowed_targets: List[str] = []

class PentestJobCreate(BaseModel):
    name: str
    target: str
    mode: str = "discovery"

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
        
        orchestrator = BotOrchestrator(org_elastic_ip)
        results = await orchestrator.execute_pentest(target)
        
        for finding_data in results['findings']:
            finding = Finding(
                pentest_job_id=job_id,
                title=finding_data['title'],
                severity=finding_data['severity'],
                vulnerability_type=finding_data['type'],
                url=finding_data['url'],
                payload=finding_data['payload'],
                discovered_by=finding_data['discovered_by']
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

@app.get("/health")
async def health_check():
    return {"status": "healthy", "platform": "FetchBot.ai"}
