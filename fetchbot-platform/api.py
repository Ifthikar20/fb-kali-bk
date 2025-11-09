"""FetchBot.ai REST API"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import asyncio
import os
import logging

from models import Organization, PentestJob, Finding, User, JobStatus, init_db, get_db
from config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# Log startup information
logger.info("=" * 80)
logger.info("FetchBot.ai API Starting")
logger.info(f"Dynamic Agents Enabled: {USE_DYNAMIC_AGENTS}")
logger.info(f"Orchestrator: {OrchestratorClass.__name__}")
logger.info(f"Logging Level: INFO")
logger.info("=" * 80)

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

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    organization_id: str  # Users must belong to an organization

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    username: str
    organization_id: str

# JWT Helper Functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    settings = get_settings()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)  # Default 7 days
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm="HS256")
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security),
                 db: Session = Depends(get_db)) -> User:
    """Verify JWT token and return user"""
    settings = get_settings()
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security),
                   db: Session = Depends(get_db)) -> Organization:
    """Verify API key"""
    api_key = credentials.credentials
    org = db.query(Organization).filter(Organization.api_key == api_key).first()
    if not org or not org.active:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return org

def verify_user_or_api_key(credentials: HTTPAuthorizationCredentials = Depends(security),
                            db: Session = Depends(get_db)) -> tuple[Organization, Optional[User]]:
    """Verify either JWT token or API key, return (organization, user)"""
    token = credentials.credentials
    settings = get_settings()

    # Try JWT token first
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if user and user.active:
                org = db.query(Organization).filter(Organization.id == user.organization_id).first()
                if org:
                    return org, user
    except JWTError:
        pass

    # Try API key
    org = db.query(Organization).filter(Organization.api_key == token).first()
    if org and org.active:
        return org, None

    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/organizations")
async def create_organization(org_data: OrganizationCreate, db: Session = Depends(get_db)):
    """Create organization with optional AWS EC2 instance"""
    logger.info(f"[CREATE ORG] Creating organization: {org_data.name}, admin email: {org_data.admin_email}")

    slug = org_data.name.lower().replace(' ', '-')

    existing = db.query(Organization).filter(Organization.slug == slug).first()
    if existing:
        logger.warning(f"[CREATE ORG] Organization with slug '{slug}' already exists")
        raise HTTPException(status_code=400, detail="Organization exists")

    org = Organization(
        name=org_data.name,
        slug=slug,
        admin_email=org_data.admin_email
    )

    db.add(org)
    db.commit()
    db.refresh(org)

    logger.info(f"[CREATE ORG] Organization created in database: ID={org.id}, API Key={org.api_key[:15]}...")

    # Try to create AWS infrastructure (optional for local testing)
    settings = get_settings()
    aws_enabled = settings.aws_access_key_id and settings.aws_secret_access_key and \
                  settings.aws_access_key_id != "your_aws_access_key_id"

    logger.info(f"[CREATE ORG] AWS enabled: {aws_enabled}")

    if aws_enabled:
        try:
            logger.info(f"[CREATE ORG] Attempting to create AWS infrastructure for org {org.id}")
            aws_manager = get_aws_manager()
            infra = aws_manager.create_organization_infrastructure(org.name, org.id)

            org.ec2_instance_id = infra['instance_id']
            org.elastic_ip = infra['elastic_ip']
            org.elastic_ip_allocation_id = infra['allocation_id']
            org.ec2_running = True

            db.commit()
            db.refresh(org)

            logger.info(f"[CREATE ORG] AWS infrastructure created successfully: IP={org.elastic_ip}, Instance={org.ec2_instance_id}")

            return {
                'id': org.id,
                'name': org.name,
                'api_key': org.api_key,
                'elastic_ip': org.elastic_ip,
                'ec2_instance_id': org.ec2_instance_id,
                'mode': 'aws'
            }

        except Exception as e:
            # AWS failed, but keep organization for local testing
            logger.warning(f"[CREATE ORG] AWS infrastructure creation failed: {e}")
            logger.info(f"[CREATE ORG] Falling back to local-only mode for org {org.id}")
            org.elastic_ip = "127.0.0.1"  # Use localhost for local testing
            db.commit()
            db.refresh(org)
    else:
        # No AWS configured - local testing mode
        logger.info(f"[CREATE ORG] AWS not configured - creating org {org.id} in local-only mode")
        org.elastic_ip = "127.0.0.1"  # Use localhost for local testing
        db.commit()
        db.refresh(org)

    response = {
        'id': org.id,
        'name': org.name,
        'api_key': org.api_key,
        'elastic_ip': org.elastic_ip,
        'ec2_instance_id': org.ec2_instance_id,
        'mode': 'local' if not aws_enabled else 'aws'
    }

    logger.info(f"[CREATE ORG] Organization {org.id} created successfully in {response['mode']} mode, IP: {org.elastic_ip}")

    return response

@app.get("/api/organizations/me")
async def get_my_organization(org: Organization = Depends(verify_api_key)):
    """Get organization details"""
    return {
        'id': org.id,
        'name': org.name,
        'elastic_ip': org.elastic_ip,
        'ec2_running': org.ec2_running
    }

@app.post("/api/register", response_model=Token)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    logger.info(f"[REGISTER] Registration attempt for username: {user_data.username}, email: {user_data.email}")

    # Check if username exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        logger.warning(f"[REGISTER] Username '{user_data.username}' already exists")
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check if email exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        logger.warning(f"[REGISTER] Email '{user_data.email}' already registered")
        raise HTTPException(status_code=400, detail="Email already registered")

    # Check if organization exists
    org = db.query(Organization).filter(Organization.id == user_data.organization_id).first()
    if not org:
        logger.warning(f"[REGISTER] Organization {user_data.organization_id} not found")
        raise HTTPException(status_code=404, detail="Organization not found")

    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        organization_id=user_data.organization_id
    )
    user.set_password(user_data.password)

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"[REGISTER] User created successfully: {user.id}, username: {user.username}, org: {user.organization_id}")

    # Create access token
    access_token = create_access_token(data={"sub": user.id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "organization_id": user.organization_id
    }

@app.post("/api/login", response_model=Token)
async def login_user(login_data: UserLogin, db: Session = Depends(get_db)):
    """Login user and return JWT token"""
    logger.info(f"[LOGIN] Login attempt for username: {login_data.username}")

    # Find user
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not user.check_password(login_data.password):
        logger.warning(f"[LOGIN] Failed login for username: {login_data.username} (invalid credentials)")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.active:
        logger.warning(f"[LOGIN] Failed login for username: {login_data.username} (account disabled)")
        raise HTTPException(status_code=401, detail="User account is disabled")

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    logger.info(f"[LOGIN] Successful login for user: {user.id}, username: {user.username}, org: {user.organization_id}")

    # Create access token
    access_token = create_access_token(data={"sub": user.id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "organization_id": user.organization_id
    }

@app.get("/api/me")
async def get_current_user(user: User = Depends(verify_token)):
    """Get current logged in user info"""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "organization_id": user.organization_id,
        "is_admin": user.is_admin
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

    logger.info(f"[BACKGROUND TASK] Starting dynamic scan for job {job_id}, target: {target}")

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        job = db.query(PentestJob).filter(PentestJob.id == job_id).first()
        if not job:
            logger.error(f"[BACKGROUND TASK] Job {job_id} not found in database!")
            return

        logger.info(f"[BACKGROUND TASK] Job {job_id} found, setting status to RUNNING")
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        db.commit()

        # Create dynamic orchestrator
        logger.info(f"[BACKGROUND TASK] Creating orchestrator for IP: {org_elastic_ip}")
        orchestrator = OrchestratorClass(org_elastic_ip)

        # Run dynamic scan
        logger.info(f"[BACKGROUND TASK] Starting orchestrator.run_scan() for {target}")
        results = await orchestrator.run_scan(target, job_id)
        logger.info(f"[BACKGROUND TASK] Orchestrator finished. Results keys: {list(results.keys())}")
        logger.info(f"[BACKGROUND TASK] Results status: {results.get('status')}, findings count: {len(results.get('findings', []))}")

        # Store findings
        findings_count = len(results.get('findings', []))
        logger.info(f"[BACKGROUND TASK] Storing {findings_count} findings to database")

        for idx, finding_data in enumerate(results.get('findings', [])):
            logger.debug(f"[BACKGROUND TASK] Storing finding {idx+1}/{findings_count}: {finding_data.get('title', 'Unknown')}")
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

        final_status = JobStatus.COMPLETED if results.get('status') == 'completed' else JobStatus.FAILED
        logger.info(f"[BACKGROUND TASK] Setting job status to {final_status.value}")

        job.status = final_status
        job.completed_at = datetime.utcnow()
        job.total_findings = results.get('total_findings', len(results.get('findings', [])))
        job.critical_count = results.get('critical_findings', 0)
        job.high_count = results.get('high_findings', 0)

        db.commit()
        logger.info(f"[BACKGROUND TASK] Job {job_id} completed successfully. Total findings: {job.total_findings}, Critical: {job.critical_count}, High: {job.high_count}")

    except Exception as e:
        logger.error(f"[BACKGROUND TASK] Job {job_id} failed with exception: {e}")
        import traceback
        logger.error(f"[BACKGROUND TASK] Traceback:\n{traceback.format_exc()}")
        job.status = JobStatus.FAILED
        db.commit()
    finally:
        db.close()
        logger.info(f"[BACKGROUND TASK] Database connection closed for job {job_id}")

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
    auth: tuple = Depends(verify_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Start a dynamic multi-agent security scan (supports JWT or API key auth)"""
    from config import get_settings
    settings = get_settings()

    org, user = auth  # Unpack organization and optional user

    logger.info(f"[SCAN START] Target: {scan_data.target}, Org: {org.id}, User: {user.id if user else 'API Key'}")

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

    logger.info(f"[SCAN CREATED] Job ID: {job.id}, Status: {job.status.value}")

    # Start dynamic scan in background
    background_tasks.add_task(
        run_dynamic_scan,
        job.id,
        org.elastic_ip,
        scan_data.target,
        settings.database_url
    )

    logger.info(f"[SCAN QUEUED] Background task started for job {job.id}")

    response = {
        "job_id": job.id,
        "status": job.status.value,
        "message": "Dynamic security assessment started",
        "target": scan_data.target
    }

    logger.info(f"[SCAN RESPONSE] Returning: {response}")
    return response


@app.get("/scan/{job_id}")
async def get_scan_status(
    job_id: str,
    auth: tuple = Depends(verify_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get scan status with findings (supports JWT or API key auth)"""
    org, user = auth

    logger.info(f"[STATUS REQUEST] Job ID: {job_id}, Org: {org.id}")

    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not job:
        logger.warning(f"[STATUS] Job {job_id} not found for org {org.id}")
        raise HTTPException(status_code=404, detail="Scan not found")

    logger.info(f"[STATUS] Job {job_id} found - Status: {job.status.value}, Findings: {job.total_findings or 0}")

    # Get findings
    findings = db.query(Finding).filter(Finding.pentest_job_id == job_id).all()
    logger.info(f"[STATUS] Retrieved {len(findings)} findings from database")

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

    logger.info(f"[STATUS RESPONSE] Job {job_id}: Status={job.status.value}, Findings={len(formatted_findings)}, Response keys={list(response.keys())}")

    return response


@app.get("/scan/{job_id}/agent-graph")
async def get_agent_graph(
    job_id: str,
    auth: tuple = Depends(verify_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get agent hierarchy graph for visualization (supports JWT or API key auth)"""
    org, user = auth

    logger.info(f"[AGENT GRAPH] Request for job {job_id}, org: {org.id}")

    # Verify job exists and belongs to organization
    job = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not job:
        logger.warning(f"[AGENT GRAPH] Job {job_id} not found for org {org.id}")
        raise HTTPException(status_code=404, detail="Scan not found")

    logger.info(f"[AGENT GRAPH] Job {job_id} found, dynamic agents enabled: {USE_DYNAMIC_AGENTS}")

    # Get agent graph from dynamic orchestrator
    if not USE_DYNAMIC_AGENTS:
        logger.info(f"[AGENT GRAPH] Dynamic agents not enabled, returning empty graph")
        return {
            "job_id": job_id,
            "message": "Agent graph only available for dynamic scans",
            "graph": {"nodes": [], "edges": []}
        }

    try:
        logger.info(f"[AGENT GRAPH] Fetching graph from orchestrator for job {job_id}")
        orchestrator = OrchestratorClass(org.elastic_ip)
        graph_data = await orchestrator.get_agent_graph(job_id)
        logger.info(f"[AGENT GRAPH] Successfully retrieved graph with {len(graph_data.get('graph', {}).get('nodes', []))} nodes")
        return graph_data
    except Exception as e:
        logger.error(f"[AGENT GRAPH] Error retrieving graph for job {job_id}: {e}")
        import traceback
        logger.error(f"[AGENT GRAPH] Traceback:\n{traceback.format_exc()}")
        return {
            "job_id": job_id,
            "error": str(e),
            "graph": {"nodes": [], "edges": []}
        }


@app.get("/scans")
async def list_scans(
    auth: tuple = Depends(verify_user_or_api_key),
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List all scans for user's organization (supports JWT or API key auth)"""
    org, user = auth

    logger.info(f"[LIST SCANS] Request for org {org.id}, limit={limit}, offset={offset}")

    # Query scans for this organization
    scans_query = db.query(PentestJob).filter(
        PentestJob.organization_id == org.id
    ).order_by(PentestJob.created_at.desc())

    # Get total count
    total = scans_query.count()
    logger.info(f"[LIST SCANS] Found {total} total scans for org {org.id}")

    # Apply pagination
    scans = scans_query.limit(limit).offset(offset).all()
    logger.info(f"[LIST SCANS] Returning {len(scans)} scans (page offset={offset})")

    # Format response
    scan_list = [
        {
            "job_id": scan.id,
            "target": scan.target,
            "status": scan.status.value,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_findings": scan.total_findings or 0,
            "critical_findings": scan.critical_count or 0,
            "high_findings": scan.high_count or 0
        }
        for scan in scans
    ]

    logger.info(f"[LIST SCANS] Response prepared with {len(scan_list)} scans")

    return {
        "scans": scan_list,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@app.delete("/scan/{job_id}")
async def delete_scan(
    job_id: str,
    auth: tuple = Depends(verify_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Delete a scan (supports JWT or API key auth)"""
    org, user = auth

    logger.info(f"[DELETE SCAN] Request to delete job {job_id} for org {org.id}")

    # Find the scan
    scan = db.query(PentestJob).filter(
        PentestJob.id == job_id,
        PentestJob.organization_id == org.id
    ).first()

    if not scan:
        logger.warning(f"[DELETE SCAN] Job {job_id} not found for org {org.id}")
        raise HTTPException(status_code=404, detail="Scan not found")

    logger.info(f"[DELETE SCAN] Job {job_id} found, target: {scan.target}, status: {scan.status.value}")

    # Delete associated findings first
    findings_deleted = db.query(Finding).filter(Finding.pentest_job_id == job_id).delete()
    logger.info(f"[DELETE SCAN] Deleted {findings_deleted} findings for job {job_id}")

    # Delete the scan
    db.delete(scan)
    db.commit()

    logger.info(f"[DELETE SCAN] Job {job_id} deleted successfully")

    return {"message": "Scan deleted successfully"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "platform": "FetchBot.ai"}
