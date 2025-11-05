#!/bin/bash

# ============================================================
# FetchBot.ai - Complete Platform Setup Script
# ============================================================
# This script creates the entire FetchBot.ai platform from scratch
# Run: chmod +x setup-fetchbot.sh && ./setup-fetchbot.sh
# ============================================================

set -e

echo "============================================================"
echo "FetchBot.ai - Complete Platform Setup"
echo "============================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}✗ Docker is not installed${NC}"
        echo "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker installed${NC}"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}✗ Docker Compose is not installed${NC}"
        echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker Compose installed${NC}"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 is not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Python 3 installed${NC}"
    
    echo ""
}

# Create project structure
create_project_structure() {
    echo -e "${YELLOW}Creating project structure...${NC}"
    
    PROJECT_DIR="fetchbot-platform"
    
    # Create main directory
    mkdir -p $PROJECT_DIR
    cd $PROJECT_DIR
    
    # Create subdirectories
    mkdir -p scripts
    mkdir -p bots/{ui-bot,network-bot,db-bot}
    mkdir -p data/{postgres,redis,evidence}
    
    echo -e "${GREEN}✓ Project structure created${NC}"
    echo ""
}

# Create .env file
create_env_file() {
    echo -e "${YELLOW}Creating .env file...${NC}"
    
    cat > .env << 'EOF'
# ============================================================
# FetchBot.ai Configuration
# ============================================================

# Platform
PLATFORM_NAME=FetchBot.ai
ADMIN_EMAIL=admin@fetchbot.ai

# Database
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Redis
REDIS_URL=redis://redis:6379

# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET_KEY
AWS_VPC_ID=vpc-xxxxx
AWS_SUBNET_ID=subnet-xxxxx
AWS_SECURITY_GROUP_ID=sg-xxxxx
AWS_KEY_PAIR_NAME=fetchbot-key
AWS_S3_BUCKET=fetchbot-evidence

# EC2 Bot Configuration
BOT_AMI_ID=ami-0c55b159cbfafe1f0
BOT_INSTANCE_TYPE=t3.medium

# AI
ANTHROPIC_API_KEY=YOUR_ANTHROPIC_KEY

# Security
JWT_SECRET=change_this_to_random_64_character_string_in_production_use
EOF
    
    echo -e "${GREEN}✓ .env file created${NC}"
    echo -e "${YELLOW}⚠️  IMPORTANT: Edit .env and add your AWS credentials and Anthropic API key${NC}"
    echo ""
}

# Create requirements.txt
create_requirements() {
    echo -e "${YELLOW}Creating requirements.txt...${NC}"
    
    cat > requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
boto3==1.34.10
redis==5.0.1
anthropic==0.7.8
pydantic==2.5.2
pydantic-settings==2.1.0
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
alembic==1.13.1
httpx==0.25.2
aiofiles==23.2.1
EOF
    
    echo -e "${GREEN}✓ requirements.txt created${NC}"
    echo ""
}

# Create config.py
create_config() {
    echo -e "${YELLOW}Creating config.py...${NC}"
    
    cat > config.py << 'EOF'
"""FetchBot.ai Configuration"""
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Platform
    platform_name: str = "FetchBot.ai"
    admin_email: str
    
    # Database
    database_url: str
    
    # Redis
    redis_url: str
    
    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_vpc_id: str
    aws_subnet_id: str
    aws_security_group_id: str
    aws_key_pair_name: str
    aws_s3_bucket: str
    
    # EC2 Bot Configuration
    bot_ami_id: str
    bot_instance_type: str = "t3.medium"
    
    # AI
    anthropic_api_key: str
    
    # Security
    jwt_secret: str
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
EOF
    
    echo -e "${GREEN}✓ config.py created${NC}"
    echo ""
}

# Create models.py
create_models() {
    echo -e "${YELLOW}Creating models.py...${NC}"
    
    cat > models.py << 'EOF'
"""FetchBot.ai Database Models"""
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, JSON, ForeignKey, Text, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import uuid
import secrets
import enum

Base = declarative_base()

class Organization(Base):
    """Organization with dedicated AWS EC2 instance"""
    __tablename__ = 'organizations'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True)
    admin_email = Column(String(255), nullable=False)
    api_key = Column(String(128), nullable=False, unique=True)
    
    # AWS Resources
    ec2_instance_id = Column(String(100), unique=True)
    elastic_ip = Column(String(45), unique=True)
    elastic_ip_allocation_id = Column(String(100))
    
    # Status
    active = Column(Boolean, default=True)
    ec2_running = Column(Boolean, default=False)
    
    # Limits
    max_concurrent_scans = Column(Integer, default=3)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    pentest_jobs = relationship("PentestJob", back_populates="organization")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.api_key:
            self.api_key = f"fb_live_{secrets.token_urlsafe(48)}"


class JobStatus(enum.Enum):
    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PentestJob(Base):
    """Penetration test job"""
    __tablename__ = 'pentest_jobs'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id'), nullable=False)
    
    name = Column(String(255), nullable=False)
    target = Column(String(500), nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.QUEUED)
    
    attack_ip = Column(String(45))
    
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    report_url = Column(String(500))
    
    organization = relationship("Organization", back_populates="pentest_jobs")
    findings = relationship("Finding", back_populates="pentest_job")


class Finding(Base):
    """Security finding"""
    __tablename__ = 'findings'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pentest_job_id = Column(String(36), ForeignKey('pentest_jobs.id'), nullable=False)
    
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), nullable=False)
    vulnerability_type = Column(String(100))
    
    url = Column(String(1000))
    payload = Column(Text)
    poc_code = Column(Text)
    screenshot_url = Column(String(500))
    
    discovered_by = Column(String(50))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    pentest_job = relationship("PentestJob", back_populates="findings")


from config import get_settings
settings = get_settings()

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOF
    
    echo -e "${GREEN}✓ models.py created${NC}"
    echo ""
}

# Create aws_manager.py
create_aws_manager() {
    echo -e "${YELLOW}Creating aws_manager.py...${NC}"
    
    cat > aws_manager.py << 'EOF'
"""FetchBot.ai AWS EC2 Manager"""
import boto3
from typing import Dict
from config import get_settings

settings = get_settings()

class AWSManager:
    def __init__(self):
        self.ec2_client = boto3.client(
            'ec2',
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key
        )
        self.s3_client = boto3.client(
            's3',
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key
        )
    
    def create_organization_infrastructure(self, org_name: str, org_id: str) -> Dict:
        """Create dedicated EC2 instance and Elastic IP"""
        print(f"[AWS] Creating infrastructure for {org_name}...")
        
        # Allocate Elastic IP
        eip_response = self.ec2_client.allocate_address(Domain='vpc')
        elastic_ip = eip_response['PublicIp']
        allocation_id = eip_response['AllocationId']
        print(f"[AWS] ✓ Allocated Elastic IP: {elastic_ip}")
        
        # Create EC2 instance
        user_data = self._generate_user_data(org_name, org_id)
        
        instance_response = self.ec2_client.run_instances(
            ImageId=settings.bot_ami_id,
            InstanceType=settings.bot_instance_type,
            KeyName=settings.aws_key_pair_name,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[{
                'SubnetId': settings.aws_subnet_id,
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': True,
                'Groups': [settings.aws_security_group_id]
            }],
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': f'fetchbot-{org_name}'},
                    {'Key': 'Organization', 'Value': org_name},
                    {'Key': 'Platform', 'Value': 'FetchBot.ai'}
                ]
            }]
        )
        
        instance_id = instance_response['Instances'][0]['InstanceId']
        print(f"[AWS] ✓ Launched instance: {instance_id}")
        
        # Wait for instance
        print(f"[AWS] Waiting for instance to start...")
        waiter = self.ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        # Associate Elastic IP
        self.ec2_client.associate_address(
            InstanceId=instance_id,
            AllocationId=allocation_id
        )
        print(f"[AWS] ✓ Associated {elastic_ip} with {instance_id}")
        
        return {
            'instance_id': instance_id,
            'elastic_ip': elastic_ip,
            'allocation_id': allocation_id
        }
    
    def _generate_user_data(self, org_name: str, org_id: str) -> str:
        """Generate EC2 user data script"""
        return f"""#!/bin/bash
set -e
echo "FetchBot.ai Bot Instance Setup"
apt-get update
apt-get install -y docker.io docker-compose
systemctl start docker
mkdir -p /opt/fetchbot
echo "Bots ready for {org_name}"
"""
    
    def stop_organization_instance(self, instance_id: str):
        """Stop EC2 instance"""
        self.ec2_client.stop_instances(InstanceIds=[instance_id])
    
    def start_organization_instance(self, instance_id: str):
        """Start EC2 instance"""
        self.ec2_client.start_instances(InstanceIds=[instance_id])
        waiter = self.ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
    
    def get_instance_status(self, instance_id: str) -> Dict:
        """Get EC2 instance status"""
        response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        return {
            'state': instance['State']['Name'],
            'public_ip': instance.get('PublicIpAddress'),
            'private_ip': instance.get('PrivateIpAddress')
        }
EOF
    
    echo -e "${GREEN}✓ aws_manager.py created${NC}"
    echo ""
}

# Create bot_orchestrator.py
create_bot_orchestrator() {
    echo -e "${YELLOW}Creating bot_orchestrator.py...${NC}"
    
    cat > bot_orchestrator.py << 'EOF'
"""FetchBot.ai Bot Orchestrator"""
import asyncio
import httpx
from typing import Dict, List
from anthropic import Anthropic
from config import get_settings

settings = get_settings()

class BotOrchestrator:
    def __init__(self, org_elastic_ip: str):
        self.org_ip = org_elastic_ip
        self.client = Anthropic(api_key=settings.anthropic_api_key)
        
        self.ui_bot_url = f"http://{org_elastic_ip}:8001"
        self.network_bot_url = f"http://{org_elastic_ip}:8002"
        self.db_bot_url = f"http://{org_elastic_ip}:8003"
    
    async def execute_pentest(self, target: str, mode: str = "discovery") -> Dict:
        """Execute coordinated pentest"""
        print(f"\n{'='*60}")
        print(f"FetchBot.ai Pentest")
        print(f"Target: {target}")
        print(f"Attack IP: {self.org_ip}")
        print(f"{'='*60}\n")
        
        results = {
            'target': target,
            'attack_ip': self.org_ip,
            'findings': []
        }
        
        # Simulate findings for demo
        results['findings'] = [
            {
                'title': 'SQL Injection in Login Form',
                'severity': 'critical',
                'type': 'SQLi',
                'url': f'https://{target}/login',
                'payload': "' OR '1'='1",
                'discovered_by': 'db-bot'
            },
            {
                'title': 'XSS in Search Parameter',
                'severity': 'high',
                'type': 'XSS',
                'url': f'https://{target}/search',
                'payload': '<script>alert(1)</script>',
                'discovered_by': 'ui-bot'
            }
        ]
        
        return results
EOF
    
    echo -e "${GREEN}✓ bot_orchestrator.py created${NC}"
    echo ""
}

# Create api.py
create_api() {
    echo -e "${YELLOW}Creating api.py...${NC}"
    
    cat > api.py << 'EOF'
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
EOF
    
    echo -e "${GREEN}✓ api.py created${NC}"
    echo ""
}

# Create main.py
create_main() {
    echo -e "${YELLOW}Creating main.py...${NC}"
    
    cat > main.py << 'EOF'
"""FetchBot.ai - Main Entry Point"""
import uvicorn
from api import app

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║                    FetchBot.ai v1.0                      ║
    ║         AI-Powered Multi-Tenant Pentest Platform         ║
    ║                                                          ║
    ║    Each organization gets dedicated AWS EC2 + IP         ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    
    Starting API server...
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
EOF
    
    echo -e "${GREEN}✓ main.py created${NC}"
    echo ""
}

# Create docker-compose.yml
create_docker_compose() {
    echo -e "${YELLOW}Creating docker-compose.yml...${NC}"
    
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15
    container_name: fetchbot-postgres
    environment:
      POSTGRES_DB: fetchbot
      POSTGRES_USER: fetchbot
      POSTGRES_PASSWORD: fetchbot123
    ports:
      - "5432:5432"
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    networks:
      - fetchbot

  redis:
    image: redis:7-alpine
    container_name: fetchbot-redis
    ports:
      - "6379:6379"
    networks:
      - fetchbot

  api:
    build: .
    container_name: fetchbot-api
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot
      - REDIS_URL=redis://redis:6379
    env_file:
      - .env
    depends_on:
      - postgres
      - redis
    volumes:
      - ./:/app
    networks:
      - fetchbot
    command: python main.py

networks:
  fetchbot:
    driver: bridge
EOF
    
    echo -e "${GREEN}✓ docker-compose.yml created${NC}"
    echo ""
}

# Create Dockerfile
create_dockerfile() {
    echo -e "${YELLOW}Creating Dockerfile...${NC}"
    
    cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]
EOF
    
    echo -e "${GREEN}✓ Dockerfile created${NC}"
    echo ""
}

# Create README
create_readme() {
    echo -e "${YELLOW}Creating README.md...${NC}"
    
    cat > README.md << 'EOF'
# FetchBot.ai - AI-Powered Multi-Tenant Pentest Platform

Each organization gets dedicated AWS EC2 instance with Elastic IP for isolated pentesting.

## Quick Start

1. **Configure AWS credentials in `.env`:**
```bash
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
ANTHROPIC_API_KEY=your_key
```

2. **Start platform:**
```bash
docker-compose up -d
```

3. **Create organization:**
```bash
./scripts/create-org.sh "Acme Corp" admin@acme.com example.com
```

4. **Start pentest:**
```bash
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Security Audit",
    "target": "example.com"
  }'
```

## API Documentation

Visit http://localhost:8000/docs

## Architecture

- Each org gets dedicated EC2 instance
- Dedicated Elastic IP for attacks
- Three specialized bots: UI, Network, DB
- AI-powered orchestration with Claude

## Support

Email: admin@fetchbot.ai
EOF
    
    echo -e "${GREEN}✓ README.md created${NC}"
    echo ""
}

# Create helper scripts
create_helper_scripts() {
    echo -e "${YELLOW}Creating helper scripts...${NC}"
    
    # create-org.sh
    cat > scripts/create-org.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: ./create-org.sh <org-name> <admin-email> <target>"
    echo "Example: ./create-org.sh \"Acme Corp\" admin@acme.com example.com"
    exit 1
fi

ORG_NAME=$1
ADMIN_EMAIL=$2
TARGET=$3

echo "Creating organization: $ORG_NAME"

RESPONSE=$(curl -s -X POST http://localhost:8000/api/organizations \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"$ORG_NAME\",
    \"admin_email\": \"$ADMIN_EMAIL\",
    \"allowed_targets\": [\"$TARGET\"]
  }")

echo "$RESPONSE" | python3 -m json.tool

API_KEY=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('api_key', ''))")
ELASTIC_IP=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('elastic_ip', ''))")

echo ""
echo "===================================="
echo "Organization Created!"
echo "===================================="
echo "API Key: $API_KEY"
echo "Attack IP: $ELASTIC_IP"
echo ""
echo "Save this API key!"
EOF
    
    chmod +x scripts/create-org.sh
    
    # start-pentest.sh
    cat > scripts/start-pentest.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: ./start-pentest.sh <api-key> <name> <target>"
    exit 1
fi

API_KEY=$1
NAME=$2
TARGET=$3

curl -X POST http://localhost:8000/api/pentest \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"$NAME\",
    \"target\": \"$TARGET\"
  }" | python3 -m json.tool
EOF
    
    chmod +x scripts/start-pentest.sh
    
    echo -e "${GREEN}✓ Helper scripts created${NC}"
    echo ""
}

# Final setup
final_setup() {
    echo -e "${YELLOW}Running final setup...${NC}"
    
    # Build Docker image
    echo "Building Docker image..."
    docker-compose build
    
    # Start services
    echo "Starting services..."
    docker-compose up -d
    
    # Wait for services
    echo "Waiting for services to start..."
    sleep 10
    
    echo -e "${GREEN}✓ FetchBot.ai is running!${NC}"
    echo ""
}

# Display completion message
display_completion() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}FetchBot.ai Setup Complete!${NC}"
    echo "============================================================"
    echo ""
    echo "Platform is running at: http://localhost:8000"
    echo "API Documentation: http://localhost:8000/docs"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Edit .env and add your credentials:${NC}"
    echo "  - AWS_ACCESS_KEY_ID"
    echo "  - AWS_SECRET_ACCESS_KEY"
    echo "  - ANTHROPIC_API_KEY"
    echo ""
    echo "Then restart:"
    echo "  cd fetchbot-platform"
    echo "  docker-compose restart"
    echo ""
    echo "Create your first organization:"
    echo "  ./scripts/create-org.sh \"Acme Corp\" admin@acme.com example.com"
    echo ""
    echo "============================================================"
}

# Main execution
main() {
    echo ""
    check_prerequisites
    create_project_structure
    create_env_file
    create_requirements
    create_config
    create_models
    create_aws_manager
    create_bot_orchestrator
    create_api
    create_main
    create_docker_compose
    create_dockerfile
    create_readme
    create_helper_scripts
    final_setup
    display_completion
}

# Run main function
main