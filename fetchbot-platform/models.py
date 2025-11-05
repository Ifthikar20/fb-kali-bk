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
