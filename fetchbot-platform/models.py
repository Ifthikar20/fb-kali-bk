"""FetchBot.ai Database Models"""
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, JSON, ForeignKey, Text, Enum, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import uuid
import secrets
import enum
import hashlib

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
    rag_tool_executions = relationship("RAGToolExecution", back_populates="organization")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.api_key:
            self.api_key = f"fb_live_{secrets.token_urlsafe(48)}"


class User(Base):
    """User account for login"""
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id'), nullable=False)

    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(128), nullable=False)

    # User info
    full_name = Column(String(255))
    is_admin = Column(Boolean, default=False)
    active = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

    # Relationship
    organization = relationship("Organization")

    def set_password(self, password: str):
        """Hash and set password"""
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        """Verify password"""
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


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

    # Execution logs - stores step-by-step scan progress
    execution_logs = Column(JSON, default=list)

    organization = relationship("Organization", back_populates="pentest_jobs")
    findings = relationship("Finding", back_populates="pentest_job")
    rag_executions = relationship("RAGToolExecution", back_populates="scan")
    rag_feedback = relationship("RAGFeedback", back_populates="scan")


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

    # Detailed evidence and remediation (JSON)
    evidence = Column(JSON, default=dict)  # Technical evidence: headers, payloads, detection method
    remediation = Column(JSON, default=dict)  # Fix instructions, code examples, references

    # Risk classification
    cvss_score = Column(Integer)  # CVSS score (0-10)
    cwe = Column(String(200))  # CWE identifier
    owasp_category = Column(String(200))  # OWASP Top 10 category

    created_at = Column(DateTime, default=datetime.utcnow)

    pentest_job = relationship("PentestJob", back_populates="findings")


class RAGToolExecution(Base):
    """Store tool execution metadata for RAG learning"""
    __tablename__ = "rag_tool_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("pentest_jobs.id"))
    organization_id = Column(String(36), ForeignKey("organizations.id"))
    tool_name = Column(String(100), nullable=False)
    agent_name = Column(String(255))
    target_url = Column(String(500))
    tech_stack_detected = Column(JSON, default=list)  # Array of detected technologies
    parameters = Column(JSON, default=dict)
    result_summary = Column(Text)
    success = Column(Boolean, default=False)
    findings_count = Column(Integer, default=0)
    severity_distribution = Column(JSON, default=dict)
    execution_time_seconds = Column(Float)
    error_message = Column(Text)

    # For RAG retrieval - reference to vector DB
    embedding_id = Column(String(100))  # Reference to vector DB document ID

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("PentestJob", back_populates="rag_executions")
    organization = relationship("Organization", back_populates="rag_tool_executions")


class RAGFeedback(Base):
    """Track feedback on RAG suggestions for continuous improvement"""
    __tablename__ = "rag_feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    suggestion_id = Column(String(100))  # RAG retrieval result ID
    tool_suggested = Column(String(100))
    tool_actually_used = Column(String(100))
    was_helpful = Column(Boolean)
    confidence_score = Column(Float)  # Original RAG confidence
    actual_relevance_score = Column(Float)  # User/agent feedback

    scan_id = Column(String(36), ForeignKey("pentest_jobs.id"))
    agent_name = Column(String(255))

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("PentestJob", back_populates="rag_feedback")


class RAGEmbeddingsMeta(Base):
    """Track embedding model versions and metadata"""
    __tablename__ = "rag_embeddings_meta"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_name = Column(String(255))  # e.g., "all-MiniLM-L6-v2"
    model_version = Column(String(100))
    embedding_dimensions = Column(Integer)
    total_documents_indexed = Column(Integer, default=0)
    last_reindex_at = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
