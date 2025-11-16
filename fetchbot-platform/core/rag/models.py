"""
Data models for RAG system
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class CollectionType(str, Enum):
    """Vector database collection types"""
    TOOL_KNOWLEDGE = "tool_knowledge"
    EXECUTION_HISTORY = "execution_history"
    VULNERABILITY_PATTERNS = "vulnerability_patterns"
    REMEDIATION_STRATEGIES = "remediation_strategies"
    PAYLOAD_LIBRARY = "payload_library"


@dataclass
class RetrievalResult:
    """Result from RAG similarity search"""
    id: str
    document: str
    metadata: Dict[str, Any]
    similarity_score: float
    collection: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "document": self.document,
            "metadata": self.metadata,
            "similarity_score": self.similarity_score,
            "collection": self.collection
        }


@dataclass
class ToolSuggestion:
    """Suggested tool with confidence and reasoning"""
    tool_name: str
    confidence: float
    reasoning: str
    similar_executions_count: int
    expected_success_rate: float
    estimated_execution_time: float
    parameters_suggestion: Optional[Dict[str, Any]] = None
    prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "similar_executions_count": self.similar_executions_count,
            "expected_success_rate": self.expected_success_rate,
            "estimated_execution_time": self.estimated_execution_time,
            "parameters_suggestion": self.parameters_suggestion,
            "prerequisites": self.prerequisites
        }


@dataclass
class ScanContext:
    """Context about current scan for RAG queries"""
    target_url: str
    current_findings: List[Dict[str, Any]] = field(default_factory=list)
    tech_stack_detected: List[str] = field(default_factory=list)
    previous_tools_used: List[str] = field(default_factory=list)
    agent_specialization: List[str] = field(default_factory=list)
    scan_id: Optional[str] = None
    organization_id: Optional[str] = None

    def to_query_text(self) -> str:
        """Convert context to natural language query"""
        parts = [f"Target: {self.target_url}"]

        if self.tech_stack_detected:
            parts.append(f"Technologies: {', '.join(self.tech_stack_detected)}")

        if self.current_findings:
            severities = [f["severity"] for f in self.current_findings]
            parts.append(f"Findings so far: {len(self.current_findings)} ({', '.join(set(severities))})")

        if self.previous_tools_used:
            parts.append(f"Tools used: {', '.join(self.previous_tools_used[-5:])}")

        if self.agent_specialization:
            parts.append(f"Agent focus: {', '.join(self.agent_specialization)}")

        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "current_findings": self.current_findings,
            "tech_stack_detected": self.tech_stack_detected,
            "previous_tools_used": self.previous_tools_used,
            "agent_specialization": self.agent_specialization,
            "scan_id": self.scan_id,
            "organization_id": self.organization_id
        }


@dataclass
class HistoricalExecution:
    """Historical tool execution record"""
    id: str
    tool_name: str
    target_url: str
    target_characteristics: Dict[str, Any]
    success: bool
    findings_count: int
    severity_distribution: Dict[str, int]
    execution_time_seconds: float
    timestamp: datetime
    agent_name: str
    scan_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "target_url": self.target_url,
            "target_characteristics": self.target_characteristics,
            "success": self.success,
            "findings_count": self.findings_count,
            "severity_distribution": self.severity_distribution,
            "execution_time_seconds": self.execution_time_seconds,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "agent_name": self.agent_name,
            "scan_id": self.scan_id
        }


@dataclass
class VulnerabilityPattern:
    """Known vulnerability pattern"""
    id: str
    name: str
    vulnerability_type: str
    description: str
    detection_methods: List[str]
    recommended_tools: List[str]
    severity: str
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    affected_frameworks: List[str] = field(default_factory=list)
    payload_examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "detection_methods": self.detection_methods,
            "recommended_tools": self.recommended_tools,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "affected_frameworks": self.affected_frameworks,
            "payload_examples": self.payload_examples
        }


@dataclass
class RAGQueryRequest:
    """Request for RAG query"""
    query: str
    collection: Optional[CollectionType] = None
    filters: Optional[Dict[str, Any]] = None
    top_k: int = 5
    min_similarity: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "collection": self.collection.value if self.collection else None,
            "filters": self.filters,
            "top_k": self.top_k,
            "min_similarity": self.min_similarity
        }


@dataclass
class EmbeddingDocument:
    """Document to be embedded and stored"""
    id: str
    document: str
    metadata: Dict[str, Any]
    collection: CollectionType

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "document": self.document,
            "metadata": self.metadata,
            "collection": self.collection.value
        }
