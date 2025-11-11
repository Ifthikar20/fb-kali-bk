"""
Knowledge Base Seeder for RAG System

Populates the vector database with:
- Tool knowledge from registry
- Vulnerability patterns
- Historical execution data
- Remediation strategies
- Payload libraries
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime

from .models import (
    CollectionType,
    EmbeddingDocument,
    VulnerabilityPattern
)
from .embeddings_service import EmbeddingsService
from .vector_store import VectorStore

logger = logging.getLogger(__name__)


class KnowledgeBaseSeeder:
    """
    Seeds the vector database with initial knowledge.
    """

    def __init__(
        self,
        embeddings_service: EmbeddingsService,
        vector_store: VectorStore
    ):
        """
        Initialize seeder.

        Args:
            embeddings_service: Service for generating embeddings
            vector_store: Vector database to seed
        """
        self.embeddings_service = embeddings_service
        self.vector_store = vector_store

        logger.info("Initialized KnowledgeBaseSeeder")

    async def seed_all(self):
        """Seed all knowledge collections"""
        logger.info("Starting full knowledge base seeding...")

        try:
            await self.seed_tool_knowledge()
            await self.seed_vulnerability_patterns()
            await self.seed_remediation_strategies()
            await self.seed_payload_library()

            logger.info("Knowledge base seeding completed successfully")

        except Exception as e:
            logger.error(f"Failed to seed knowledge base: {e}")
            raise

    async def seed_tool_knowledge(self):
        """
        Seed tool knowledge collection from tool registry.
        """
        logger.info("Seeding tool knowledge...")

        try:
            # Import tool registry
            from core.tools.registry import get_all_tools

            tools = get_all_tools()
            logger.info(f"Found {len(tools)} tools in registry")

            documents = []
            texts_to_embed = []

            for tool in tools:
                # Create comprehensive document text
                doc_text = self._create_tool_document(tool)
                texts_to_embed.append(doc_text)

                # Create metadata
                metadata = {
                    "tool_name": tool['name'],
                    "category": self._categorize_tool(tool['name']),
                    "sandbox_execution": tool.get('sandbox_execution', False),
                    "parameters": tool.get('parameters', {}),
                    "description": tool.get('description', ''),
                    "use_cases": self._extract_use_cases(tool),
                    "prerequisites": self._extract_prerequisites(tool),
                    "mcp_tool": self._is_mcp_tool(tool['name'])
                }

                # Create document
                doc = EmbeddingDocument(
                    id=f"tool_{tool['name']}",
                    document=doc_text,
                    metadata=metadata,
                    collection=CollectionType.TOOL_KNOWLEDGE
                )
                documents.append(doc)

            # Generate embeddings in batch
            embeddings = await self.embeddings_service.embed_batch_async(texts_to_embed)

            # Store in vector database
            await self.vector_store.add_documents(documents, embeddings=embeddings)

            logger.info(f"Seeded {len(documents)} tool knowledge documents")

        except Exception as e:
            logger.error(f"Failed to seed tool knowledge: {e}")
            raise

    async def seed_vulnerability_patterns(self):
        """
        Seed vulnerability patterns collection.
        """
        logger.info("Seeding vulnerability patterns...")

        # Define common vulnerability patterns
        patterns = [
            {
                "name": "SQL Injection - MySQL Error-Based",
                "vulnerability_type": "sql_injection",
                "description": "SQL injection vulnerability in MySQL databases detectable through error messages",
                "detection_methods": ["error_based", "syntax_error_triggers"],
                "recommended_tools": ["sql_injection_test"],
                "severity": "critical",
                "cvss_score": 9.8,
                "cwe": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "affected_frameworks": ["wordpress", "drupal", "joomla", "custom_php"],
                "payload_examples": ["' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--"]
            },
            {
                "name": "Cross-Site Scripting (XSS) - Reflected",
                "vulnerability_type": "xss",
                "description": "Reflected XSS vulnerability where user input is immediately reflected in the response",
                "detection_methods": ["payload_reflection", "javascript_execution"],
                "recommended_tools": ["xss_test"],
                "severity": "high",
                "cvss_score": 7.1,
                "cwe": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "affected_frameworks": ["react", "angular", "vue", "wordpress", "custom"],
                "payload_examples": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
            },
            {
                "name": "Directory Traversal / Path Traversal",
                "vulnerability_type": "directory_traversal",
                "description": "Ability to access files outside the web root through path manipulation",
                "detection_methods": ["path_manipulation", "file_access"],
                "recommended_tools": ["directory_fuzzing", "http_scan"],
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "affected_frameworks": ["custom", "wordpress", "nodejs"],
                "payload_examples": ["../../../etc/passwd", "....//....//etc/passwd", "..%252f..%252fetc/passwd"]
            },
            {
                "name": "Authentication Bypass",
                "vulnerability_type": "authentication",
                "description": "Ability to bypass authentication mechanisms",
                "detection_methods": ["credential_stuffing", "logic_bypass", "session_hijacking"],
                "recommended_tools": ["http_scan", "api_scan"],
                "severity": "critical",
                "cvss_score": 9.1,
                "cwe": "CWE-287",
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "affected_frameworks": ["custom", "wordpress", "django", "spring"],
                "payload_examples": []
            },
            {
                "name": "Server-Side Request Forgery (SSRF)",
                "vulnerability_type": "ssrf",
                "description": "Ability to make the server perform requests to arbitrary URLs",
                "detection_methods": ["url_callback", "internal_service_access"],
                "recommended_tools": ["http_scan"],
                "severity": "high",
                "cvss_score": 8.6,
                "cwe": "CWE-918",
                "owasp_category": "A10:2021-Server-Side Request Forgery",
                "affected_frameworks": ["custom", "nodejs", "python", "java"],
                "payload_examples": ["http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]
            },
            {
                "name": "Open Ports and Services",
                "vulnerability_type": "network_exposure",
                "description": "Exposed network services that may be vulnerable",
                "detection_methods": ["port_scanning", "service_detection"],
                "recommended_tools": ["nmap_scan"],
                "severity": "medium",
                "cvss_score": 5.3,
                "cwe": "CWE-16",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "affected_frameworks": ["all"],
                "payload_examples": []
            },
            {
                "name": "Sensitive File Exposure",
                "vulnerability_type": "information_disclosure",
                "description": "Exposure of sensitive files like .env, config files, backups",
                "detection_methods": ["directory_fuzzing", "known_path_scanning"],
                "recommended_tools": ["directory_fuzzing", "http_scan"],
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-200",
                "owasp_category": "A01:2021-Broken Access Control",
                "affected_frameworks": ["all"],
                "payload_examples": []
            }
        ]

        documents = []
        texts_to_embed = []

        for pattern_data in patterns:
            # Create document text
            doc_text = self._create_vulnerability_pattern_document(pattern_data)
            texts_to_embed.append(doc_text)

            # Create document
            doc = EmbeddingDocument(
                id=f"vuln_pattern_{uuid.uuid4().hex[:8]}",
                document=doc_text,
                metadata=pattern_data,
                collection=CollectionType.VULNERABILITY_PATTERNS
            )
            documents.append(doc)

        # Generate embeddings
        embeddings = await self.embeddings_service.embed_batch_async(texts_to_embed)

        # Store in vector database
        await self.vector_store.add_documents(documents, embeddings=embeddings)

        logger.info(f"Seeded {len(documents)} vulnerability patterns")

    async def seed_remediation_strategies(self):
        """
        Seed remediation strategies collection.
        """
        logger.info("Seeding remediation strategies...")

        strategies = [
            {
                "vulnerability_type": "sql_injection",
                "title": "SQL Injection Remediation",
                "description": "Use parameterized queries (prepared statements) instead of string concatenation. Validate and sanitize all user inputs. Use ORM frameworks that handle escaping automatically.",
                "applicable_languages": ["php", "python", "java", "javascript", "ruby"],
                "applicable_frameworks": ["wordpress", "django", "spring", "express"],
                "code_example": "# Python\nquery = 'SELECT * FROM users WHERE id = ?'\ncursor.execute(query, (user_id,))",
                "difficulty": "medium",
                "implementation_time_hours": 4
            },
            {
                "vulnerability_type": "xss",
                "title": "XSS Remediation",
                "description": "Encode all user-controlled data before rendering. Use Content Security Policy (CSP). Implement input validation. Use frameworks with automatic escaping.",
                "applicable_languages": ["javascript", "php", "python", "java"],
                "applicable_frameworks": ["react", "angular", "vue", "django", "spring"],
                "code_example": "// React\nconst UserInput = ({ data }) => <div>{data}</div>; // Automatic escaping",
                "difficulty": "easy",
                "implementation_time_hours": 2
            },
            {
                "vulnerability_type": "directory_traversal",
                "title": "Path Traversal Remediation",
                "description": "Validate file paths against a whitelist. Use absolute paths. Never construct file paths from user input directly. Implement proper access controls.",
                "applicable_languages": ["php", "python", "java", "nodejs"],
                "applicable_frameworks": ["all"],
                "code_example": "import os\nbase_dir = '/var/www/uploads'\nfilename = os.path.basename(user_input)\npath = os.path.join(base_dir, filename)",
                "difficulty": "easy",
                "implementation_time_hours": 2
            }
        ]

        documents = []
        texts_to_embed = []

        for strategy in strategies:
            doc_text = f"{strategy['title']}: {strategy['description']}"
            texts_to_embed.append(doc_text)

            doc = EmbeddingDocument(
                id=f"remediation_{uuid.uuid4().hex[:8]}",
                document=doc_text,
                metadata=strategy,
                collection=CollectionType.REMEDIATION_STRATEGIES
            )
            documents.append(doc)

        embeddings = await self.embeddings_service.embed_batch_async(texts_to_embed)
        await self.vector_store.add_documents(documents, embeddings=embeddings)

        logger.info(f"Seeded {len(documents)} remediation strategies")

    async def seed_payload_library(self):
        """
        Seed payload library collection.
        """
        logger.info("Seeding payload library...")

        payloads = [
            {
                "vulnerability_type": "xss",
                "xss_type": "reflected",
                "payload": "<script>alert(1)</script>",
                "description": "Basic reflected XSS payload",
                "browser_compatibility": ["chrome", "firefox", "safari", "edge"],
                "waf_evasion_level": "low"
            },
            {
                "vulnerability_type": "xss",
                "xss_type": "dom_based",
                "payload": "<img src=x onerror=alert(1)>",
                "description": "DOM-based XSS using image error handler",
                "browser_compatibility": ["chrome", "firefox", "safari", "edge"],
                "waf_evasion_level": "medium"
            },
            {
                "vulnerability_type": "sql_injection",
                "database_type": "mysql",
                "payload": "' OR '1'='1",
                "description": "Basic MySQL boolean-based blind SQL injection",
                "waf_evasion_level": "low"
            },
            {
                "vulnerability_type": "sql_injection",
                "database_type": "mysql",
                "payload": "' UNION SELECT NULL, NULL, NULL--",
                "description": "MySQL UNION-based SQL injection with 3 columns",
                "waf_evasion_level": "medium"
            }
        ]

        documents = []
        texts_to_embed = []

        for payload_data in payloads:
            doc_text = f"{payload_data['vulnerability_type']} payload: {payload_data['payload']} - {payload_data['description']}"
            texts_to_embed.append(doc_text)

            doc = EmbeddingDocument(
                id=f"payload_{uuid.uuid4().hex[:8]}",
                document=doc_text,
                metadata=payload_data,
                collection=CollectionType.PAYLOAD_LIBRARY
            )
            documents.append(doc)

        embeddings = await self.embeddings_service.embed_batch_async(texts_to_embed)
        await self.vector_store.add_documents(documents, embeddings=embeddings)

        logger.info(f"Seeded {len(documents)} payloads")

    async def seed_from_historical_data(self, db_connection):
        """
        Seed execution history from existing database records.

        Args:
            db_connection: Database connection/session
        """
        logger.info("Seeding from historical scan data...")

        try:
            # Query existing pentest jobs and findings
            # This would query the PentestJob and Finding tables
            # For now, this is a placeholder for future implementation

            logger.info("Historical data seeding completed")

        except Exception as e:
            logger.error(f"Failed to seed historical data: {e}")
            raise

    def _create_tool_document(self, tool: Dict[str, Any]) -> str:
        """Create comprehensive document text for a tool"""
        parts = []

        # Tool name and description
        parts.append(f"Tool: {tool['name']}")
        parts.append(f"Description: {tool.get('description', '')}")

        # Category
        category = self._categorize_tool(tool['name'])
        parts.append(f"Category: {category}")

        # Parameters
        if tool.get('parameters'):
            param_names = list(tool['parameters'].keys())
            parts.append(f"Parameters: {', '.join(param_names)}")

        # Execution environment
        if tool.get('sandbox_execution'):
            parts.append("Execution: Runs in isolated Kali container")
        else:
            parts.append("Execution: Runs locally (coordination)")

        # Use cases
        use_cases = self._extract_use_cases(tool)
        if use_cases:
            parts.append(f"Use cases: {', '.join(use_cases)}")

        return " | ".join(parts)

    def _create_vulnerability_pattern_document(self, pattern: Dict[str, Any]) -> str:
        """Create document text for vulnerability pattern"""
        parts = []

        parts.append(f"Vulnerability: {pattern['name']}")
        parts.append(f"Type: {pattern['vulnerability_type']}")
        parts.append(f"Description: {pattern['description']}")
        parts.append(f"Severity: {pattern['severity']}")
        parts.append(f"OWASP: {pattern['owasp_category']}")

        if pattern.get('affected_frameworks'):
            parts.append(f"Affects: {', '.join(pattern['affected_frameworks'])}")

        if pattern.get('recommended_tools'):
            parts.append(f"Detection tools: {', '.join(pattern['recommended_tools'])}")

        if pattern.get('detection_methods'):
            parts.append(f"Detection methods: {', '.join(pattern['detection_methods'])}")

        return " | ".join(parts)

    def _categorize_tool(self, tool_name: str) -> str:
        """Categorize tool based on name"""
        if 'nmap' in tool_name or 'network' in tool_name or 'port' in tool_name:
            return "network_reconnaissance"
        elif 'sql' in tool_name:
            return "database_testing"
        elif 'xss' in tool_name:
            return "web_application_testing"
        elif 'directory' in tool_name or 'fuzz' in tool_name:
            return "web_fuzzing"
        elif 'http' in tool_name or 'api' in tool_name:
            return "web_testing"
        elif 'agent' in tool_name or 'message' in tool_name or 'finish' in tool_name:
            return "coordination"
        else:
            return "general"

    def _extract_use_cases(self, tool: Dict[str, Any]) -> List[str]:
        """Extract use cases from tool metadata"""
        tool_name = tool['name']

        use_case_map = {
            'nmap_scan': ['port_scanning', 'service_detection', 'os_fingerprinting'],
            'http_scan': ['http_endpoint_analysis', 'header_inspection', 'ssl_testing'],
            'directory_fuzzing': ['directory_discovery', 'hidden_file_discovery', 'backup_detection'],
            'sql_injection_test': ['sql_injection_detection', 'database_enumeration'],
            'xss_test': ['xss_detection', 'input_validation_testing'],
            'create_agent': ['task_delegation', 'parallel_testing'],
            'send_message': ['inter_agent_communication', 'result_sharing'],
            'finish': ['task_completion', 'report_generation']
        }

        return use_case_map.get(tool_name, [])

    def _extract_prerequisites(self, tool: Dict[str, Any]) -> List[str]:
        """Extract prerequisites for tool usage"""
        tool_name = tool['name']

        prereq_map = {
            'sql_injection_test': ['http_scan_completed', 'target_must_be_web_application'],
            'xss_test': ['http_scan_completed', 'input_fields_identified'],
            'directory_fuzzing': ['target_must_be_web_server'],
            'nmap_scan': ['target_must_be_ip_or_domain'],
        }

        return prereq_map.get(tool_name, [])

    def _is_mcp_tool(self, tool_name: str) -> bool:
        """Check if tool is available via MCP server"""
        mcp_tools = [
            'nmap_scan',
            'http_scan',
            'directory_fuzzing',
            'sql_injection_test',
            'xss_test'
        ]
        return tool_name in mcp_tools


# Helper function
async def seed_knowledge_base(
    embeddings_service: Optional[EmbeddingsService] = None,
    vector_store: Optional[VectorStore] = None
):
    """
    Convenience function to seed the knowledge base.

    Args:
        embeddings_service: Embeddings service instance
        vector_store: Vector store instance
    """
    from .embeddings_service import get_embeddings_service
    from .vector_store import get_vector_store

    if embeddings_service is None:
        embeddings_service = get_embeddings_service()
    if vector_store is None:
        vector_store = get_vector_store()

    seeder = KnowledgeBaseSeeder(embeddings_service, vector_store)
    await seeder.seed_all()

    logger.info("Knowledge base fully seeded and ready for use")
