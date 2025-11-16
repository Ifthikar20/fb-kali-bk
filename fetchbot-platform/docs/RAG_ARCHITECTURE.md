# RAG-Enhanced Tool Selection Architecture

## Overview

This document describes the Retrieval-Augmented Generation (RAG) system integrated with FetchBot.ai's MCP server and agent architecture. The RAG system enables intelligent, context-aware tool selection by leveraging historical execution data, vulnerability patterns, and semantic search capabilities.

## Architecture Vision

```
┌─────────────────────────────────────────────────────────────────┐
│                        FETCHBOT.AI RAG SYSTEM                    │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│   UI Layer   │◄───────│  WebSocket   │◄───────│  FastAPI     │
│  (React)     │  Stream│   Manager    │  Events│   Server     │
└──────────────┘        └──────────────┘        └──────┬───────┘
                                                        │
                        ┌───────────────────────────────┼────────────┐
                        │        Agent Orchestrator     │            │
                        └───────────────────────────────┼────────────┘
                                                        │
                ┌───────────────────────────────────────┼────────────────┐
                │                                       │                │
         ┌──────▼──────┐                      ┌────────▼────────┐       │
         │ Root Agent  │                      │ Specialized     │       │
         │             │                      │ Agents (SQL,    │       │
         │ ┌─────────┐ │                      │ XSS, Network)   │       │
         │ │RAG Query│ │                      │ ┌─────────┐     │       │
         │ └────┬────┘ │                      │ │RAG Query│     │       │
         └──────┼──────┘                      └─┴────┬────┴─────┘       │
                │                                     │                  │
                └─────────────────┬───────────────────┘                  │
                                  │                                      │
                    ┌─────────────▼─────────────┐                       │
                    │   RAG Retrieval Service    │                       │
                    │                            │                       │
                    │  ┌──────────────────────┐  │                       │
                    │  │ Query Processor      │  │                       │
                    │  │ - Embed query        │  │                       │
                    │  │ - Context builder    │  │                       │
                    │  └──────────────────────┘  │                       │
                    │                            │                       │
                    │  ┌──────────────────────┐  │                       │
                    │  │ Similarity Search    │  │                       │
                    │  │ - Tool knowledge     │  │                       │
                    │  │ - Execution history  │  │                       │
                    │  │ - Vuln patterns      │  │                       │
                    │  └──────────────────────┘  │                       │
                    │                            │                       │
                    │  ┌──────────────────────┐  │                       │
                    │  │ Re-ranker            │  │                       │
                    │  │ - Score contexts     │  │                       │
                    │  │ - Filter relevance   │  │                       │
                    │  └──────────────────────┘  │                       │
                    └────────────┬───────────────┘                       │
                                 │                                       │
                    ┌────────────▼───────────────┐                       │
                    │  Vector Database           │                       │
                    │  (ChromaDB / pgvector)     │                       │
                    │                            │                       │
                    │  Collections:              │                       │
                    │  ├─ tool_knowledge         │                       │
                    │  ├─ execution_history      │                       │
                    │  ├─ vulnerability_patterns │                       │
                    │  ├─ remediation_strategies │                       │
                    │  └─ payload_library        │                       │
                    └────────────┬───────────────┘                       │
                                 │                                       │
                    ┌────────────▼───────────────┐                       │
                    │  PostgreSQL Database       │                       │
                    │                            │                       │
                    │  New Tables:               │                       │
                    │  ├─ rag_tool_executions    │                       │
                    │  ├─ rag_feedback           │                       │
                    │  └─ rag_embeddings_meta    │                       │
                    └────────────────────────────┘                       │
                                                                          │
                    ┌─────────────────────────────────────────────────┐  │
                    │         MCP Server (Enhanced)                   │  │
                    │                                                 │  │
                    │  Tools:                                         │  │
                    │  ├─ nmap_scan                                   │  │
                    │  ├─ http_scan                                   │  │
                    │  ├─ directory_fuzzing                           │  │
                    │  ├─ sql_injection_test                          │  │
                    │  ├─ xss_test                                    │  │
                    │  │                                              │  │
                    │  New RAG Tools:                                 │  │
                    │  ├─ query_tool_knowledge                        │  │
                    │  ├─ get_similar_executions                      │  │
                    │  └─ suggest_next_tools                          │  │
                    └─────────────────────────────────────────────────┘  │
                                                                          │
                    ┌─────────────────────────────────────────────────┐  │
                    │      Kali Agent Containers                      │◄─┘
                    │  (Tool Execution Environment)                   │
                    └─────────────────────────────────────────────────┘
```

## Core Components

### 1. RAG Retrieval Service

**Location**: `fetchbot-platform/core/rag/retrieval_service.py`

**Responsibilities**:
- Embed incoming queries (target info, current findings, agent context)
- Perform semantic similarity search across knowledge collections
- Re-rank results based on relevance and confidence scores
- Construct augmented context for LLM prompts
- Track query performance metrics

**Key Methods**:
```python
class RAGRetrievalService:
    async def query_tool_knowledge(
        self,
        query: str,
        target_info: Dict,
        current_findings: List[Dict],
        agent_context: Dict,
        top_k: int = 5
    ) -> List[RetrievalResult]

    async def suggest_tools(
        self,
        scan_context: ScanContext
    ) -> List[ToolSuggestion]

    async def get_similar_executions(
        self,
        tool_name: str,
        target_characteristics: Dict,
        limit: int = 10
    ) -> List[HistoricalExecution]

    async def augment_agent_prompt(
        self,
        base_prompt: str,
        retrieved_contexts: List[RetrievalResult]
    ) -> str
```

### 2. Vector Database

**Technology Choice**: **ChromaDB** (embedded) or **pgvector** (PostgreSQL extension)

**Recommendation**: Start with **ChromaDB** for simplicity, migrate to **pgvector** for production scale.

**Collections Structure**:

#### a. `tool_knowledge`
Stores comprehensive information about each security tool.

**Schema**:
```python
{
    "id": "tool_nmap_scan_001",
    "document": "nmap scan is used for network discovery...",
    "metadata": {
        "tool_name": "nmap_scan",
        "category": "network_reconnaissance",
        "use_cases": ["port_scanning", "service_detection", "os_fingerprinting"],
        "parameters": {...},
        "prerequisites": ["target_must_be_ip_or_domain"],
        "execution_time_avg": 15.3,  # seconds
        "success_rate": 0.95,
        "sandbox_required": true,
        "mcp_tool": true
    },
    "embedding": [0.123, 0.456, ...]  # 384 or 1536 dimensions
}
```

#### b. `execution_history`
Historical tool execution results for learning patterns.

**Schema**:
```python
{
    "id": "exec_uuid_12345",
    "document": "Executed nmap scan on WordPress site, discovered ports 80, 443, 3306...",
    "metadata": {
        "tool_name": "nmap_scan",
        "target_url": "https://example.com",
        "target_type": "web_application",
        "tech_stack": ["nginx", "mysql", "wordpress"],
        "execution_timestamp": "2024-01-15T10:30:00Z",
        "success": true,
        "findings_count": 3,
        "severity_distribution": {"critical": 0, "high": 1, "medium": 2},
        "agent_name": "Network Reconnaissance Agent",
        "scan_id": "scan_abc_123",
        "execution_time_seconds": 12.5
    },
    "embedding": [...]
}
```

#### c. `vulnerability_patterns`
Known vulnerability signatures and detection patterns.

**Schema**:
```python
{
    "id": "vuln_pattern_sqli_mysql_001",
    "document": "MySQL SQL injection detected via error-based technique using single quote...",
    "metadata": {
        "vulnerability_type": "sql_injection",
        "database_type": "mysql",
        "detection_method": "error_based",
        "affected_frameworks": ["wordpress", "drupal"],
        "recommended_tools": ["sql_injection_test", "sqlmap"],
        "severity": "critical",
        "cvss_score": 9.8,
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "payload_examples": ["' OR '1'='1", "' UNION SELECT NULL--"]
    },
    "embedding": [...]
}
```

#### d. `remediation_strategies`
Fix recommendations and security best practices.

**Schema**:
```python
{
    "id": "remediation_sqli_001",
    "document": "To fix SQL injection, use parameterized queries...",
    "metadata": {
        "vulnerability_type": "sql_injection",
        "applicable_languages": ["php", "python", "java"],
        "applicable_frameworks": ["wordpress", "django", "spring"],
        "difficulty": "medium",
        "implementation_time_hours": 4
    },
    "embedding": [...]
}
```

#### e. `payload_library`
Proven attack payloads categorized by vulnerability type.

**Schema**:
```python
{
    "id": "payload_xss_dom_001",
    "document": "DOM-based XSS payload: <img src=x onerror=alert(1)>",
    "metadata": {
        "vulnerability_type": "xss",
        "xss_type": "dom_based",
        "browser_compatibility": ["chrome", "firefox", "safari"],
        "waf_evasion_level": "medium",
        "success_rate_historical": 0.73,
        "blocked_by_wafs": ["cloudflare", "akamai"]
    },
    "embedding": [...]
}
```

### 3. Embeddings Service

**Location**: `fetchbot-platform/core/rag/embeddings_service.py`

**Technology**: Sentence Transformers (local, free) or OpenAI Embeddings API

**Recommended Model**: `sentence-transformers/all-MiniLM-L6-v2`
- Dimensions: 384
- Fast inference
- Good for security domain with fine-tuning

**Interface**:
```python
class EmbeddingsService:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)

    def embed_text(self, text: str) -> List[float]:
        """Generate embedding for single text"""
        return self.model.encode(text).tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embedding for efficiency"""
        return self.model.encode(texts).tolist()

    async def embed_async(self, text: str) -> List[float]:
        """Async wrapper for non-blocking"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.embed_text,
            text
        )
```

### 4. Knowledge Base Seeder

**Location**: `fetchbot-platform/core/rag/seeder.py`

**Purpose**: Populate vector database with initial knowledge.

**Seed Sources**:
1. **Tool Registry** → Extract tool metadata → Embed descriptions
2. **Vulnerability Database** → OWASP, CVE, CWE data → Embed patterns
3. **Historical Scans** → Query existing findings from PostgreSQL → Embed
4. **Security Knowledge Base** → Articles, documentation → Embed
5. **Payload Collections** → PayloadsAllTheThings, SecLists → Embed

**Implementation**:
```python
class KnowledgeBaseSeeder:
    async def seed_all(self):
        """Seed all knowledge collections"""
        await self.seed_tool_knowledge()
        await self.seed_vulnerability_patterns()
        await self.seed_remediation_strategies()
        await self.seed_payload_library()
        await self.seed_historical_executions()

    async def seed_tool_knowledge(self):
        """Extract from tool registry and MCP server"""
        tools = get_all_tools()  # From registry.py
        for tool in tools:
            document = self._create_tool_document(tool)
            embedding = await self.embeddings.embed_async(document)
            await self.vector_db.add_to_collection(
                collection="tool_knowledge",
                id=f"tool_{tool['name']}",
                document=document,
                metadata=tool,
                embedding=embedding
            )
```

### 5. Agent Integration

**Modified Agent Loop** (`core/agents/base_agent.py`):

```python
class BaseAgent:
    async def agent_loop(self, task: str) -> Dict[str, Any]:
        while not self.state.should_stop():
            # NEW: Query RAG for relevant context
            rag_context = await self._retrieve_rag_context()

            # Build enhanced system prompt with RAG context
            enhanced_prompt = await self.rag_service.augment_agent_prompt(
                base_prompt=self.llm.system_prompt,
                retrieved_contexts=rag_context
            )

            # Generate LLM response with RAG-enhanced prompt
            response = await self.llm.generate(
                messages=self.state.get_conversation_history(),
                system_prompt_override=enhanced_prompt,
                scan_id=str(self.agent_id),
                step_number=self.state.iteration
            )

            # Process tool invocations
            await self._process_tool_invocations(response.tool_invocations)

            # NEW: Store execution results in RAG database
            await self._store_execution_in_rag(response.tool_invocations)

            self.state.iteration += 1

    async def _retrieve_rag_context(self) -> List[RetrievalResult]:
        """Retrieve relevant context from RAG database"""
        scan_context = ScanContext(
            target_url=self.state.target_url,
            current_findings=self.state.findings,
            tech_stack_detected=self.state.metadata.get("tech_stack", []),
            previous_tools_used=self._get_tools_history(),
            agent_specialization=self.config.llm_config.prompt_modules
        )

        # Query RAG service for:
        # 1. Similar successful executions
        # 2. Relevant vulnerability patterns
        # 3. Recommended next tools
        # 4. Applicable payloads

        results = await self.rag_service.suggest_tools(scan_context)
        return results

    async def _store_execution_in_rag(self, tool_invocations: List[ToolInvocation]):
        """Store tool execution results for future learning"""
        for invocation in tool_invocations:
            execution_doc = {
                "tool_name": invocation.tool_name,
                "target_url": self.state.target_url,
                "parameters": invocation.parameters,
                "result": invocation.result,
                "success": invocation.success,
                "findings": invocation.findings,
                "execution_time": invocation.execution_time,
                "agent_name": self.name,
                "scan_id": str(self.agent_id),
                "timestamp": datetime.utcnow().isoformat()
            }

            await self.rag_service.store_execution(execution_doc)
```

### 6. Enhanced MCP Server

**Location**: `fetchbot-platform/mcp-security-server/server.py`

**New RAG-Enabled Tools**:

```python
@app.call_tool()
async def call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
    # Existing tools...

    # NEW RAG Tools
    if name == "query_tool_knowledge":
        return await query_tool_knowledge_handler(arguments)

    elif name == "suggest_next_tools":
        return await suggest_next_tools_handler(arguments)

    elif name == "get_similar_executions":
        return await get_similar_executions_handler(arguments)


async def query_tool_knowledge_handler(args: dict) -> Sequence[TextContent]:
    """Query RAG database for tool information"""
    query = args["query"]
    context = args.get("context", {})

    results = await rag_service.query_tool_knowledge(
        query=query,
        target_info=context.get("target_info", {}),
        current_findings=context.get("current_findings", []),
        agent_context=context.get("agent_context", {}),
        top_k=args.get("top_k", 5)
    )

    response = format_rag_results(results)
    return [TextContent(type="text", text=response)]


async def suggest_next_tools_handler(args: dict) -> Sequence[TextContent]:
    """Suggest next tools based on scan context"""
    scan_context = ScanContext(**args["scan_context"])

    suggestions = await rag_service.suggest_tools(scan_context)

    response = format_tool_suggestions(suggestions)
    return [TextContent(type="text", text=response)]
```

**Updated Tool List** in `@app.list_tools()`:
```python
Tool(
    name="query_tool_knowledge",
    description="Query the RAG knowledge base for information about tools, vulnerabilities, and execution patterns",
    inputSchema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Natural language query"},
            "context": {
                "type": "object",
                "description": "Current scan context (target, findings, tech stack)"
            },
            "top_k": {"type": "integer", "default": 5}
        },
        "required": ["query"]
    }
),
Tool(
    name="suggest_next_tools",
    description="Get intelligent suggestions for next tools to execute based on current scan state",
    inputSchema={
        "type": "object",
        "properties": {
            "scan_context": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string"},
                    "current_findings": {"type": "array"},
                    "tech_stack_detected": {"type": "array"},
                    "previous_tools_used": {"type": "array"}
                }
            }
        },
        "required": ["scan_context"]
    }
)
```

### 7. Database Schema Extensions

**New PostgreSQL Tables** (in `models.py`):

```python
class RAGToolExecution(Base):
    """Store tool execution metadata for RAG learning"""
    __tablename__ = "rag_tool_executions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("pentest_jobs.id"))
    tool_name = Column(String, nullable=False)
    agent_name = Column(String)
    target_url = Column(String)
    tech_stack_detected = Column(JSON)  # Array of detected technologies
    parameters = Column(JSON)
    result_summary = Column(Text)
    success = Column(Boolean)
    findings_count = Column(Integer, default=0)
    severity_distribution = Column(JSON)
    execution_time_seconds = Column(Float)
    error_message = Column(Text)

    # For RAG retrieval
    embedding_id = Column(String)  # Reference to vector DB

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("PentestJob", back_populates="rag_executions")


class RAGFeedback(Base):
    """Track feedback on RAG suggestions for continuous improvement"""
    __tablename__ = "rag_feedback"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    suggestion_id = Column(String)  # RAG retrieval result ID
    tool_suggested = Column(String)
    tool_actually_used = Column(String)
    was_helpful = Column(Boolean)
    confidence_score = Column(Float)  # Original RAG confidence
    actual_relevance_score = Column(Float)  # User/agent feedback

    scan_id = Column(String, ForeignKey("pentest_jobs.id"))
    agent_name = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)


class RAGEmbeddingsMeta(Base):
    """Track embedding model versions and metadata"""
    __tablename__ = "rag_embeddings_meta"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_name = Column(String)  # e.g., "all-MiniLM-L6-v2"
    model_version = Column(String)
    embedding_dimensions = Column(Integer)
    total_documents_indexed = Column(Integer, default=0)
    last_reindex_at = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
```

**Add relationships to existing models**:
```python
# In PentestJob class:
rag_executions = relationship("RAGToolExecution", back_populates="scan")
```

### 8. Streaming RAG Insights

**Enhanced WebSocket Events** (`api.py`):

```python
# New event types
await ws_manager.send_event(job_id, "rag_suggestion", {
    "tool_suggested": "sql_injection_test",
    "confidence": 0.87,
    "reasoning": "Similar WordPress sites showed SQL injection in /wp-admin/admin-ajax.php",
    "similar_executions_count": 12,
    "expected_success_rate": 0.73
})

await ws_manager.send_event(job_id, "rag_context", {
    "tech_stack_detected": ["WordPress 6.2", "MySQL", "Nginx"],
    "similar_targets_found": 45,
    "recommended_tools": [
        {"name": "sql_injection_test", "confidence": 0.87},
        {"name": "directory_fuzzing", "confidence": 0.82},
        {"name": "xss_test", "confidence": 0.76}
    ]
})
```

## Data Flow: RAG-Enhanced Scan

### Sequence Diagram

```
User → API: POST /api/pentest {target: "https://example.com"}
API → DB: Create PentestJob (status=QUEUED)
API → Background: Spawn run_dynamic_scan()
Background → Orchestrator: run_scan()
Orchestrator → ContainerMgr: Spawn Kali agents
Orchestrator → RootAgent: run_assessment()

RootAgent → RAG Service: query_tool_knowledge("WordPress security assessment")
RAG Service → VectorDB: Similarity search on "WordPress security"
VectorDB → RAG Service: Top 5 relevant documents
RAG Service → RootAgent: {
  suggested_tools: ["nmap_scan", "http_scan", "directory_fuzzing"],
  confidence: 0.89,
  similar_scans: 47,
  reasoning: "WordPress sites typically vulnerable in /wp-admin, /wp-content"
}

RootAgent → LLM: Generate plan with RAG context
LLM → RootAgent: "Start with nmap_scan to discover services"

RootAgent → ToolExecutor: execute_tool("nmap_scan", {target: "..."})
ToolExecutor → KaliContainer: POST /execute
KaliContainer → ToolExecutor: {ports: [80, 443, 3306], services: [...]}

RootAgent → RAG Service: store_execution({
  tool: "nmap_scan",
  target: "example.com",
  tech_stack: ["nginx", "mysql"],
  success: true,
  findings_count: 3
})
RAG Service → VectorDB: Store execution embedding
RAG Service → PostgreSQL: Insert RAGToolExecution record

RootAgent → WebSocket: send_event("rag_suggestion", {...})
WebSocket → UI: Display RAG insights

RootAgent → RAG Service: suggest_next_tools({
  target: "example.com",
  tech_stack: ["WordPress", "MySQL"],
  findings_so_far: [...]
})
RAG Service → VectorDB: Query execution_history + vulnerability_patterns
VectorDB → RAG Service: Similar executions with MySQL + WordPress
RAG Service → RootAgent: {
  next_tools: [
    {name: "sql_injection_test", confidence: 0.91, reasoning: "..."},
    {name: "directory_fuzzing", confidence: 0.85, reasoning: "..."}
  ]
}

RootAgent → LLM: Generate next step with RAG suggestions
LLM → RootAgent: "Execute sql_injection_test on /wp-admin/admin-ajax.php"

... repeat until scan complete ...

RootAgent → Orchestrator: Return findings
Orchestrator → DB: Update PentestJob, insert Findings
Orchestrator → WebSocket: send_event("completed", {...})
```

## Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Set up ChromaDB vector database
- [ ] Implement EmbeddingsService
- [ ] Create database migrations for new RAG tables
- [ ] Build basic RAGRetrievalService
- [ ] Implement KnowledgeBaseSeeder

### Phase 2: Integration (Week 3-4)
- [ ] Integrate RAG service with BaseAgent loop
- [ ] Enhance MCP server with RAG tools
- [ ] Implement tool execution storage
- [ ] Add RAG context to LLM prompts

### Phase 3: UI & Streaming (Week 5)
- [ ] Add RAG events to WebSocket manager
- [ ] Update frontend to display RAG insights
- [ ] Implement confidence score displays
- [ ] Add tool suggestion UI components

### Phase 4: Feedback & Optimization (Week 6-7)
- [ ] Implement feedback loop for suggestions
- [ ] Add re-ranking algorithms
- [ ] Optimize embedding performance
- [ ] Fine-tune retrieval parameters

### Phase 5: Production Hardening (Week 8)
- [ ] Add caching layer (Redis)
- [ ] Implement rate limiting
- [ ] Add monitoring and metrics
- [ ] Write comprehensive tests
- [ ] Performance optimization
- [ ] Documentation

## Configuration

**New Environment Variables** (`.env`):
```bash
# RAG Configuration
RAG_ENABLED=true
RAG_VECTOR_DB=chromadb  # or pgvector
RAG_CHROMA_PERSIST_DIR=/data/chromadb
RAG_EMBEDDING_MODEL=all-MiniLM-L6-v2
RAG_EMBEDDING_DIMENSIONS=384
RAG_TOP_K_RESULTS=5
RAG_CONFIDENCE_THRESHOLD=0.7

# Optional: OpenAI embeddings (if using instead of local)
OPENAI_API_KEY=sk-...
RAG_USE_OPENAI_EMBEDDINGS=false
```

**New Settings** (`config.py`):
```python
class Settings(BaseSettings):
    # ... existing settings ...

    # RAG Settings
    rag_enabled: bool = True
    rag_vector_db: str = "chromadb"
    rag_chroma_persist_dir: str = "/data/chromadb"
    rag_embedding_model: str = "all-MiniLM-L6-v2"
    rag_embedding_dimensions: int = 384
    rag_top_k_results: int = 5
    rag_confidence_threshold: float = 0.7
    rag_use_openai_embeddings: bool = False
```

## Performance Considerations

### Scalability
- **Embedding Generation**: Batch processing for efficiency
- **Vector Search**: Sub-100ms latency with ChromaDB
- **Caching**: Redis cache for frequently queried embeddings
- **Async Operations**: All RAG calls are async, non-blocking

### Resource Usage
- **ChromaDB**: ~200MB for 10k documents (384 dimensions)
- **Embedding Model**: ~80MB in memory (all-MiniLM-L6-v2)
- **Query Latency**: <100ms for similarity search
- **Total Overhead**: ~300MB additional memory per agent

### Optimization Strategies
1. **Lazy Loading**: Load embeddings model only when needed
2. **Batch Embeddings**: Generate embeddings in batches of 32-64
3. **Result Caching**: Cache RAG results for identical queries
4. **Index Optimization**: Periodically re-index ChromaDB for performance
5. **Hybrid Search**: Combine semantic search with keyword filtering

## Security & Privacy

### Data Protection
- **Sensitive Data**: Never embed API keys, credentials, or PII
- **Data Isolation**: Each organization's execution history is segregated
- **Embedding Sanitization**: Strip sensitive info before embedding
- **Access Control**: RAG queries respect organization boundaries

### Compliance
- **Data Retention**: Configurable retention policy for execution history
- **Audit Logs**: Track all RAG queries and suggestions
- **GDPR Compliance**: Support for right to deletion (remove embeddings)

## Monitoring & Metrics

### Key Metrics to Track
```python
# RAG Performance
- rag_query_latency_ms
- rag_embedding_generation_time_ms
- rag_retrieval_accuracy_score
- rag_suggestion_acceptance_rate

# Business Metrics
- tools_suggested_vs_used
- scan_efficiency_improvement
- false_positive_reduction
- time_to_first_finding

# Resource Metrics
- vector_db_size_mb
- total_documents_indexed
- queries_per_second
- cache_hit_rate
```

### Dashboards
- RAG suggestion accuracy over time
- Tool usage patterns
- Embedding model performance
- Query latency distribution

## Testing Strategy

### Unit Tests
- Embeddings generation consistency
- Similarity search accuracy
- Context augmentation correctness
- Tool suggestion ranking

### Integration Tests
- End-to-end RAG query flow
- Agent loop with RAG integration
- MCP server RAG tools
- WebSocket RAG events

### Performance Tests
- Concurrent query load testing
- Large-scale embedding generation
- Vector search under load
- Memory usage profiling

## Migration Path

### For Existing Data
1. **Historical Scans**: Backfill execution history from existing `PentestJob` and `Finding` tables
2. **Tool Metadata**: Extract from current tool registry
3. **Embeddings**: Generate embeddings for all historical data (one-time job)
4. **Validation**: Compare RAG suggestions against actual historical tool usage

### Rollout Strategy
1. **Beta Mode**: Enable RAG for select organizations
2. **Shadow Mode**: Generate suggestions but don't act on them (collect metrics)
3. **Gradual Rollout**: Increase RAG-driven decisions incrementally
4. **Full Deployment**: RAG becomes primary tool selection mechanism

## Future Enhancements

### Phase 2 Features
- **Fine-tuned Embeddings**: Train custom embedding model on security data
- **Multi-modal RAG**: Include screenshot/image analysis
- **Adaptive Learning**: Automatic model updates based on feedback
- **Cross-scan Insights**: Learn patterns across different organizations (anonymized)
- **Payload Evolution**: Automatically generate new payloads based on WAF blocks
- **Vulnerability Chaining**: Suggest attack paths combining multiple vulns

### Advanced Capabilities
- **Graph RAG**: Use knowledge graphs for complex vulnerability relationships
- **Agentic RAG**: Agents autonomously decide when to query RAG
- **Federated Learning**: Collaborative learning across instances while preserving privacy
- **Real-time Updates**: Stream new vulnerability patterns from threat intelligence feeds

## Success Criteria

### Quantitative Goals
- **Tool Selection Accuracy**: >85% (RAG-suggested tool finds vulnerabilities)
- **Scan Efficiency**: 30% reduction in unnecessary tool executions
- **False Positive Rate**: <5% (down from current baseline)
- **Query Latency**: <100ms for RAG retrieval
- **Agent Iteration Reduction**: 20% fewer iterations to complete scans

### Qualitative Goals
- Agents make more informed decisions
- Users gain visibility into agent reasoning
- Knowledge accumulates and improves over time
- New agents benefit from historical learnings

## Conclusion

This RAG architecture transforms FetchBot.ai from a reactive tool executor to an intelligent, learning system. By leveraging semantic search, historical execution data, and vulnerability patterns, agents make context-aware decisions that improve scan quality and efficiency.

The modular design allows incremental adoption, starting with simple tool suggestions and scaling to sophisticated multi-agent collaboration with shared knowledge.

---

**Next Steps**: Proceed with Phase 1 implementation (Foundation).
