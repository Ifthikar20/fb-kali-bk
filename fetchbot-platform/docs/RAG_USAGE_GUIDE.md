# RAG System Usage Guide

## Quick Start

### 1. Installation

First, install the RAG dependencies:

```bash
cd /home/user/fb-kali-bk/fetchbot-platform
pip install -r requirements-rag.txt
```

### 2. Configuration

Add the following to your `.env` file:

```bash
# RAG Configuration
RAG_ENABLED=true
RAG_VECTOR_DB=chromadb
RAG_CHROMA_PERSIST_DIR=/data/chromadb
RAG_EMBEDDING_MODEL=all-MiniLM-L6-v2
RAG_EMBEDDING_DIMENSIONS=384
RAG_TOP_K_RESULTS=5
RAG_CONFIDENCE_THRESHOLD=0.7
RAG_USE_OPENAI_EMBEDDINGS=false

# Optional: If using OpenAI embeddings
# OPENAI_API_KEY=sk-...
# RAG_USE_OPENAI_EMBEDDINGS=true
# RAG_EMBEDDING_MODEL=text-embedding-3-small
```

### 3. Initialize Database

Create the RAG tables in your database:

```bash
python -c "from models import init_db; init_db()"
```

### 4. Seed Knowledge Base

Populate the vector database with initial security knowledge:

```bash
python scripts/seed_rag_kb.py --all
```

This will seed:
- Tool knowledge from your tool registry
- Vulnerability patterns (SQL injection, XSS, etc.)
- Remediation strategies
- Payload libraries

### 5. Verify Setup

Check that the knowledge base was seeded successfully:

```python
from core.rag.vector_store import get_vector_store

vector_store = get_vector_store()
stats = vector_store.get_all_stats()

for stat in stats:
    print(f"{stat['collection']}: {stat['document_count']} documents")
```

Expected output:
```
tool_knowledge: 8 documents
execution_history: 0 documents
vulnerability_patterns: 7 documents
remediation_strategies: 3 documents
payload_library: 4 documents
```

---

## Using RAG-Enhanced Agents

### Option 1: Automatic (Recommended)

The RAG system integrates automatically when `RAG_ENABLED=true` in your config. The orchestrator will use RAG-enhanced agents by default.

### Option 2: Explicit Usage

To explicitly create a RAG-enhanced agent:

```python
from core.agents.rag_enhanced_agent import RAGEnhancedAgent
from core.llm.config import LLMConfig

# Create agent configuration
config = {
    "llm_config": LLMConfig(prompt_modules=["sql_injection"]),
    "max_iterations": 50,
    "sandbox_url": "http://kali-agent-1:9000",
    "target": "https://example.com",
    "job_id": "scan_123"
}

# Create RAG-enhanced agent
agent = RAGEnhancedAgent(
    config=config,
    name="SQL Injection Specialist",
    task="Test for SQL injection vulnerabilities"
)

# Run the agent
result = await agent.agent_loop("Find SQL injection vulnerabilities")
```

---

## Understanding RAG Features

### 1. Intelligent Tool Suggestions

Before each LLM call, the RAG system:

1. **Analyzes current scan context**:
   - Target URL
   - Technologies detected (WordPress, MySQL, etc.)
   - Findings so far
   - Tools already used

2. **Queries knowledge base**:
   - Similar historical scans
   - Relevant vulnerability patterns
   - Tool effectiveness data

3. **Suggests next tools**:
   ```python
   suggestions = await rag_service.suggest_tools(scan_context)
   # Returns:
   # [
   #   ToolSuggestion(
   #     tool_name="sql_injection_test",
   #     confidence=0.87,
   #     reasoning="Similar WordPress sites showed SQL injection in /wp-admin/admin-ajax.php",
   #     similar_executions_count=12,
   #     expected_success_rate=0.73
   #   ),
   #   ...
   # ]
   ```

### 2. Context-Aware Prompts

The RAG system augments LLM prompts with relevant context:

```
Original System Prompt:
  You are a security testing agent...

RAG-Enhanced Prompt:
  You are a security testing agent...

  ## RAG-Retrieved Intelligence

  ### Context 1 (Relevance: 0.89)
  **Source**: vulnerability_patterns
  **Content**: SQL injection vulnerability in MySQL databases...
  **Recommended Tools**: sql_injection_test

  ### Context 2 (Relevance: 0.82)
  **Source**: execution_history
  **Content**: Executed sql_injection_test on WordPress site...
  **Historical Success**: True
  **Findings**: 3
```

This gives agents:
- Historical execution patterns
- Known vulnerability signatures
- Proven attack vectors
- Framework-specific knowledge

### 3. Automatic Learning

After each tool execution, results are stored in the vector database:

```python
# Automatic after every tool invocation
execution_data = {
    "tool_name": "sql_injection_test",
    "target_url": "https://example.com",
    "tech_stack": ["WordPress", "MySQL"],
    "success": True,
    "findings_count": 2,
    "severity_distribution": {"critical": 1, "high": 1},
    "execution_time_seconds": 8.5
}

await rag_service.store_execution(execution_data)
```

This creates a **feedback loop**:
- New executions → Stored in vector DB
- Future scans → Learn from past executions
- Accuracy improves over time

---

## Advanced Usage

### Querying the Knowledge Base

#### Search Tool Knowledge

```python
from core.rag.retrieval_service import get_rag_service

rag_service = get_rag_service()

# Query for tool information
results = await rag_service.query_tool_knowledge(
    query="tools for testing SQL injection in WordPress",
    target_info={"framework": "WordPress", "database": "MySQL"},
    top_k=5
)

for result in results:
    print(f"{result.similarity_score:.2f}: {result.document}")
```

#### Get Similar Executions

```python
# Find similar historical executions
executions = await rag_service.get_similar_executions(
    tool_name="sql_injection_test",
    target_characteristics={
        "tech_stack": ["WordPress", "MySQL"],
        "target_type": "web_application"
    },
    limit=10
)

for exec in executions:
    print(f"Target: {exec.target_url}")
    print(f"Success: {exec.success}, Findings: {exec.findings_count}")
    print(f"Time: {exec.execution_time_seconds}s")
```

### Custom Knowledge Seeding

Add your own security knowledge:

```python
from core.rag.models import EmbeddingDocument, CollectionType
from core.rag.vector_store import get_vector_store
from core.rag.embeddings_service import get_embeddings_service

vector_store = get_vector_store()
embeddings_service = get_embeddings_service()

# Add custom vulnerability pattern
doc_text = "Custom XSS bypass technique for ModSecurity WAF..."
metadata = {
    "vulnerability_type": "xss",
    "waf_bypass": "modsecurity",
    "recommended_tools": ["xss_test"],
    "payload": "<svg/onload=alert(1)>"
}

embedding = await embeddings_service.embed_async(doc_text)

document = EmbeddingDocument(
    id="custom_xss_001",
    document=doc_text,
    metadata=metadata,
    collection=CollectionType.VULNERABILITY_PATTERNS
)

await vector_store.add_document(document, embedding=embedding)
```

### Backfilling Historical Data

Seed from existing scan results:

```python
from models import SessionLocal, PentestJob, Finding

db = SessionLocal()

# Query completed scans
scans = db.query(PentestJob).filter(
    PentestJob.status == "completed"
).all()

for scan in scans:
    # Extract tech stack, findings, etc.
    execution_data = {
        "tool_name": "inferred_from_findings",
        "target_url": scan.target,
        "success": scan.total_findings > 0,
        "findings_count": scan.total_findings,
        "severity_distribution": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count
        }
    }

    await rag_service.store_execution(execution_data)
```

---

## CLI Tools

### Seed Knowledge Base

```bash
# Seed all collections
python scripts/seed_rag_kb.py --all

# Seed specific collections
python scripts/seed_rag_kb.py --tool-knowledge --vuln-patterns

# Clear and re-seed
python scripts/seed_rag_kb.py --all --clear-first

# Use different embedding model
python scripts/seed_rag_kb.py --all --model "all-mpnet-base-v2"
```

### View Statistics

```bash
python -c "
from core.rag.vector_store import get_vector_store
vector_store = get_vector_store()
stats = vector_store.get_all_stats()
for stat in stats:
    print(f'{stat[\"collection\"]}: {stat[\"document_count\"]} documents')
"
```

---

## Performance Tuning

### Embedding Cache

The embeddings service caches frequently embedded texts:

```python
from core.rag.embeddings_service import get_embeddings_service

embeddings_service = get_embeddings_service()

# Check cache stats
info = embeddings_service.get_model_info()
print(f"Cache: {info['cache_size']}/{info['max_cache_size']}")

# Save cache to disk
embeddings_service.save_cache("/data/embeddings_cache.json")

# Load cache from disk
embeddings_service.load_cache("/data/embeddings_cache.json")

# Clear cache
embeddings_service.clear_cache()
```

### Batch Processing

For bulk operations, use batch embedding:

```python
texts = ["Text 1", "Text 2", ..., "Text 100"]

# Efficient batch processing
embeddings = await embeddings_service.embed_batch_async(
    texts,
    batch_size=32  # Process 32 at a time
)
```

### Vector Database Optimization

```python
from core.rag.vector_store import get_vector_store

vector_store = get_vector_store()

# Persist to disk manually
vector_store.persist()

# Get collection statistics
stats = vector_store.get_collection_stats(CollectionType.TOOL_KNOWLEDGE)
print(f"Documents: {stats['document_count']}")
```

---

## Monitoring & Debugging

### Enable Debug Logging

```python
import logging

# Enable RAG debug logs
logging.getLogger("core.rag").setLevel(logging.DEBUG)

# View RAG suggestions
logging.getLogger("core.agents.rag_enhanced_agent").setLevel(logging.INFO)
```

### View RAG Suggestions

RAG suggestions are logged at INFO level:

```
INFO - RAG suggested 3 tools:
INFO -   1. sql_injection_test (confidence: 0.87)
INFO -   2. directory_fuzzing (confidence: 0.82)
INFO -   3. xss_test (confidence: 0.76)
```

### Query Performance

Track query latency:

```python
import time

start = time.time()
results = await rag_service.query_tool_knowledge("SQL injection WordPress")
elapsed = time.time() - start

print(f"Query took {elapsed*1000:.2f}ms")
# Expected: < 100ms for ChromaDB
```

---

## Troubleshooting

### Issue: Knowledge Base Not Seeding

**Symptom**: `seed_rag_kb.py` fails with import errors

**Solution**:
```bash
# Ensure you're in the correct directory
cd /home/user/fb-kali-bk/fetchbot-platform

# Install dependencies
pip install -r requirements-rag.txt

# Verify installation
python -c "import chromadb; import sentence_transformers; print('OK')"
```

### Issue: RAG Not Providing Suggestions

**Symptom**: Agent logs show "RAG suggested 0 tools"

**Possible Causes**:
1. Knowledge base not seeded
2. Confidence threshold too high
3. No relevant historical data

**Solution**:
```python
# Check if knowledge base is populated
from core.rag.vector_store import get_vector_store
stats = get_vector_store().get_all_stats()
# Should show documents > 0

# Lower confidence threshold in .env
RAG_CONFIDENCE_THRESHOLD=0.5

# Seed knowledge base
python scripts/seed_rag_kb.py --all
```

### Issue: Slow Embedding Generation

**Symptom**: First tool suggestion takes >10 seconds

**Explanation**: First call loads the embedding model into memory (one-time cost ~5-10s)

**Optimization**:
```python
# Pre-load model at startup
from core.rag.embeddings_service import get_embeddings_service
embeddings_service = get_embeddings_service()
embeddings_service._initialize_model()  # Pre-load
```

### Issue: ChromaDB Permission Errors

**Symptom**: `PermissionError: [Errno 13] Permission denied: '/data/chromadb'`

**Solution**:
```bash
# Create directory with correct permissions
mkdir -p /data/chromadb
chmod 755 /data/chromadb

# Or use local directory
# In .env:
RAG_CHROMA_PERSIST_DIR=./data/chromadb
```

---

## Best Practices

### 1. Seed Knowledge Base Regularly

After significant changes to tools or discovering new vulnerability patterns:

```bash
# Update knowledge base
python scripts/seed_rag_kb.py --tool-knowledge

# Or full re-seed
python scripts/seed_rag_kb.py --all --clear-first
```

### 2. Monitor RAG Accuracy

Track how often RAG suggestions lead to findings:

```python
# In agent code
suggested_tools = [s.tool_name for s in rag_suggestions]
actually_used_tools = [...]  # Tools that found vulnerabilities

accuracy = len(set(suggested_tools) & set(actually_used_tools)) / len(suggested_tools)
print(f"RAG accuracy: {accuracy:.2%}")
```

### 3. Balance Exploration vs. Exploitation

Don't rely solely on RAG suggestions - maintain randomness:

```python
# Use RAG suggestions 80% of the time
# Explore new tools 20% of the time
if random.random() < 0.8:
    tool = rag_suggestions[0].tool_name
else:
    tool = random.choice(all_available_tools)
```

### 4. Customize for Your Environment

Add organization-specific knowledge:

```python
# Add internal vulnerability patterns
# Add custom payloads that work in your environment
# Add framework-specific knowledge for your tech stack
```

---

## Performance Benchmarks

Expected performance (on average hardware):

- **Embedding Generation**: 50-100ms per document (cached: <1ms)
- **Vector Search**: 20-50ms for top-5 results
- **Total RAG Overhead**: 100-200ms per agent iteration
- **Memory Usage**: ~300MB (model + vector DB)
- **Disk Usage**: ~10MB per 1000 documents

---

## Next Steps

- ✅ RAG system is installed and configured
- ✅ Knowledge base is seeded
- ✅ Agents use RAG automatically
- ⏭ Monitor RAG accuracy and iterate
- ⏭ Add organization-specific knowledge
- ⏭ Fine-tune confidence thresholds
- ⏭ Backfill historical scan data

For more details, see:
- [RAG Architecture Documentation](RAG_ARCHITECTURE.md)
- [API Reference](RAG_API_REFERENCE.md)
- [Examples](../examples/rag_examples.py)
