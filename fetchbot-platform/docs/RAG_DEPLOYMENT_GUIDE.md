# RAG System Deployment Guide

This guide walks you through deploying the RAG (Retrieval-Augmented Generation) system for FetchBot.ai.

---

## Prerequisites

- Python 3.9+
- PostgreSQL database
- Docker (for Kali agents)
- 2GB+ free RAM for embedding model
- 500MB+ free disk space for vector database

---

## Step-by-Step Deployment

### Step 1: Install Dependencies

```bash
cd /home/user/fb-kali-bk/fetchbot-platform

# Install base requirements (if not already installed)
pip install -r requirements.txt

# Install RAG-specific dependencies
pip install -r requirements-rag.txt
```

**Dependencies installed**:
- `chromadb`: Vector database for semantic search
- `sentence-transformers`: Local embedding model
- `torch`: Required by sentence-transformers
- `numpy`: Numerical operations

### Step 2: Configure Environment

Update your `.env` file:

```bash
# Database (existing)
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Anthropic API (existing)
ANTHROPIC_API_KEY=sk-ant-...

# ===== RAG Configuration (NEW) =====

# Enable RAG system
RAG_ENABLED=true

# Vector database selection (chromadb or pgvector)
RAG_VECTOR_DB=chromadb

# ChromaDB persistence directory
RAG_CHROMA_PERSIST_DIR=/data/chromadb

# Embedding model configuration
RAG_EMBEDDING_MODEL=all-MiniLM-L6-v2
RAG_EMBEDDING_DIMENSIONS=384

# Retrieval configuration
RAG_TOP_K_RESULTS=5
RAG_CONFIDENCE_THRESHOLD=0.7

# Embedding provider (local or OpenAI)
RAG_USE_OPENAI_EMBEDDINGS=false

# Optional: OpenAI embeddings (if RAG_USE_OPENAI_EMBEDDINGS=true)
# OPENAI_API_KEY=sk-...
```

### Step 3: Create ChromaDB Directory

```bash
# Create directory for vector database persistence
mkdir -p /data/chromadb
chmod 755 /data/chromadb

# Or use local directory (for development)
mkdir -p ./data/chromadb
```

Update `.env` if using local directory:
```bash
RAG_CHROMA_PERSIST_DIR=./data/chromadb
```

### Step 4: Initialize Database

Run database migrations to create RAG tables:

```bash
# Create all tables (including new RAG tables)
python -c "from models import init_db; init_db()"
```

This creates:
- `rag_tool_executions`: Historical tool execution data
- `rag_feedback`: Feedback on RAG suggestions
- `rag_embeddings_meta`: Embedding model metadata

### Step 5: Seed Knowledge Base

Populate the vector database with initial security knowledge:

```bash
# Make script executable
chmod +x scripts/seed_rag_kb.py

# Seed all knowledge collections
python scripts/seed_rag_kb.py --all
```

**Expected output**:
```
🚀 Starting RAG Knowledge Base Seeding
Vector DB: chromadb
Embedding Model: all-MiniLM-L6-v2
Initializing embeddings service...
Initializing vector store...
📚 Seeding all collections...
🔧 Seeding tool knowledge...
Seeded 8 tool knowledge documents
🔍 Seeding vulnerability patterns...
Seeded 7 vulnerability patterns
💊 Seeding remediation strategies...
Seeded 3 remediation strategies
💣 Seeding payload library...
Seeded 4 payloads
💾 Persisting vector database to disk...

📊 Knowledge Base Statistics:
  tool_knowledge: 8 documents
  execution_history: 0 documents
  vulnerability_patterns: 7 documents
  remediation_strategies: 3 documents
  payload_library: 4 documents

🤖 Embedding Model Info:
  Model: all-MiniLM-L6-v2
  Dimensions: 384
  Cache Size: 0/1000

✅ Knowledge base seeding completed successfully!
The RAG system is now ready to provide intelligent tool suggestions.
```

### Step 6: Verify Installation

Test the RAG system:

```python
# Run this Python script to verify
python << 'EOF'
import asyncio
from core.rag.embeddings_service import get_embeddings_service
from core.rag.vector_store import get_vector_store
from core.rag.retrieval_service import get_rag_service

async def test_rag():
    print("Testing RAG system...")

    # Test embeddings service
    embeddings_service = get_embeddings_service()
    embedding = await embeddings_service.embed_async("SQL injection test")
    print(f"✓ Embeddings service working (dim={len(embedding)})")

    # Test vector store
    vector_store = get_vector_store()
    stats = vector_store.get_all_stats()
    total_docs = sum(s['document_count'] for s in stats)
    print(f"✓ Vector store working ({total_docs} documents)")

    # Test RAG retrieval
    rag_service = get_rag_service()
    results = await rag_service.query_tool_knowledge(
        query="tools for SQL injection testing",
        top_k=3
    )
    print(f"✓ RAG retrieval working ({len(results)} results)")

    if results:
        print(f"\nTop result: {results[0].document[:100]}...")
        print(f"Similarity: {results[0].similarity_score:.2f}")

    print("\n✅ All RAG components operational!")

asyncio.run(test_rag())
EOF
```

**Expected output**:
```
Testing RAG system...
✓ Embeddings service working (dim=384)
✓ Vector store working (22 documents)
✓ RAG retrieval working (3 results)

Top result: Tool: sql_injection_test | Description: Test for SQL injection vulnerabilities...
Similarity: 0.89

✅ All RAG components operational!
```

### Step 7: Update Application Startup

Ensure RAG services initialize on application start.

Create `startup_rag.py`:

```python
"""
RAG System Startup Script
Initializes RAG services when the application starts
"""
import logging
from config import get_settings
from core.rag.embeddings_service import get_embeddings_service
from core.rag.vector_store import get_vector_store
from core.rag.retrieval_service import get_rag_service

logger = logging.getLogger(__name__)

def initialize_rag_services():
    """Initialize RAG services on application startup"""
    settings = get_settings()

    if not settings.rag_enabled:
        logger.info("RAG system disabled (RAG_ENABLED=false)")
        return

    try:
        logger.info("Initializing RAG services...")

        # Initialize embeddings service (pre-loads model)
        embeddings_service = get_embeddings_service(
            model_name=settings.rag_embedding_model,
            use_openai=settings.rag_use_openai_embeddings,
            openai_api_key=settings.openai_api_key
        )
        embeddings_service._initialize_model()
        logger.info(f"✓ Embeddings service ready (model={settings.rag_embedding_model})")

        # Initialize vector store
        vector_store = get_vector_store(
            persist_directory=settings.rag_chroma_persist_dir
        )
        stats = vector_store.get_all_stats()
        total_docs = sum(s['document_count'] for s in stats)
        logger.info(f"✓ Vector store ready ({total_docs} documents)")

        # Initialize RAG service
        rag_service = get_rag_service(
            embeddings_service=embeddings_service,
            vector_store=vector_store,
            confidence_threshold=settings.rag_confidence_threshold
        )
        logger.info("✓ RAG retrieval service ready")

        logger.info("✅ RAG system fully initialized and ready")

    except Exception as e:
        logger.error(f"❌ Failed to initialize RAG services: {e}")
        logger.warning("Application will continue without RAG features")
```

Import in `api.py` or `main.py`:

```python
from startup_rag import initialize_rag_services

# In your startup event or main function
@app.on_event("startup")
async def startup_event():
    initialize_rag_services()
    # ... other startup tasks
```

### Step 8: Restart Application

```bash
# Stop existing services
docker-compose down

# Rebuild if needed
docker-compose build

# Start with RAG enabled
docker-compose up -d

# View logs to confirm RAG initialization
docker-compose logs -f api
```

**Look for**:
```
INFO - Initializing RAG services...
INFO - ✓ Embeddings service ready (model=all-MiniLM-L6-v2)
INFO - ✓ Vector store ready (22 documents)
INFO - ✓ RAG retrieval service ready
INFO - ✅ RAG system fully initialized and ready
```

---

## Production Deployment Considerations

### 1. Resource Allocation

**Memory**:
- Embedding model: ~80MB
- Vector database: ~10MB per 1000 documents
- Cache: ~50MB
- **Total**: Allocate 2GB+ RAM for RAG components

**CPU**:
- Embedding generation: CPU-intensive
- Consider GPU for faster embeddings (optional)

**Disk**:
- Vector database: ~500MB initially
- Grows with execution history
- **Recommendation**: 10GB+ for production

### 2. Scaling Strategy

**Horizontal Scaling**:

For multiple API instances:

```yaml
# docker-compose.yml
services:
  api:
    # ... existing config ...
    environment:
      RAG_CHROMA_PERSIST_DIR: /shared/chromadb
    volumes:
      - chroma_data:/shared/chromadb

volumes:
  chroma_data:
    driver: local
```

All instances share the same vector database.

**Vertical Scaling**:

Increase resources for single instance:

```yaml
services:
  api:
    # ... existing config ...
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
```

### 3. Backup & Recovery

**Backup Vector Database**:

```bash
# Backup ChromaDB
tar -czf chromadb_backup_$(date +%Y%m%d).tar.gz /data/chromadb

# Backup PostgreSQL RAG tables
pg_dump -h postgres -U fetchbot -d fetchbot \
  -t rag_tool_executions \
  -t rag_feedback \
  -t rag_embeddings_meta \
  > rag_tables_backup_$(date +%Y%m%d).sql
```

**Restore**:

```bash
# Restore ChromaDB
tar -xzf chromadb_backup_YYYYMMDD.tar.gz -C /data/

# Restore PostgreSQL
psql -h postgres -U fetchbot -d fetchbot < rag_tables_backup_YYYYMMDD.sql
```

### 4. Monitoring

**Metrics to Track**:

```python
# In your monitoring system
from prometheus_client import Counter, Histogram

rag_queries_total = Counter('rag_queries_total', 'Total RAG queries')
rag_query_latency = Histogram('rag_query_latency_seconds', 'RAG query latency')
rag_suggestions_used = Counter('rag_suggestions_used', 'RAG suggestions actually used')
```

**Alerts**:
- RAG query latency > 1s
- Knowledge base not seeded (0 documents)
- Embedding service failures
- Disk usage > 80%

### 5. Security

**Access Control**:
- Restrict access to ChromaDB directory
- Ensure RAG tables respect organization boundaries
- Don't embed sensitive data (API keys, credentials)

```python
# In seeder or storage functions
def sanitize_for_embedding(text: str) -> str:
    """Remove sensitive data before embedding"""
    # Remove API keys, tokens, credentials
    text = re.sub(r'sk-[a-zA-Z0-9]{48}', '[REDACTED]', text)
    text = re.sub(r'Bearer [a-zA-Z0-9_-]+', '[REDACTED]', text)
    # ... more patterns
    return text
```

### 6. Performance Optimization

**Use pgvector for PostgreSQL**:

For large-scale deployments, consider pgvector:

```bash
# Install pgvector extension
psql -h postgres -U fetchbot -d fetchbot -c "CREATE EXTENSION vector;"
```

Update `.env`:
```bash
RAG_VECTOR_DB=pgvector
```

**Enable GPU Acceleration** (optional):

For faster embedding generation:

```bash
# Install CUDA-enabled torch
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

Update `.env`:
```bash
# Use larger, GPU-optimized model
RAG_EMBEDDING_MODEL=all-mpnet-base-v2
RAG_EMBEDDING_DIMENSIONS=768
```

---

## Troubleshooting Production Issues

### Issue: High Memory Usage

**Symptom**: Container OOMKilled or swapping

**Solution**:
```bash
# Limit embedding cache size
# In embeddings_service.py initialization:
EmbeddingsService(cache_size=500)  # Reduce from 1000

# Use smaller model
RAG_EMBEDDING_MODEL=all-MiniLM-L6-v2  # 80MB vs 420MB for all-mpnet-base-v2
```

### Issue: Slow Query Performance

**Symptom**: RAG queries > 500ms

**Solutions**:
1. Enable caching
2. Reduce `RAG_TOP_K_RESULTS`
3. Add Redis cache layer
4. Switch to pgvector with proper indexes

### Issue: Stale Knowledge

**Symptom**: RAG suggests outdated tools or patterns

**Solution**:
```bash
# Re-seed knowledge base
python scripts/seed_rag_kb.py --all --clear-first

# Or incremental update
python scripts/seed_rag_kb.py --tool-knowledge
```

---

## Health Checks

Add RAG health check endpoint:

```python
# In api.py
@app.get("/health/rag")
async def rag_health_check():
    """Check RAG system health"""
    settings = get_settings()

    if not settings.rag_enabled:
        return {"status": "disabled"}

    try:
        from core.rag.vector_store import get_vector_store
        vector_store = get_vector_store()
        stats = vector_store.get_all_stats()

        return {
            "status": "healthy",
            "collections": stats,
            "total_documents": sum(s['document_count'] for s in stats),
            "embedding_model": settings.rag_embedding_model
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }
```

---

## Rollback Plan

If RAG causes issues, disable without code changes:

```bash
# In .env, set:
RAG_ENABLED=false

# Restart application
docker-compose restart api
```

Application continues normally without RAG features.

---

## Success Criteria

After deployment, verify:

- ✅ RAG services initialize on startup
- ✅ Knowledge base contains documents
- ✅ Agents receive RAG suggestions
- ✅ Tool executions are stored
- ✅ Query latency < 200ms
- ✅ Memory usage within limits
- ✅ No errors in logs

---

## Next Steps

1. ✅ Deploy RAG system
2. ⏭ Monitor performance and accuracy
3. ⏭ Backfill historical scan data
4. ⏭ Add organization-specific knowledge
5. ⏭ Fine-tune confidence thresholds
6. ⏭ Implement feedback mechanisms

For more information:
- [RAG Architecture](RAG_ARCHITECTURE.md)
- [Usage Guide](RAG_USAGE_GUIDE.md)
- [API Reference](RAG_API_REFERENCE.md)
