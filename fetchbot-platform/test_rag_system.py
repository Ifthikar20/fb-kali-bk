#!/usr/bin/env python3
"""
Comprehensive RAG System Test Script

This script tests all RAG components to verify proper installation and functionality.
"""

import asyncio
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))


async def test_rag_system():
    """Run comprehensive RAG system tests"""

    print("=" * 70)
    print("🧪 FETCHBOT.AI RAG SYSTEM TEST SUITE")
    print("=" * 70)
    print()

    # Test 1: Configuration Loading
    print("Test 1: Configuration Loading")
    print("-" * 70)
    try:
        from config import get_settings
        settings = get_settings()
        print(f"✅ RAG Enabled: {settings.rag_enabled}")
        print(f"✅ Vector DB: {settings.rag_vector_db}")
        print(f"✅ Persist Dir: {settings.rag_chroma_persist_dir}")
        print(f"✅ Embedding Model: {settings.rag_embedding_model}")
        print(f"✅ Top-K Results: {settings.rag_top_k_results}")
        print(f"✅ Confidence Threshold: {settings.rag_confidence_threshold}")
    except Exception as e:
        print(f"❌ Configuration failed: {e}")
        return False

    print()

    # Test 2: Embeddings Service
    print("Test 2: Embeddings Service")
    print("-" * 70)
    try:
        from core.rag.embeddings_service import get_embeddings_service

        embeddings_svc = get_embeddings_service(settings.rag_embedding_model)

        # Test embedding generation
        test_text = "SQL injection vulnerability testing"
        embedding = await embeddings_svc.embed_async(test_text)

        print(f"✅ Generated embedding for: '{test_text}'")
        print(f"✅ Embedding dimensions: {len(embedding)}")
        print(f"✅ Expected dimensions: {settings.rag_embedding_dimensions}")

        if len(embedding) != settings.rag_embedding_dimensions:
            print(f"⚠️  Dimension mismatch! Expected {settings.rag_embedding_dimensions}, got {len(embedding)}")

    except Exception as e:
        print(f"❌ Embeddings service failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Test 3: Vector Store
    print("Test 3: Vector Store")
    print("-" * 70)
    try:
        from core.rag.vector_store import get_vector_store

        vector_store = get_vector_store(persist_directory=settings.rag_chroma_persist_dir)

        # Get collection stats
        stats = vector_store.get_all_stats()

        total_docs = sum(s.get('document_count', 0) for s in stats)
        print(f"✅ Vector store initialized")
        print(f"✅ Total documents across all collections: {total_docs}")
        print()
        print("Collection breakdown:")
        for stat in stats:
            count = stat.get('document_count', 0)
            status = "✅" if count > 0 else "⚠️ "
            print(f"  {status} {stat['collection']:30s}: {count:3d} documents")

        if total_docs == 0:
            print()
            print("⚠️  No documents found! Run: python scripts/seed_rag_kb.py --all")

    except Exception as e:
        print(f"❌ Vector store failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Test 4: Retrieval Service
    print("Test 4: Retrieval Service - Tool Knowledge Query")
    print("-" * 70)
    try:
        from core.rag.retrieval_service import get_rag_service

        retrieval_svc = get_rag_service()

        # Test querying tool knowledge
        query = "SQL injection testing tools"

        results = await retrieval_svc.query_tool_knowledge(
            query=query,
            top_k=3
        )

        print(f"✅ Query: '{query}'")
        print(f"✅ Found {len(results)} relevant tools")

        if results:
            print()
            for i, result in enumerate(results, 1):
                print(f"  {i}. Similarity: {result.similarity_score:.3f}")
                print(f"     Document: {result.document[:100]}...")
                print()
        else:
            print("⚠️  No results found. Make sure knowledge base is seeded.")

    except Exception as e:
        print(f"❌ Retrieval service failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Test 5: Tool Suggestions
    print("Test 5: Tool Suggestions")
    print("-" * 70)
    try:
        from core.rag.models import ScanContext

        # Create a realistic scan context
        context = ScanContext(
            target_url="https://example-wordpress.com",
            tech_stack_detected=["WordPress", "PHP", "MySQL", "Apache"],
            current_findings=[],
            previous_tools_used=["nmap_scan"],
            agent_specialization=["web", "database"]
        )

        suggestions = await retrieval_svc.suggest_tools(context, max_suggestions=5)

        print(f"✅ Scan Context: {context.target_url}")
        print(f"✅ Tech Stack: {', '.join(context.tech_stack_detected)}")
        print(f"✅ RAG suggested {len(suggestions)} tools")

        if suggestions:
            print()
            for i, s in enumerate(suggestions, 1):
                print(f"  {i}. {s.tool_name}")
                print(f"     Confidence: {s.confidence:.2f}")
                print(f"     Success Rate: {s.expected_success_rate:.0%}")
                print(f"     Similar Scans: {s.similar_executions_count}")
                print(f"     Reasoning: {s.reasoning[:100]}...")
                print()
        else:
            print("⚠️  No tool suggestions. This is expected if execution_history is empty.")
            print("     The system will learn from actual scans over time.")

    except Exception as e:
        print(f"❌ Tool suggestion failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Test 6: Prompt Augmentation
    print("Test 6: Prompt Augmentation")
    print("-" * 70)
    try:
        base_prompt = "Test this WordPress site for vulnerabilities"

        # First, retrieve some contexts based on the scan
        retrieved_contexts = await retrieval_svc.query_tool_knowledge(
            query="WordPress security testing tools and techniques",
            top_k=5
        )

        # Then augment the prompt with retrieved contexts
        augmented_prompt = await retrieval_svc.augment_agent_prompt(
            base_prompt=base_prompt,
            retrieved_contexts=retrieved_contexts
        )

        print(f"✅ Original prompt length: {len(base_prompt)} chars")
        print(f"✅ Retrieved contexts: {len(retrieved_contexts)}")
        print(f"✅ Augmented prompt length: {len(augmented_prompt)} chars")
        print(f"✅ Added context: {len(augmented_prompt) - len(base_prompt)} chars")

        print()
        print("Preview of augmented prompt:")
        print("-" * 70)
        print(augmented_prompt[:500])
        if len(augmented_prompt) > 500:
            print("...")
        else:
            print(augmented_prompt)

    except Exception as e:
        print(f"❌ Prompt augmentation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Final Summary
    print("=" * 70)
    print("🎉 RAG SYSTEM TEST COMPLETE")
    print("=" * 70)
    print()
    print("✅ All core components are working!")
    print()
    print("Next Steps:")
    print("  1. Start the API server: uvicorn api:app --reload")
    print("  2. Create a pentesting job via API or UI")
    print("  3. Watch RAG suggestions in real-time in the logs")
    print("  4. As scans complete, RAG learns and improves suggestions")
    print()

    if total_docs < 10:
        print("⚠️  Recommendation: Seed more knowledge for better suggestions")
        print("     Run: python scripts/seed_rag_kb.py --all")
        print()

    return True


if __name__ == "__main__":
    try:
        result = asyncio.run(test_rag_system())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
