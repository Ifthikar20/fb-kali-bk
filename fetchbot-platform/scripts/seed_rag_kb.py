#!/usr/bin/env python3
"""
CLI tool for seeding the RAG knowledge base

Usage:
    python scripts/seed_rag_kb.py [--all] [--tool-knowledge] [--vuln-patterns] [--remediation] [--payloads]
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_settings
from core.rag.embeddings_service import get_embeddings_service
from core.rag.vector_store import get_vector_store
from core.rag.seeder import KnowledgeBaseSeeder, seed_knowledge_base

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    parser = argparse.ArgumentParser(
        description='Seed the RAG knowledge base with security intelligence'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Seed all collections (default)'
    )
    parser.add_argument(
        '--tool-knowledge',
        action='store_true',
        help='Seed only tool knowledge collection'
    )
    parser.add_argument(
        '--vuln-patterns',
        action='store_true',
        help='Seed only vulnerability patterns collection'
    )
    parser.add_argument(
        '--remediation',
        action='store_true',
        help='Seed only remediation strategies collection'
    )
    parser.add_argument(
        '--payloads',
        action='store_true',
        help='Seed only payload library collection'
    )
    parser.add_argument(
        '--clear-first',
        action='store_true',
        help='Clear collections before seeding'
    )
    parser.add_argument(
        '--model',
        type=str,
        default=None,
        help='Embedding model to use (default from config)'
    )

    args = parser.parse_args()

    # Load settings
    settings = get_settings()

    logger.info("🚀 Starting RAG Knowledge Base Seeding")
    logger.info(f"Vector DB: {settings.rag_vector_db}")
    logger.info(f"Embedding Model: {settings.rag_embedding_model}")

    try:
        # Initialize services
        logger.info("Initializing embeddings service...")
        embeddings_service = get_embeddings_service(
            model_name=args.model or settings.rag_embedding_model,
            use_openai=settings.rag_use_openai_embeddings,
            openai_api_key=settings.openai_api_key
        )

        logger.info("Initializing vector store...")
        vector_store = get_vector_store(
            persist_directory=settings.rag_chroma_persist_dir
        )

        # Clear collections if requested
        if args.clear_first:
            logger.warning("⚠️  Clearing existing collections...")
            from core.rag.models import CollectionType
            for collection_type in CollectionType:
                try:
                    await vector_store.clear_collection(collection_type)
                    logger.info(f"Cleared {collection_type.value}")
                except Exception as e:
                    logger.warning(f"Could not clear {collection_type.value}: {e}")

        # Create seeder
        seeder = KnowledgeBaseSeeder(embeddings_service, vector_store)

        # Determine what to seed
        seed_all = args.all or not any([
            args.tool_knowledge,
            args.vuln_patterns,
            args.remediation,
            args.payloads
        ])

        if seed_all:
            logger.info("📚 Seeding all collections...")
            await seeder.seed_all()
        else:
            if args.tool_knowledge:
                logger.info("🔧 Seeding tool knowledge...")
                await seeder.seed_tool_knowledge()

            if args.vuln_patterns:
                logger.info("🔍 Seeding vulnerability patterns...")
                await seeder.seed_vulnerability_patterns()

            if args.remediation:
                logger.info("💊 Seeding remediation strategies...")
                await seeder.seed_remediation_strategies()

            if args.payloads:
                logger.info("💣 Seeding payload library...")
                await seeder.seed_payload_library()

        # Persist to disk
        logger.info("💾 Persisting vector database to disk...")
        vector_store.persist()

        # Show statistics
        logger.info("\n📊 Knowledge Base Statistics:")
        stats = vector_store.get_all_stats()
        for stat in stats:
            logger.info(
                f"  {stat['collection']}: {stat['document_count']} documents"
            )

        # Show model info
        model_info = embeddings_service.get_model_info()
        logger.info(f"\n🤖 Embedding Model Info:")
        logger.info(f"  Model: {model_info['model_name']}")
        logger.info(f"  Dimensions: {model_info['embedding_dimensions']}")
        logger.info(f"  Cache Size: {model_info['cache_size']}/{model_info['max_cache_size']}")

        logger.info("\n✅ Knowledge base seeding completed successfully!")
        logger.info("The RAG system is now ready to provide intelligent tool suggestions.")

    except Exception as e:
        logger.error(f"❌ Failed to seed knowledge base: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
