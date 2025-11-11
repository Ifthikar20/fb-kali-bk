"""
RAG (Retrieval-Augmented Generation) System for FetchBot.ai

This package provides intelligent, context-aware tool selection through:
- Semantic search over tool knowledge
- Historical execution pattern matching
- Vulnerability pattern recognition
- Intelligent tool suggestions
"""

from .embeddings_service import EmbeddingsService
from .vector_store import VectorStore
from .retrieval_service import RAGRetrievalService
from .seeder import KnowledgeBaseSeeder
from .models import (
    RetrievalResult,
    ToolSuggestion,
    ScanContext,
    HistoricalExecution
)

__all__ = [
    "EmbeddingsService",
    "VectorStore",
    "RAGRetrievalService",
    "KnowledgeBaseSeeder",
    "RetrievalResult",
    "ToolSuggestion",
    "ScanContext",
    "HistoricalExecution",
]
