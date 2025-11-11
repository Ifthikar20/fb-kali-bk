"""
Vector Store implementation using ChromaDB
"""

import logging
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime

from .models import (
    CollectionType,
    RetrievalResult,
    EmbeddingDocument,
    RAGQueryRequest
)

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Vector database wrapper using ChromaDB for semantic search.

    Supports multiple collections for different knowledge types:
    - tool_knowledge
    - execution_history
    - vulnerability_patterns
    - remediation_strategies
    - payload_library
    """

    def __init__(
        self,
        persist_directory: str = "/data/chromadb",
        embedding_function=None
    ):
        """
        Initialize ChromaDB vector store.

        Args:
            persist_directory: Directory to persist the database
            embedding_function: Custom embedding function (optional)
        """
        self.persist_directory = persist_directory
        self._client = None
        self._collections = {}
        self._embedding_function = embedding_function

        logger.info(f"Initializing VectorStore at {persist_directory}")

    def _initialize_client(self):
        """Lazy initialize ChromaDB client"""
        if self._client is not None:
            return

        try:
            import chromadb

            # Use new PersistentClient API (ChromaDB 0.4+)
            self._client = chromadb.PersistentClient(
                path=self.persist_directory
            )

            logger.info("ChromaDB client initialized successfully")

        except ImportError:
            raise ImportError(
                "ChromaDB not installed. Run: pip install chromadb"
            )
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            raise

    def _get_collection(self, collection_type: CollectionType):
        """
        Get or create a collection.

        Args:
            collection_type: Type of collection

        Returns:
            ChromaDB collection object
        """
        self._initialize_client()

        collection_name = collection_type.value

        if collection_name in self._collections:
            return self._collections[collection_name]

        try:
            # Try to get existing collection
            collection = self._client.get_collection(
                name=collection_name,
                embedding_function=self._embedding_function
            )
            logger.info(f"Retrieved existing collection: {collection_name}")

        except Exception:
            # Create new collection if it doesn't exist
            collection = self._client.create_collection(
                name=collection_name,
                embedding_function=self._embedding_function,
                metadata={"created_at": datetime.utcnow().isoformat()}
            )
            logger.info(f"Created new collection: {collection_name}")

        self._collections[collection_name] = collection
        return collection

    async def add_document(
        self,
        document: EmbeddingDocument,
        embedding: Optional[List[float]] = None
    ) -> str:
        """
        Add a single document to the vector store.

        Args:
            document: Document to add
            embedding: Pre-computed embedding (optional)

        Returns:
            Document ID
        """
        collection = self._get_collection(document.collection)

        try:
            collection.add(
                ids=[document.id],
                documents=[document.document],
                metadatas=[document.metadata],
                embeddings=[embedding] if embedding else None
            )

            logger.debug(f"Added document {document.id} to {document.collection.value}")
            return document.id

        except Exception as e:
            logger.error(f"Failed to add document: {e}")
            raise

    async def add_documents(
        self,
        documents: List[EmbeddingDocument],
        embeddings: Optional[List[List[float]]] = None
    ) -> List[str]:
        """
        Add multiple documents to the vector store.

        Args:
            documents: List of documents to add
            embeddings: Pre-computed embeddings (optional)

        Returns:
            List of document IDs
        """
        if not documents:
            return []

        # Group documents by collection
        by_collection = {}
        for i, doc in enumerate(documents):
            if doc.collection not in by_collection:
                by_collection[doc.collection] = []
            by_collection[doc.collection].append((i, doc))

        added_ids = [None] * len(documents)

        # Add to each collection
        for collection_type, doc_list in by_collection.items():
            collection = self._get_collection(collection_type)

            indices = [i for i, _ in doc_list]
            docs = [doc for _, doc in doc_list]

            try:
                collection.add(
                    ids=[doc.id for doc in docs],
                    documents=[doc.document for doc in docs],
                    metadatas=[doc.metadata for doc in docs],
                    embeddings=[embeddings[i] for i in indices] if embeddings else None
                )

                for idx, doc in zip(indices, docs):
                    added_ids[idx] = doc.id

                logger.info(f"Added {len(docs)} documents to {collection_type.value}")

            except Exception as e:
                logger.error(f"Failed to add documents to {collection_type.value}: {e}")
                raise

        return added_ids

    async def query(
        self,
        query_request: RAGQueryRequest,
        query_embedding: Optional[List[float]] = None
    ) -> List[RetrievalResult]:
        """
        Query the vector store for similar documents.

        Args:
            query_request: Query parameters
            query_embedding: Pre-computed query embedding (optional)

        Returns:
            List of retrieval results
        """
        # If no specific collection, search across all collections
        collections_to_search = []
        if query_request.collection:
            collections_to_search = [query_request.collection]
        else:
            collections_to_search = list(CollectionType)

        all_results = []

        for collection_type in collections_to_search:
            try:
                collection = self._get_collection(collection_type)

                # Build where filter
                where_filter = query_request.filters if query_request.filters else None

                # Query
                results = collection.query(
                    query_texts=[query_request.query] if not query_embedding else None,
                    query_embeddings=[query_embedding] if query_embedding else None,
                    n_results=query_request.top_k,
                    where=where_filter
                )

                # Parse results
                if results['ids'] and results['ids'][0]:
                    for i in range(len(results['ids'][0])):
                        # Calculate similarity from distance (ChromaDB returns distances)
                        # Distance is typically L2 or cosine distance
                        # Convert to similarity score (0-1, higher is better)
                        distance = results['distances'][0][i] if 'distances' in results else 0.0
                        similarity = 1.0 / (1.0 + distance)  # Simple conversion

                        if similarity >= query_request.min_similarity:
                            result = RetrievalResult(
                                id=results['ids'][0][i],
                                document=results['documents'][0][i],
                                metadata=results['metadatas'][0][i],
                                similarity_score=similarity,
                                collection=collection_type.value
                            )
                            all_results.append(result)

            except Exception as e:
                logger.warning(f"Failed to query collection {collection_type.value}: {e}")
                continue

        # Sort by similarity score (descending) and limit to top_k
        all_results.sort(key=lambda x: x.similarity_score, reverse=True)
        all_results = all_results[:query_request.top_k]

        logger.info(f"Query returned {len(all_results)} results")
        return all_results

    async def query_by_metadata(
        self,
        collection_type: CollectionType,
        metadata_filter: Dict[str, Any],
        limit: int = 10
    ) -> List[RetrievalResult]:
        """
        Query documents by metadata filters only (no semantic search).

        Args:
            collection_type: Collection to search
            metadata_filter: Metadata filters
            limit: Maximum results

        Returns:
            List of retrieval results
        """
        collection = self._get_collection(collection_type)

        try:
            results = collection.get(
                where=metadata_filter,
                limit=limit
            )

            retrieval_results = []
            if results['ids']:
                for i in range(len(results['ids'])):
                    result = RetrievalResult(
                        id=results['ids'][i],
                        document=results['documents'][i],
                        metadata=results['metadatas'][i],
                        similarity_score=1.0,  # No similarity for metadata-only query
                        collection=collection_type.value
                    )
                    retrieval_results.append(result)

            logger.info(f"Metadata query returned {len(retrieval_results)} results")
            return retrieval_results

        except Exception as e:
            logger.error(f"Failed to query by metadata: {e}")
            raise

    async def delete_document(self, collection_type: CollectionType, document_id: str):
        """
        Delete a document from the vector store.

        Args:
            collection_type: Collection containing the document
            document_id: ID of document to delete
        """
        collection = self._get_collection(collection_type)

        try:
            collection.delete(ids=[document_id])
            logger.info(f"Deleted document {document_id} from {collection_type.value}")
        except Exception as e:
            logger.error(f"Failed to delete document: {e}")
            raise

    async def update_document(
        self,
        document: EmbeddingDocument,
        embedding: Optional[List[float]] = None
    ):
        """
        Update an existing document.

        Args:
            document: Updated document
            embedding: Updated embedding (optional)
        """
        collection = self._get_collection(document.collection)

        try:
            collection.update(
                ids=[document.id],
                documents=[document.document],
                metadatas=[document.metadata],
                embeddings=[embedding] if embedding else None
            )
            logger.info(f"Updated document {document.id} in {document.collection.value}")
        except Exception as e:
            logger.error(f"Failed to update document: {e}")
            raise

    def get_collection_stats(self, collection_type: CollectionType) -> Dict[str, Any]:
        """
        Get statistics about a collection.

        Args:
            collection_type: Collection to get stats for

        Returns:
            Statistics dictionary
        """
        collection = self._get_collection(collection_type)

        try:
            count = collection.count()
            return {
                "collection": collection_type.value,
                "document_count": count,
                "metadata": collection.metadata
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {
                "collection": collection_type.value,
                "document_count": 0,
                "error": str(e)
            }

    def get_all_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for all collections"""
        stats = []
        for collection_type in CollectionType:
            stats.append(self.get_collection_stats(collection_type))
        return stats

    async def clear_collection(self, collection_type: CollectionType):
        """
        Clear all documents from a collection.

        Args:
            collection_type: Collection to clear
        """
        self._initialize_client()

        try:
            self._client.delete_collection(collection_type.value)
            logger.info(f"Cleared collection: {collection_type.value}")

            # Remove from cache
            if collection_type.value in self._collections:
                del self._collections[collection_type.value]

        except Exception as e:
            logger.error(f"Failed to clear collection: {e}")
            raise

    def persist(self):
        """Persist the database to disk"""
        if self._client:
            try:
                self._client.persist()
                logger.info("Persisted ChromaDB to disk")
            except Exception as e:
                logger.error(f"Failed to persist database: {e}")


# Singleton instance
_vector_store_instance = None


def get_vector_store(persist_directory: str = "/data/chromadb") -> VectorStore:
    """
    Get or create singleton vector store instance.

    Args:
        persist_directory: Directory to persist the database

    Returns:
        VectorStore instance
    """
    global _vector_store_instance

    if _vector_store_instance is None:
        _vector_store_instance = VectorStore(persist_directory=persist_directory)

    return _vector_store_instance
