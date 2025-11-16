"""
Embeddings Service for converting text to vector representations
"""

import asyncio
import logging
from typing import List, Optional
from functools import lru_cache
import hashlib
import json

logger = logging.getLogger(__name__)


class EmbeddingsService:
    """
    Service for generating text embeddings using sentence transformers.

    Supports both local models (sentence-transformers) and OpenAI embeddings API.
    Implements caching for frequently embedded texts.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        use_openai: bool = False,
        openai_api_key: Optional[str] = None,
        cache_size: int = 1000
    ):
        """
        Initialize embeddings service.

        Args:
            model_name: Name of the sentence transformer model or OpenAI model
            use_openai: Whether to use OpenAI embeddings API
            openai_api_key: OpenAI API key (required if use_openai=True)
            cache_size: Number of embeddings to cache in memory
        """
        self.model_name = model_name
        self.use_openai = use_openai
        self.openai_api_key = openai_api_key
        self._model = None
        self._cache_size = cache_size
        self._embedding_cache = {}

        logger.info(f"Initializing EmbeddingsService with model: {model_name}")

    def _initialize_model(self):
        """Lazy load the embedding model"""
        if self._model is not None:
            return

        if self.use_openai:
            try:
                import openai
                openai.api_key = self.openai_api_key
                self._model = "openai"
                self.embedding_dimensions = 1536  # OpenAI embeddings dimension
                logger.info("Initialized OpenAI embeddings")
            except ImportError:
                raise ImportError("OpenAI package not installed. Run: pip install openai")
        else:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self.model_name)
                self.embedding_dimensions = self._model.get_sentence_embedding_dimension()
                logger.info(f"Initialized SentenceTransformer model: {self.model_name} (dim={self.embedding_dimensions})")
            except ImportError:
                raise ImportError("sentence-transformers not installed. Run: pip install sentence-transformers")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                raise

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def _get_from_cache(self, text: str) -> Optional[List[float]]:
        """Retrieve embedding from cache"""
        cache_key = self._get_cache_key(text)
        return self._embedding_cache.get(cache_key)

    def _add_to_cache(self, text: str, embedding: List[float]):
        """Add embedding to cache with LRU eviction"""
        cache_key = self._get_cache_key(text)

        # Simple LRU: if cache is full, remove oldest entry
        if len(self._embedding_cache) >= self._cache_size:
            # Remove first item (oldest)
            oldest_key = next(iter(self._embedding_cache))
            del self._embedding_cache[oldest_key]

        self._embedding_cache[cache_key] = embedding

    def embed_text(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.

        Args:
            text: Text to embed

        Returns:
            List of floats representing the embedding vector
        """
        if not text or not text.strip():
            raise ValueError("Text cannot be empty")

        # Check cache first
        cached_embedding = self._get_from_cache(text)
        if cached_embedding is not None:
            logger.debug(f"Cache hit for text: {text[:50]}...")
            return cached_embedding

        # Initialize model if needed
        self._initialize_model()

        try:
            if self.use_openai:
                import openai
                response = openai.Embedding.create(
                    input=text,
                    model=self.model_name
                )
                embedding = response['data'][0]['embedding']
            else:
                embedding = self._model.encode(text, convert_to_numpy=True).tolist()

            # Cache the result
            self._add_to_cache(text, embedding)

            logger.debug(f"Generated embedding for text: {text[:50]}... (dim={len(embedding)})")
            return embedding

        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            raise

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Generate embeddings for multiple texts efficiently.

        Args:
            texts: List of texts to embed
            batch_size: Number of texts to process at once

        Returns:
            List of embedding vectors
        """
        if not texts:
            return []

        # Check cache for all texts
        embeddings = []
        texts_to_embed = []
        cache_indices = []

        for i, text in enumerate(texts):
            if not text or not text.strip():
                logger.warning(f"Empty text at index {i}, using zero vector")
                embeddings.append([0.0] * self.embedding_dimensions if hasattr(self, 'embedding_dimensions') else [0.0] * 384)
                continue

            cached = self._get_from_cache(text)
            if cached is not None:
                embeddings.append(cached)
            else:
                texts_to_embed.append(text)
                cache_indices.append(i)
                embeddings.append(None)  # Placeholder

        # If all were cached, return early
        if not texts_to_embed:
            logger.debug(f"All {len(texts)} embeddings retrieved from cache")
            return embeddings

        # Initialize model if needed
        self._initialize_model()

        logger.info(f"Generating embeddings for {len(texts_to_embed)}/{len(texts)} texts")

        try:
            if self.use_openai:
                import openai
                # OpenAI API has batch limit of 2048
                new_embeddings = []
                for i in range(0, len(texts_to_embed), min(batch_size, 2048)):
                    batch = texts_to_embed[i:i + min(batch_size, 2048)]
                    response = openai.Embedding.create(
                        input=batch,
                        model=self.model_name
                    )
                    batch_embeddings = [item['embedding'] for item in response['data']]
                    new_embeddings.extend(batch_embeddings)
            else:
                # Sentence transformers batch processing
                new_embeddings = self._model.encode(
                    texts_to_embed,
                    batch_size=batch_size,
                    convert_to_numpy=True,
                    show_progress_bar=len(texts_to_embed) > 100
                ).tolist()

            # Insert new embeddings and cache them
            for idx, new_emb in zip(cache_indices, new_embeddings):
                embeddings[idx] = new_emb
                self._add_to_cache(texts[idx], new_emb)

            logger.info(f"Successfully generated {len(new_embeddings)} embeddings")
            return embeddings

        except Exception as e:
            logger.error(f"Failed to generate batch embeddings: {e}")
            raise

    async def embed_async(self, text: str) -> List[float]:
        """
        Async wrapper for embed_text to avoid blocking.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.embed_text, text)

    async def embed_batch_async(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Async wrapper for embed_batch to avoid blocking.

        Args:
            texts: List of texts to embed
            batch_size: Batch size for processing

        Returns:
            List of embedding vectors
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.embed_batch, texts, batch_size)

    def get_model_info(self) -> dict:
        """Get information about the current model"""
        self._initialize_model()
        return {
            "model_name": self.model_name,
            "use_openai": self.use_openai,
            "embedding_dimensions": self.embedding_dimensions,
            "cache_size": len(self._embedding_cache),
            "max_cache_size": self._cache_size
        }

    def clear_cache(self):
        """Clear the embedding cache"""
        self._embedding_cache.clear()
        logger.info("Embedding cache cleared")

    def save_cache(self, filepath: str):
        """Save embedding cache to disk"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self._embedding_cache, f)
            logger.info(f"Saved embedding cache to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
            raise

    def load_cache(self, filepath: str):
        """Load embedding cache from disk"""
        try:
            with open(filepath, 'r') as f:
                self._embedding_cache = json.load(f)
            logger.info(f"Loaded {len(self._embedding_cache)} cached embeddings from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            raise


# Singleton instance for reuse across application
_embeddings_service_instance = None


def get_embeddings_service(
    model_name: str = "all-MiniLM-L6-v2",
    use_openai: bool = False,
    openai_api_key: Optional[str] = None
) -> EmbeddingsService:
    """
    Get or create singleton embeddings service instance.

    Args:
        model_name: Embedding model name
        use_openai: Use OpenAI embeddings
        openai_api_key: OpenAI API key

    Returns:
        EmbeddingsService instance
    """
    global _embeddings_service_instance

    if _embeddings_service_instance is None:
        _embeddings_service_instance = EmbeddingsService(
            model_name=model_name,
            use_openai=use_openai,
            openai_api_key=openai_api_key
        )

    return _embeddings_service_instance
