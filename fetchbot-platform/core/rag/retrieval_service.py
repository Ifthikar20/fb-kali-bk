"""
RAG Retrieval Service - Core intelligence for tool selection
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from .models import (
    CollectionType,
    RetrievalResult,
    ToolSuggestion,
    ScanContext,
    HistoricalExecution,
    RAGQueryRequest
)
from .embeddings_service import EmbeddingsService
from .vector_store import VectorStore

logger = logging.getLogger(__name__)


class RAGRetrievalService:
    """
    Intelligent retrieval service for context-aware tool selection.

    This service combines:
    - Semantic search over tool knowledge
    - Historical execution pattern matching
    - Vulnerability pattern recognition
    - Confidence scoring and ranking
    """

    def __init__(
        self,
        embeddings_service: EmbeddingsService,
        vector_store: VectorStore,
        confidence_threshold: float = 0.7
    ):
        """
        Initialize RAG retrieval service.

        Args:
            embeddings_service: Service for generating embeddings
            vector_store: Vector database for similarity search
            confidence_threshold: Minimum confidence score for suggestions
        """
        self.embeddings_service = embeddings_service
        self.vector_store = vector_store
        self.confidence_threshold = confidence_threshold

        logger.info("Initialized RAGRetrievalService")

    async def query_tool_knowledge(
        self,
        query: str,
        target_info: Optional[Dict] = None,
        current_findings: Optional[List[Dict]] = None,
        agent_context: Optional[Dict] = None,
        top_k: int = 5
    ) -> List[RetrievalResult]:
        """
        Query the RAG knowledge base for tool information.

        Args:
            query: Natural language query
            target_info: Information about the target
            current_findings: Current scan findings
            agent_context: Agent-specific context
            top_k: Number of results to return

        Returns:
            List of retrieval results
        """
        logger.info(f"Querying tool knowledge: {query}")

        try:
            # Generate embedding for query
            query_embedding = await self.embeddings_service.embed_async(query)

            # Search tool knowledge collection
            query_request = RAGQueryRequest(
                query=query,
                collection=CollectionType.TOOL_KNOWLEDGE,
                top_k=top_k,
                min_similarity=self.confidence_threshold
            )

            results = await self.vector_store.query(
                query_request=query_request,
                query_embedding=query_embedding
            )

            logger.info(f"Found {len(results)} relevant tool knowledge entries")
            return results

        except Exception as e:
            logger.error(f"Failed to query tool knowledge: {e}")
            return []

    async def suggest_tools(
        self,
        scan_context: ScanContext,
        max_suggestions: int = 5
    ) -> List[ToolSuggestion]:
        """
        Suggest next tools based on scan context.

        This is the main intelligence function that combines multiple signals:
        1. Current target characteristics
        2. Tech stack detected
        3. Previous tools used
        4. Similar historical executions
        5. Known vulnerability patterns

        Args:
            scan_context: Current scan context
            max_suggestions: Maximum number of suggestions

        Returns:
            List of tool suggestions ranked by confidence
        """
        logger.info(f"Generating tool suggestions for {scan_context.target_url}")

        try:
            # Build comprehensive query from context
            context_query = self._build_context_query(scan_context)

            # Parallel retrieval from multiple collections
            results = await self._multi_collection_retrieval(
                context_query,
                scan_context,
                top_k=10
            )

            # Extract tool recommendations from results
            tool_scores = self._score_tools(results, scan_context)

            # Convert to tool suggestions
            suggestions = []
            for tool_name, score_data in sorted(
                tool_scores.items(),
                key=lambda x: x[1]['confidence'],
                reverse=True
            )[:max_suggestions]:
                suggestion = ToolSuggestion(
                    tool_name=tool_name,
                    confidence=score_data['confidence'],
                    reasoning=score_data['reasoning'],
                    similar_executions_count=score_data['similar_executions'],
                    expected_success_rate=score_data['success_rate'],
                    estimated_execution_time=score_data['estimated_time'],
                    parameters_suggestion=score_data.get('parameters'),
                    prerequisites=score_data.get('prerequisites', [])
                )
                suggestions.append(suggestion)

            logger.info(f"Generated {len(suggestions)} tool suggestions")
            return suggestions

        except Exception as e:
            logger.error(f"Failed to generate tool suggestions: {e}")
            return []

    async def get_similar_executions(
        self,
        tool_name: str,
        target_characteristics: Dict,
        limit: int = 10
    ) -> List[HistoricalExecution]:
        """
        Get similar historical tool executions.

        Args:
            tool_name: Name of the tool
            target_characteristics: Target characteristics to match
            limit: Maximum results

        Returns:
            List of historical executions
        """
        logger.info(f"Finding similar executions for {tool_name}")

        try:
            # Build query from target characteristics
            query_parts = [f"tool: {tool_name}"]
            if 'tech_stack' in target_characteristics:
                query_parts.append(f"technologies: {', '.join(target_characteristics['tech_stack'])}")
            if 'target_type' in target_characteristics:
                query_parts.append(f"type: {target_characteristics['target_type']}")

            query = " | ".join(query_parts)

            # Generate embedding
            query_embedding = await self.embeddings_service.embed_async(query)

            # Query execution history
            query_request = RAGQueryRequest(
                query=query,
                collection=CollectionType.EXECUTION_HISTORY,
                filters={"tool_name": tool_name},
                top_k=limit,
                min_similarity=0.5
            )

            results = await self.vector_store.query(
                query_request=query_request,
                query_embedding=query_embedding
            )

            # Convert to HistoricalExecution objects
            executions = []
            for result in results:
                exec_data = result.metadata
                execution = HistoricalExecution(
                    id=result.id,
                    tool_name=exec_data.get('tool_name', tool_name),
                    target_url=exec_data.get('target_url', ''),
                    target_characteristics=exec_data.get('target_characteristics', {}),
                    success=exec_data.get('success', False),
                    findings_count=exec_data.get('findings_count', 0),
                    severity_distribution=exec_data.get('severity_distribution', {}),
                    execution_time_seconds=exec_data.get('execution_time_seconds', 0.0),
                    timestamp=exec_data.get('timestamp', datetime.utcnow().isoformat()),
                    agent_name=exec_data.get('agent_name', ''),
                    scan_id=exec_data.get('scan_id', '')
                )
                executions.append(execution)

            logger.info(f"Found {len(executions)} similar executions")
            return executions

        except Exception as e:
            logger.error(f"Failed to get similar executions: {e}")
            return []

    async def augment_agent_prompt(
        self,
        base_prompt: str,
        retrieved_contexts: List[RetrievalResult]
    ) -> str:
        """
        Augment agent prompt with RAG-retrieved context.

        Args:
            base_prompt: Original system prompt
            retrieved_contexts: Retrieved context from RAG

        Returns:
            Enhanced prompt with RAG context
        """
        if not retrieved_contexts:
            return base_prompt

        # Build RAG context section
        rag_section = "\n\n## RAG-Retrieved Intelligence\n\n"
        rag_section += "The following information has been retrieved from the knowledge base based on your current scan context:\n\n"

        for i, context in enumerate(retrieved_contexts[:5], 1):
            rag_section += f"### Context {i} (Relevance: {context.similarity_score:.2f})\n"
            rag_section += f"**Source**: {context.collection}\n"
            rag_section += f"**Content**: {context.document[:500]}...\n"

            # Add relevant metadata
            if context.collection == "tool_knowledge":
                if 'recommended_tools' in context.metadata:
                    rag_section += f"**Recommended Tools**: {', '.join(context.metadata['recommended_tools'])}\n"
            elif context.collection == "execution_history":
                if 'success' in context.metadata:
                    rag_section += f"**Historical Success**: {context.metadata['success']}\n"
                if 'findings_count' in context.metadata:
                    rag_section += f"**Findings**: {context.metadata['findings_count']}\n"

            rag_section += "\n"

        # Append to base prompt
        enhanced_prompt = base_prompt + rag_section

        logger.debug(f"Augmented prompt with {len(retrieved_contexts)} contexts")
        return enhanced_prompt

    async def store_execution(self, execution_data: Dict[str, Any]) -> str:
        """
        Store tool execution result in RAG database for future learning.

        Args:
            execution_data: Execution result data

        Returns:
            Document ID
        """
        try:
            from .models import EmbeddingDocument
            import uuid

            # Create document text
            doc_text = self._create_execution_document(execution_data)

            # Generate embedding
            embedding = await self.embeddings_service.embed_async(doc_text)

            # Create document
            doc_id = f"exec_{uuid.uuid4().hex}"
            document = EmbeddingDocument(
                id=doc_id,
                document=doc_text,
                metadata=execution_data,
                collection=CollectionType.EXECUTION_HISTORY
            )

            # Store in vector database
            await self.vector_store.add_document(document, embedding=embedding)

            logger.info(f"Stored execution {doc_id} in RAG database")
            return doc_id

        except Exception as e:
            logger.error(f"Failed to store execution: {e}")
            raise

    def _build_context_query(self, scan_context: ScanContext) -> str:
        """Build comprehensive query from scan context"""
        return scan_context.to_query_text()

    async def _multi_collection_retrieval(
        self,
        query: str,
        scan_context: ScanContext,
        top_k: int = 10
    ) -> Dict[str, List[RetrievalResult]]:
        """
        Retrieve from multiple collections in parallel.

        Returns:
            Dictionary mapping collection name to results
        """
        # Generate embedding once
        query_embedding = await self.embeddings_service.embed_async(query)

        results = {}

        # Query tool knowledge
        tool_knowledge_request = RAGQueryRequest(
            query=query,
            collection=CollectionType.TOOL_KNOWLEDGE,
            top_k=top_k,
            min_similarity=0.5
        )
        results['tool_knowledge'] = await self.vector_store.query(
            tool_knowledge_request,
            query_embedding=query_embedding
        )

        # Query execution history
        exec_history_request = RAGQueryRequest(
            query=query,
            collection=CollectionType.EXECUTION_HISTORY,
            top_k=top_k,
            min_similarity=0.5
        )
        results['execution_history'] = await self.vector_store.query(
            exec_history_request,
            query_embedding=query_embedding
        )

        # Query vulnerability patterns if we have tech stack info
        if scan_context.tech_stack_detected:
            vuln_pattern_request = RAGQueryRequest(
                query=query,
                collection=CollectionType.VULNERABILITY_PATTERNS,
                top_k=5,
                min_similarity=0.6
            )
            results['vulnerability_patterns'] = await self.vector_store.query(
                vuln_pattern_request,
                query_embedding=query_embedding
            )

        return results

    def _score_tools(
        self,
        retrieval_results: Dict[str, List[RetrievalResult]],
        scan_context: ScanContext
    ) -> Dict[str, Dict]:
        """
        Score and rank tools based on retrieval results.

        Returns:
            Dictionary mapping tool name to score data
        """
        tool_scores = {}

        # Extract tool mentions from tool knowledge
        for result in retrieval_results.get('tool_knowledge', []):
            tool_name = result.metadata.get('tool_name')
            if not tool_name:
                continue

            if tool_name not in tool_scores:
                tool_scores[tool_name] = {
                    'confidence': 0.0,
                    'reasoning': [],
                    'similar_executions': 0,
                    'success_rate': 0.0,
                    'estimated_time': 0.0,
                    'prerequisites': result.metadata.get('prerequisites', []),
                    'parameters': {}
                }

            # Add confidence from similarity score
            tool_scores[tool_name]['confidence'] += result.similarity_score * 0.4
            tool_scores[tool_name]['reasoning'].append(
                f"Tool knowledge match (score: {result.similarity_score:.2f})"
            )

        # Extract tools from execution history
        for result in retrieval_results.get('execution_history', []):
            tool_name = result.metadata.get('tool_name')
            if not tool_name:
                continue

            if tool_name not in tool_scores:
                tool_scores[tool_name] = {
                    'confidence': 0.0,
                    'reasoning': [],
                    'similar_executions': 0,
                    'success_rate': 0.0,
                    'estimated_time': 0.0,
                    'prerequisites': [],
                    'parameters': {}
                }

            # Increment similar executions
            tool_scores[tool_name]['similar_executions'] += 1

            # Add confidence based on historical success
            if result.metadata.get('success'):
                tool_scores[tool_name]['confidence'] += result.similarity_score * 0.3
                tool_scores[tool_name]['success_rate'] += 1.0

            # Update estimated time
            exec_time = result.metadata.get('execution_time_seconds', 0.0)
            if exec_time > 0:
                current_time = tool_scores[tool_name]['estimated_time']
                count = tool_scores[tool_name]['similar_executions']
                tool_scores[tool_name]['estimated_time'] = (current_time * (count - 1) + exec_time) / count

            # Add reasoning
            findings_count = result.metadata.get('findings_count', 0)
            if findings_count > 0:
                tool_scores[tool_name]['reasoning'].append(
                    f"Found {findings_count} findings in similar target"
                )

        # Extract tools from vulnerability patterns
        for result in retrieval_results.get('vulnerability_patterns', []):
            recommended_tools = result.metadata.get('recommended_tools', [])
            for tool_name in recommended_tools:
                if tool_name not in tool_scores:
                    tool_scores[tool_name] = {
                        'confidence': 0.0,
                        'reasoning': [],
                        'similar_executions': 0,
                        'success_rate': 0.0,
                        'estimated_time': 0.0,
                        'prerequisites': [],
                        'parameters': {}
                    }

                # Add confidence from vulnerability pattern match
                tool_scores[tool_name]['confidence'] += result.similarity_score * 0.3
                vuln_type = result.metadata.get('vulnerability_type', 'vulnerability')
                tool_scores[tool_name]['reasoning'].append(
                    f"Recommended for {vuln_type} (pattern match: {result.similarity_score:.2f})"
                )

        # Penalize tools already used
        for tool_name in scan_context.previous_tools_used:
            if tool_name in tool_scores:
                tool_scores[tool_name]['confidence'] *= 0.7
                tool_scores[tool_name]['reasoning'].append("Already used in this scan")

        # Normalize success rate
        for tool_name, scores in tool_scores.items():
            if scores['similar_executions'] > 0:
                scores['success_rate'] /= scores['similar_executions']
            else:
                scores['success_rate'] = 0.5  # Default

            # Combine reasoning into single string
            scores['reasoning'] = " | ".join(scores['reasoning'][:3])

            # Cap confidence at 1.0
            scores['confidence'] = min(1.0, scores['confidence'])

        return tool_scores

    def _create_execution_document(self, execution_data: Dict[str, Any]) -> str:
        """
        Create document text from execution data for embedding.

        Args:
            execution_data: Execution result data

        Returns:
            Document text
        """
        parts = []

        tool_name = execution_data.get('tool_name', 'unknown')
        target_url = execution_data.get('target_url', '')
        success = execution_data.get('success', False)

        parts.append(f"Executed {tool_name} on {target_url}")

        if success:
            findings_count = execution_data.get('findings', [])
            if isinstance(findings_count, list):
                findings_count = len(findings_count)
            parts.append(f"Successfully found {findings_count} findings")

            # Add severity info
            severity_dist = execution_data.get('severity_distribution', {})
            if severity_dist:
                sev_str = ", ".join([f"{k}: {v}" for k, v in severity_dist.items() if v > 0])
                if sev_str:
                    parts.append(f"Severities: {sev_str}")
        else:
            parts.append("Execution failed or no findings")

        # Add tech stack
        if 'tech_stack' in execution_data:
            parts.append(f"Technologies: {', '.join(execution_data['tech_stack'])}")

        # Add parameters
        if 'parameters' in execution_data:
            param_str = json.dumps(execution_data['parameters'])
            if len(param_str) < 200:
                parts.append(f"Parameters: {param_str}")

        return " | ".join(parts)

    async def provide_feedback(
        self,
        suggestion_id: str,
        tool_suggested: str,
        tool_actually_used: str,
        was_helpful: bool,
        relevance_score: float
    ):
        """
        Store feedback on RAG suggestions for continuous improvement.

        Args:
            suggestion_id: ID of the suggestion
            tool_suggested: Tool that was suggested
            tool_actually_used: Tool that was actually used
            was_helpful: Whether the suggestion was helpful
            relevance_score: User/agent assessed relevance score
        """
        # This would be stored in PostgreSQL RAGFeedback table
        # For now, just log it
        logger.info(
            f"Feedback: suggestion_id={suggestion_id}, "
            f"suggested={tool_suggested}, used={tool_actually_used}, "
            f"helpful={was_helpful}, relevance={relevance_score}"
        )

        # TODO: Store in database for analytics and model improvement


# Singleton instance
_rag_service_instance = None


def get_rag_service(
    embeddings_service: Optional[EmbeddingsService] = None,
    vector_store: Optional[VectorStore] = None,
    confidence_threshold: float = 0.7
) -> RAGRetrievalService:
    """
    Get or create singleton RAG retrieval service.

    Args:
        embeddings_service: Embeddings service instance
        vector_store: Vector store instance
        confidence_threshold: Minimum confidence threshold

    Returns:
        RAGRetrievalService instance
    """
    global _rag_service_instance

    if _rag_service_instance is None:
        from .embeddings_service import get_embeddings_service
        from .vector_store import get_vector_store

        if embeddings_service is None:
            embeddings_service = get_embeddings_service()
        if vector_store is None:
            vector_store = get_vector_store()

        _rag_service_instance = RAGRetrievalService(
            embeddings_service=embeddings_service,
            vector_store=vector_store,
            confidence_threshold=confidence_threshold
        )

    return _rag_service_instance
