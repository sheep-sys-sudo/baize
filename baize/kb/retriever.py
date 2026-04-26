"""Knowledge base retriever for RAG queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


from baize.kb.vector_store import VectorStore


@dataclass
class RetrievalResult:
    """Result from knowledge base retrieval."""

    content: str
    metadata: dict
    score: float
    vuln_type: Optional[str] = None
    cwe: Optional[str] = None


class KnowledgeRetriever:
    """Retrieves relevant knowledge from the vector store for RAG.

    This class provides methods to retrieve vulnerability information,
    query templates, and fix suggestions based on natural language queries.
    """

    def __init__(self, vector_store: VectorStore):
        """Initialize the retriever.

        Args:
            vector_store: Vector store to query
        """
        self._vector_store = vector_store

    def retrieve_vulnerability_info(
        self,
        query: str,
        vuln_type: Optional[str] = None,
        top_k: int = 5,
    ) -> list[RetrievalResult]:
        """Retrieve vulnerability information matching the query.

        Args:
            query: Natural language query
            vuln_type: Optional vulnerability type filter
            top_k: Number of results to return

        Returns:
            List of retrieval results
        """
        filter_meta = {"category": "vulnerability"}
        if vuln_type:
            filter_meta["vuln_type"] = vuln_type

        entries = self._vector_store.query(
            query_text=query,
            n_results=top_k,
            filter_metadata=filter_meta,
        )

        return [
            RetrievalResult(
                content=entry.content,
                metadata=entry.metadata,
                score=entry.score,
                vuln_type=entry.metadata.get("vuln_type"),
                cwe=entry.metadata.get("cwe"),
            )
            for entry in entries
        ]

    def retrieve_fix_suggestion(
        self,
        vuln_type: str,
        language: str,
    ) -> Optional[str]:
        """Retrieve fix suggestion for a vulnerability type.

        Args:
            vuln_type: Vulnerability type (sqli, xss, etc.)
            language: Programming language

        Returns:
            Fix suggestion content or None
        """
        filter_meta = {
            "category": "vulnerability",
            "vuln_type": vuln_type,
        }

        entries = self._vector_store.get_by_metadata(
            metadata_filter=filter_meta,
            limit=1,
        )

        if entries:
            return entries[0].content

        return None

    def retrieve_query_template(
        self,
        vuln_type: str,
        language: str,
    ) -> Optional[str]:
        """Retrieve query template for a vulnerability type.

        Args:
            vuln_type: Vulnerability type
            language: Programming language

        Returns:
            Query template content or None
        """
        filter_meta = {
            "category": "query_template",
            "vuln_type": vuln_type,
            "language": language,
        }

        entries = self._vector_store.get_by_metadata(
            metadata_filter=filter_meta,
            limit=1,
        )

        if entries:
            return entries[0].content

        return None

    def enrich_context(
        self,
        query: str,
        max_context_length: int = 4000,
    ) -> str:
        """Enrich a query with relevant knowledge base context.

        Args:
            query: Original query
            max_context_length: Maximum context length in characters

        Returns:
            Enriched context string
        """
        results = self.retrieve_vulnerability_info(query, top_k=3)

        if not results:
            return ""

        context_parts = []
        current_length = 0

        for result in results:
            if current_length + len(result.content) > max_context_length:
                break
            context_parts.append(result.content)
            current_length += len(result.content)

        return "\n\n".join(context_parts)


def create_retriever(vector_store: VectorStore) -> KnowledgeRetriever:
    """Create a knowledge retriever instance.

    Args:
        vector_store: Vector store to use

    Returns:
        KnowledgeRetriever instance
    """
    return KnowledgeRetriever(vector_store)