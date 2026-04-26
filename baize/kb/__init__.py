"""Knowledge base module for RAG (Retrieval Augmented Generation).

This module provides:
- Vector store using ChromaDB for storing vulnerability knowledge
- Retriever for querying the knowledge base
- Default vulnerability entries for initialization

Usage:
    from baize.kb import VectorStore, KnowledgeRetriever, initialize_knowledge_base

    # Initialize vector store
    store = VectorStore(persist_directory="./.baize/kb")
    initialize_knowledge_base(store)

    # Create retriever and query
    retriever = create_retriever(store)
    results = retriever.retrieve_vulnerability_info("SQL injection in Java")
"""

from baize.kb.vector_store import (
    VectorStore,
    KnowledgeDocument,
    KnowledgeEntry,
    initialize_knowledge_base,
    create_default_knowledge_entries,
)
from baize.kb.retriever import (
    KnowledgeRetriever,
    RetrievalResult,
    create_retriever,
)

__all__ = [
    "VectorStore",
    "KnowledgeDocument",
    "KnowledgeEntry",
    "KnowledgeRetriever",
    "RetrievalResult",
    "initialize_knowledge_base",
    "create_default_knowledge_entries",
    "create_retriever",
]