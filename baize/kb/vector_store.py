"""Knowledge base vector store using ChromaDB.

This module provides a RAG (Retrieval Augmented Generation) knowledge base
for storing and retrieving vulnerability knowledge, query templates, and
CodeQL documentation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("ChromaDB not available. Install with: pip install chromadb")


@dataclass
class KnowledgeDocument:
    """A document in the knowledge base."""

    id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: Optional[list[float]] = None


@dataclass
class KnowledgeEntry:
    """A knowledge entry for RAG retrieval."""

    content: str
    metadata: dict[str, Any]
    score: float = 0.0


class VectorStore:
    """Vector store for knowledge base using ChromaDB.

    The knowledge base stores:
    - CVE vulnerability descriptions
    - Query templates and examples
    - Fix suggestions and patterns
    - CodeQL documentation
    """

    def __init__(
        self,
        persist_directory: Path | str = "./.baize/kb",
        collection_name: str = "baize_knowledge",
    ):
        self._persist_directory = Path(persist_directory)
        self._collection_name = collection_name
        self._client = None
        self._collection = None
        self._initialized = False

        if CHROMADB_AVAILABLE:
            self._init_client()
        else:
            logger.warning("ChromaDB not available, using in-memory fallback")

    def _init_client(self) -> None:
        """Initialize the ChromaDB client."""
        if not CHROMADB_AVAILABLE:
            return

        try:
            self._persist_directory.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(self._persist_directory),
                settings=Settings(anonymized_telemetry=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"description": "Baize knowledge base"},
            )
            self._initialized = True
            logger.info(f"Initialized ChromaDB at {self._persist_directory}")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            self._initialized = False

    def add_document(self, doc: KnowledgeDocument) -> bool:
        """Add or update a document in the knowledge base (upsert)."""
        if not self._initialized:
            logger.warning("Vector store not initialized")
            return False

        try:
            self._collection.upsert(
                ids=[doc.id],
                documents=[doc.content],
                metadatas=[doc.metadata],
            )
            logger.debug(f"Upserted document: {doc.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to upsert document: {e}")
            return False

    def add_documents(self, docs: list[KnowledgeDocument]) -> bool:
        """Add or update multiple documents in the knowledge base (upsert).

        Using upsert ensures that re-initialisation does not fail with
        duplicate-ID errors.
        """
        if not self._initialized:
            return False

        try:
            self._collection.upsert(
                ids=[doc.id for doc in docs],
                documents=[doc.content for doc in docs],
                metadatas=[doc.metadata for doc in docs],
            )
            logger.info(f"Upserted {len(docs)} documents")
            return True
        except Exception as e:
            logger.error(f"Failed to upsert documents: {e}")
            return False

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        filter_metadata: Optional[dict] = None,
    ) -> list[KnowledgeEntry]:
        """Query the knowledge base."""
        if not self._initialized:
            logger.warning("Vector store not initialized")
            return []

        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=min(n_results, 10),  # cap per design doc
                where=filter_metadata,
            )

            entries = []
            if results and results.get("documents"):
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results["metadatas"][0][i] if results.get("metadatas") else {}
                    distance = results["distances"][0][i] if results.get("distances") else 0.0
                    score = 1.0 / (1.0 + distance)

                    entries.append(KnowledgeEntry(
                        content=doc,
                        metadata=metadata,
                        score=score,
                    ))

            return entries

        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def get_by_metadata(
        self,
        metadata_filter: dict,
        limit: int = 100,
    ) -> list[KnowledgeDocument]:
        """Get documents by metadata filter."""
        if not self._initialized:
            return []

        try:
            results = self._collection.get(
                where=metadata_filter,
                limit=limit,
            )

            docs = []
            if results and results.get("ids"):
                for i, doc_id in enumerate(results["ids"]):
                    docs.append(KnowledgeDocument(
                        id=doc_id,
                        content=results["documents"][i],
                        metadata=results.get("metadatas", [{}])[i],
                    ))

            return docs

        except Exception as e:
            logger.error(f"Get by metadata failed: {e}")
            return []

    def delete(self, doc_id: str) -> bool:
        """Delete a document by ID."""
        if not self._initialized:
            return False

        try:
            self._collection.delete(ids=[doc_id])
            logger.debug(f"Deleted document: {doc_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete document: {e}")
            return False

    def count(self) -> int:
        """Get the number of documents in the knowledge base."""
        if not self._initialized:
            return 0

        try:
            return self._collection.count()
        except Exception:
            return 0

    @property
    def is_initialized(self) -> bool:
        return self._initialized


def create_default_knowledge_entries() -> list[KnowledgeDocument]:
    """Create default knowledge base entries for common vulnerabilities."""
    entries = []

    vuln_data = [
        {
            "id": "cwe-89",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "title": "SQL Injection",
            "description": (
                "SQL injection vulnerabilities occur when user input is incorrectly "
                "filtered or not strongly typed. Attackers can execute arbitrary "
                "SQL commands to access, modify, or delete database data."
            ),
            "fix": (
                "Use parameterized queries (PreparedStatement in Java, "
                "psycopg2 in Python) instead of string concatenation. "
                "Never construct SQL queries with user input directly."
            ),
            "languages": ["java", "python", "javascript", "go"],
        },
        {
            "id": "cwe-79",
            "vuln_type": "xss",
            "cwe": "CWE-79",
            "title": "Cross-Site Scripting (XSS)",
            "description": (
                "XSS vulnerabilities allow attackers to inject malicious scripts "
                "into web pages viewed by other users. Types include reflected, "
                "stored, and DOM-based XSS."
            ),
            "fix": (
                "Encode output using context-appropriate encoding functions. "
                "Use Content Security Policy (CSP). Validate and sanitize input."
            ),
            "languages": ["java", "python", "javascript"],
        },
        {
            "id": "cwe-94",
            "vuln_type": "rce",
            "cwe": "CWE-94",
            "title": "Remote Code Execution",
            "description": (
                "RCE vulnerabilities allow attackers to execute arbitrary code "
                "on the target system. Common causes include unsafe deserialization, "
                "command injection, and code evaluation."
            ),
            "fix": (
                "Never use eval() or similar functions with user input. "
                "Use safe APIs for code execution. Validate and sanitize all input."
            ),
            "languages": ["java", "python", "javascript", "go"],
        },
        {
            "id": "cwe-918",
            "vuln_type": "ssrf",
            "cwe": "CWE-918",
            "title": "Server-Side Request Forgery",
            "description": (
                "SSRF vulnerabilities allow attackers to make requests to internal "
                "or external resources from the server. Can lead to data access, "
                "port scanning, or remote code execution."
            ),
            "fix": (
                "Validate and whitelist URLs that the server can access. "
                "Use allowlists for IP addresses and domains. "
                "Disable unused URL schemas."
            ),
            "languages": ["java", "python", "javascript", "go"],
        },
        {
            "id": "cwe-22",
            "vuln_type": "path-traversal",
            "cwe": "CWE-22",
            "title": "Path Traversal",
            "description": (
                "Path traversal vulnerabilities allow attackers to access files "
                "outside the intended directory by using ../ sequences in user input."
            ),
            "fix": (
                "Use realpath() or Path.resolve() to canonicalize paths. "
                "Validate that resolved paths are within allowed directories. "
                "Use chroot or sandboxing for file operations."
            ),
            "languages": ["java", "python", "javascript", "go"],
        },
        {
            "id": "cwe-502",
            "vuln_type": "deserialization",
            "cwe": "CWE-502",
            "title": "Deserialization of Untrusted Data",
            "description": (
                "Insecure deserialization can lead to remote code execution when "
                "attacker-controlled data is deserialized without validation."
            ),
            "fix": (
                "Never deserialize untrusted data. Use digital signatures to "
                "validate serialized data. Consider using JSON instead of "
                "binary serialization formats."
            ),
            "languages": ["java", "python", "javascript"],
        },
    ]

    for vuln in vuln_data:
        content = (
            f"{vuln['title']} ({vuln['cwe']})\n\n"
            f"Description:\n{vuln['description']}\n\n"
            f"Fix:\n{vuln['fix']}\n\n"
            f"Severity: High to Critical\n"
            f"CWE: {vuln['cwe']}"
        )

        entries.append(KnowledgeDocument(
            id=vuln["id"],
            content=content,
            metadata={
                "vuln_type": vuln["vuln_type"],
                "cwe": vuln["cwe"],
                "title": vuln["title"],
                "languages": vuln["languages"],
                "category": "vulnerability",
            },
        ))

    return entries


def initialize_knowledge_base(vector_store: VectorStore) -> None:
    """Initialize the knowledge base with default entries (idempotent)."""
    entries = create_default_knowledge_entries()
    vector_store.add_documents(entries)
    logger.info(f"Initialized knowledge base with {len(entries)} entries")
