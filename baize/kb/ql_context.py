"""QL context provider — injects real CodeQL examples into the generation prompt.

Two complementary retrieval strategies (both optional, can be combined):

1. **Local file scan** (``QLFileContextProvider``)
   Walk a local directory tree (e.g. a cloned *learning-codeql* repo) and
   return the most relevant `.ql` files based on keyword / language matching.
   No external dependencies — works offline immediately after cloning.

2. **Vector store retrieval** (``QLVectorContextProvider``)
   Use the existing ChromaDB knowledge base (``baize.kb``) to retrieve
   semantically similar QL snippets that were previously indexed.

Both implement the ``QLContextProvider`` protocol and can be composed via
``CompositeQLContextProvider``.

Indexing workflow (one-time setup):

    from baize.kb.ql_context import QLIndexer
    indexer = QLIndexer(vector_store)
    count = indexer.index_directory("/path/to/learning-codeql")
    print(f"Indexed {count} .ql files")

Runtime workflow (inside CustomFlowAnalyzer):

    provider = build_context_provider(
        ql_examples_dir=Path("/path/to/learning-codeql"),
        vector_store=store,          # optional
    )
    snippets = provider.retrieve(
        query="SQL injection taint flow from HTTP parameters to executeQuery",
        language="java",
        top_k=3,
    )
    # snippets → injected as few-shot examples into the LLM system prompt
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from loguru import logger


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class QLSnippet:
    """A single CodeQL example retrieved for prompt injection.

    Attributes:
        source_path:  Origin file path (relative or absolute).
        language:     Target language the query is written for.
        content:      Full .ql file content.
        description:  Human-readable summary (from @name / @description tags).
        vuln_keywords: Keywords extracted from metadata comments.
        score:        Relevance score (higher = more relevant).
    """

    source_path: str
    language: str
    content: str
    description: str = ""
    vuln_keywords: list[str] = field(default_factory=list)
    score: float = 0.0

    def format_for_prompt(self, max_chars: int = 3000) -> str:
        """Format the snippet as a labelled few-shot block for prompt injection."""
        header = f"// === Example: {self.description or self.source_path} ==="
        body = self.content[:max_chars]
        if len(self.content) > max_chars:
            body += "\n// … (truncated)"
        return f"{header}\n{body}"


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class QLContextProvider(Protocol):
    """Protocol for QL example retrieval backends."""

    def retrieve(
        self,
        query: str,
        language: str,
        top_k: int = 3,
    ) -> list[QLSnippet]:
        """Retrieve the *top_k* most relevant QL snippets for the query."""
        ...


# ---------------------------------------------------------------------------
# Helper — QL metadata parser
# ---------------------------------------------------------------------------

def _parse_ql_metadata(content: str) -> dict[str, str]:
    """Extract @name, @description, @kind, @id from QL comment header."""
    import re
    meta: dict[str, str] = {}
    for tag in ("name", "description", "kind", "id", "tags"):
        m = re.search(rf"@{tag}\s+(.+)", content)
        if m:
            meta[tag] = m.group(1).strip()
    return meta


def _score_ql_file(content: str, query: str, language: str) -> float:
    """Simple keyword overlap score for local-file ranking (no embeddings needed)."""
    query_tokens = set(query.lower().split())
    content_lower = content.lower()

    # Bonus if language appears in path/imports
    lang_bonus = 0.3 if language.lower() in content_lower else 0.0

    # Keyword hits in content (weighted by position: header hits score more)
    header = content_lower[:500]
    body = content_lower

    hit_score = 0.0
    for token in query_tokens:
        if len(token) < 3:
            continue
        if token in header:
            hit_score += 0.2
        elif token in body:
            hit_score += 0.05

    return min(hit_score + lang_bonus, 1.0)


# ---------------------------------------------------------------------------
# 1. Local file-scan provider
# ---------------------------------------------------------------------------

# Language aliases used in directory names inside common QL repos
_LANG_DIR_ALIASES: dict[str, list[str]] = {
    "java":       ["java", "java-",  "Java"],
    "python":     ["python", "py",   "Python"],
    "javascript": ["javascript", "js", "JavaScript", "ts", "typescript"],
    "go":         ["go", "Go", "golang"],
    "cpp":        ["cpp", "c", "C", "csharp", "c-cpp"],
    "csharp":     ["csharp", "cs", "C#"],
}


class QLFileContextProvider:
    """Retrieves QL examples by scanning a local directory tree.

    Designed to work with clones of repos such as:
    - https://github.com/SummerSec/learning-codeql
    - https://github.com/github/codeql  (the official repo)
    - any local folder of .ql files

    No external dependencies — pure filesystem scan + keyword scoring.
    """

    def __init__(
        self,
        root_dir: Path,
        max_file_size_kb: int = 64,
        min_score: float = 0.05,
    ):
        """Initialise the provider.

        Args:
            root_dir:         Root directory to scan for .ql files.
            max_file_size_kb: Skip files larger than this (avoids huge generated files).
            min_score:        Minimum relevance score to include a result.
        """
        self._root = Path(root_dir)
        self._max_bytes = max_file_size_kb * 1024
        self._min_score = min_score
        self._index: list[QLSnippet] = []
        self._indexed = False

        if not self._root.exists():
            logger.warning(f"QL examples directory does not exist: {root_dir}")

    # ── lazy index ────────────────────────────────────────────────────────────

    def _ensure_indexed(self) -> None:
        if self._indexed:
            return
        self._index = self._build_index()
        self._indexed = True
        logger.info(
            f"Indexed {len(self._index)} .ql files from {self._root}"
        )

    def _build_index(self) -> list[QLSnippet]:
        snippets: list[QLSnippet] = []
        for ql_path in self._root.rglob("*.ql"):
            if ql_path.stat().st_size > self._max_bytes:
                continue
            try:
                content = ql_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            meta = _parse_ql_metadata(content)
            lang = self._infer_language(ql_path)
            snippets.append(QLSnippet(
                source_path=str(ql_path.relative_to(self._root)),
                language=lang,
                content=content,
                description=meta.get("name") or meta.get("description") or "",
                vuln_keywords=meta.get("tags", "").split(),
            ))
        return snippets

    def _infer_language(self, ql_path: Path) -> str:
        """Infer language from directory structure."""
        parts_lower = [p.lower() for p in ql_path.parts]
        for lang, aliases in _LANG_DIR_ALIASES.items():
            for alias in aliases:
                if any(alias.lower() in part for part in parts_lower):
                    return lang
        return "java"  # safe default for most QL repos

    # ── public API ────────────────────────────────────────────────────────────

    def retrieve(
        self,
        query: str,
        language: str,
        top_k: int = 3,
    ) -> list[QLSnippet]:
        """Return *top_k* QL snippets most relevant to *query* and *language*."""
        self._ensure_indexed()

        scored: list[QLSnippet] = []
        for snippet in self._index:
            # Prefer same-language files; allow cross-language with lower score
            lang_match = snippet.language == language
            score = _score_ql_file(snippet.content, query, language)
            if not lang_match:
                score *= 0.4          # penalise wrong-language files
            if score >= self._min_score:
                snippet.score = score
                scored.append(snippet)

        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:top_k]

    def count(self) -> int:
        self._ensure_indexed()
        return len(self._index)


# ---------------------------------------------------------------------------
# 2. Vector store provider
# ---------------------------------------------------------------------------

class QLVectorContextProvider:
    """Retrieves QL examples from the ChromaDB knowledge base.

    Requires prior indexing via ``QLIndexer.index_directory()``.
    Degrades gracefully when ChromaDB is unavailable.
    """

    _CATEGORY = "ql_example"

    def __init__(self, vector_store):
        """Args:
            vector_store: ``baize.kb.VectorStore`` instance.
        """
        self._store = vector_store

    def retrieve(
        self,
        query: str,
        language: str,
        top_k: int = 3,
    ) -> list[QLSnippet]:
        if not self._store.is_initialized:
            logger.debug("VectorStore not initialised — skipping vector retrieval")
            return []

        try:
            entries = self._store.query(
                query_text=f"{language} {query}",
                n_results=top_k,
                filter_metadata={"category": self._CATEGORY, "language": language},
            )
        except Exception as exc:
            # ChromaDB may error if the collection has no ql_example entries yet
            logger.debug(f"Vector QL retrieval failed (non-fatal): {exc}")
            return []

        snippets = []
        for entry in entries:
            snippets.append(QLSnippet(
                source_path=entry.metadata.get("source_path", ""),
                language=entry.metadata.get("language", language),
                content=entry.content,
                description=entry.metadata.get("description", ""),
                vuln_keywords=entry.metadata.get("tags", "").split(),
                score=entry.score,
            ))
        return snippets


# ---------------------------------------------------------------------------
# 3. Composite provider
# ---------------------------------------------------------------------------

class CompositeQLContextProvider:
    """Combines multiple providers and deduplicates by content hash.

    Providers are queried in order; results are merged and re-ranked by score.
    """

    def __init__(self, providers: list[QLContextProvider]):
        self._providers = providers

    def retrieve(
        self,
        query: str,
        language: str,
        top_k: int = 3,
    ) -> list[QLSnippet]:
        seen: set[str] = set()
        all_snippets: list[QLSnippet] = []

        for provider in self._providers:
            for snippet in provider.retrieve(query, language, top_k=top_k):
                content_hash = hashlib.md5(
                    snippet.content[:500].encode(), usedforsecurity=False
                ).hexdigest()
                if content_hash not in seen:
                    seen.add(content_hash)
                    all_snippets.append(snippet)

        all_snippets.sort(key=lambda s: s.score, reverse=True)
        return all_snippets[:top_k]


# ---------------------------------------------------------------------------
# 4. Indexer (one-time ingestion into ChromaDB)
# ---------------------------------------------------------------------------

class QLIndexer:
    """Indexes local .ql files into the ChromaDB vector store.

    Run once after cloning a QL learning repository:

        indexer = QLIndexer(vector_store)
        n = indexer.index_directory("/path/to/learning-codeql")
        print(f"Indexed {n} files")
    """

    _CATEGORY = "ql_example"

    def __init__(self, vector_store):
        self._store = vector_store

    def index_directory(
        self,
        root_dir: Path | str,
        max_file_size_kb: int = 64,
    ) -> int:
        """Scan *root_dir* for .ql files and upsert them into the vector store.

        Returns the number of files successfully indexed.
        """
        from baize.kb.vector_store import KnowledgeDocument

        root_dir = Path(root_dir)
        if not root_dir.exists():
            logger.error(f"Directory not found: {root_dir}")
            return 0

        docs: list[KnowledgeDocument] = []
        provider = QLFileContextProvider(root_dir, max_file_size_kb=max_file_size_kb)
        provider._ensure_indexed()

        for snippet in provider._index:
            doc_id = "ql_" + hashlib.md5(
                snippet.source_path.encode(), usedforsecurity=False
            ).hexdigest()
            docs.append(KnowledgeDocument(
                id=doc_id,
                content=snippet.content,
                metadata={
                    "category": self._CATEGORY,
                    "language": snippet.language,
                    "source_path": snippet.source_path,
                    "description": snippet.description,
                    "tags": " ".join(snippet.vuln_keywords),
                },
            ))

        if not docs:
            logger.warning("No .ql files found to index")
            return 0

        # Batch upsert (ChromaDB handles dedup by id)
        BATCH = 100
        indexed = 0
        for i in range(0, len(docs), BATCH):
            batch = docs[i: i + BATCH]
            if self._store.add_documents(batch):
                indexed += len(batch)

        logger.info(f"Indexed {indexed}/{len(docs)} QL files from {root_dir}")
        return indexed


# ---------------------------------------------------------------------------
# 5. Factory helper
# ---------------------------------------------------------------------------

def build_context_provider(
    ql_examples_dir: Optional[Path] = None,
    vector_store=None,
) -> Optional[CompositeQLContextProvider]:
    """Build a provider from whichever backends are available.

    Args:
        ql_examples_dir: Local directory with .ql files (e.g. a cloned repo).
        vector_store:    baize.kb.VectorStore instance (optional).

    Returns:
        CompositeQLContextProvider if at least one backend is available, else None.
    """
    providers: list[QLContextProvider] = []

    if ql_examples_dir is not None:
        dir_path = Path(ql_examples_dir)
        if dir_path.exists():
            providers.append(QLFileContextProvider(dir_path))
            logger.debug(f"QL file provider registered: {dir_path}")
        else:
            logger.warning(f"--ql-examples-dir does not exist: {dir_path}")

    if vector_store is not None and getattr(vector_store, "is_initialized", False):
        providers.append(QLVectorContextProvider(vector_store))
        logger.debug("QL vector provider registered")

    if not providers:
        return None

    return CompositeQLContextProvider(providers)


def format_snippets_for_prompt(snippets: list[QLSnippet], max_total_chars: int = 8000) -> str:
    """Render retrieved snippets as a prompt section.

    Returns a string ready to be appended to the system or user prompt.
    """
    if not snippets:
        return ""

    parts = ["=== Real CodeQL Examples (use as structural reference) ===\n"]
    remaining = max_total_chars
    for snippet in snippets:
        block = snippet.format_for_prompt(max_chars=min(3000, remaining))
        if len(block) > remaining:
            break
        parts.append(block)
        remaining -= len(block)
        if remaining <= 0:
            break

    return "\n\n".join(parts)
