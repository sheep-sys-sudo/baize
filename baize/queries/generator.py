"""Query template manager - loads and manages QL templates."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from loguru import logger


VULNERABILITY_TYPES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "rce": "Remote Code Execution",
    "ssrf": "Server-Side Request Forgery",
    "deserialization": "Unsafe Deserialization",
    "path-traversal": "Path Traversal",
    "command-injection": "Command Injection",
    "xxe": "XML External Entity",
    "open-redirect": "Open Redirect",
}

LANGUAGE_MAP = {
    "java": "java",
    "python": "python",
    "javascript": "javascript",
    "js": "javascript",
    "go": "go",
    "cpp": "cpp",
    "csharp": "csharp",
    "cs": "csharp",
}

# Default: sibling "codeql-queries" directory (clone of github/codeql).
# Can be overridden via ``baize.yaml`` → ``codeql.queries_path``.
_DEFAULT_QUERIES_BASE = Path(__file__).resolve().parent.parent.parent.parent / "codeql-queries"

# ── CodeQL pack references (fallback when no local queries path is available) ──
_CODEQL_PACK_SUITES: dict[str, str] = {
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
    "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
    "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
}

# ── Relative paths within the codeql-queries tree ────────────────────
# Suite paths (relative to queries_base)
_SUITE_REL: dict[str, str] = {
    "java": "java/ql/src/codeql-suites/java-security-extended.qls",
    "python": "python/ql/src/codeql-suites/python-security-extended.qls",
    "javascript": "javascript/ql/src/codeql-suites/javascript-security-extended.qls",
    "go": "go/ql/src/codeql-suites/go-security-extended.qls",
    "cpp": "cpp/ql/src/codeql-suites/cpp-security-extended.qls",
    "csharp": "csharp/ql/src/codeql-suites/csharp-security-extended.qls",
}

# Individual query paths (relative to queries_base), keyed by (language, vuln_type)
_QUERY_REL: dict[tuple[str, str], str] = {
    # Java
    ("java", "sqli"):             "java/ql/src/Security/CWE/CWE-089/SqlTainted.ql",
    ("java", "xss"):              "java/ql/src/Security/CWE/CWE-079/XSS.ql",
    ("java", "rce"):              "java/ql/src/Security/CWE/CWE-078/ExecTainted.ql",
    ("java", "path-traversal"):   "java/ql/src/Security/CWE/CWE-022/TaintedPath.ql",
    ("java", "ssrf"):             "java/ql/src/Security/CWE/CWE-918/RequestForgery.ql",
    ("java", "deserialization"):   "java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql",
    ("java", "xxe"):              "java/ql/src/Security/CWE/CWE-611/XXE.ql",
    ("java", "open-redirect"):    "java/ql/src/Security/CWE/CWE-601/UrlRedirect.ql",
    # Python
    ("python", "sqli"):           "python/ql/src/Security/CWE/CWE-089/SqlInjection.ql",
    ("python", "xss"):            "python/ql/src/Security/CWE/CWE-079/ReflectedXss.ql",
    ("python", "rce"):            "python/ql/src/Security/CWE/CWE-078/CommandInjection.ql",
    ("python", "path-traversal"): "python/ql/src/Security/CWE/CWE-022/PathTraversal.ql",
    ("python", "ssrf"):           "python/ql/src/Security/CWE/CWE-918/ServerSideRequestForgery.ql",
    ("python", "deserialization"): "python/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql",
    # JavaScript
    ("javascript", "sqli"):       "javascript/ql/src/Security/CWE/CWE-089/SqlInjection.ql",
    ("javascript", "xss"):        "javascript/ql/src/Security/CWE/CWE-079/ReflectedXss.ql",
    ("javascript", "rce"):        "javascript/ql/src/Security/CWE/CWE-078/CommandInjection.ql",
    ("javascript", "path-traversal"): "javascript/ql/src/Security/CWE/CWE-022/PathTraversal.ql",
    ("javascript", "ssrf"):       "javascript/ql/src/Security/CWE/CWE-918/ServerSideRequestForgery.ql",
    ("javascript", "open-redirect"): "javascript/ql/src/Security/CWE/CWE-601/ServerSideUrlRedirect.ql",
    # Go
    ("go", "sqli"):              "go/ql/src/Security/CWE/CWE-089/SqlInjection.ql",
    ("go", "xss"):               "go/ql/src/Security/CWE/CWE-079/ReflectedXss.ql",
    ("go", "rce"):               "go/ql/src/Security/CWE/CWE-078/CommandInjection.ql",
    ("go", "path-traversal"):    "go/ql/src/Security/CWE/CWE-022/PathTraversal.ql",
    ("go", "ssrf"):              "go/ql/src/Security/CWE/CWE-918/RequestForgery.ql",
    ("go", "open-redirect"):     "go/ql/src/Security/CWE/CWE-601/OpenUrlRedirect.ql",
}


def _resolve_queries_base(explicit: str | None, project_path: Path | None = None) -> Path | None:
    """Resolve the queries base path from config or auto-detection.

    Priority:
    1. Explicit path from ``baize.yaml`` → ``codeql.queries_path``
    2. Sibling ``codeql-queries/`` (configurable, if project_path given)
    3. Default sibling ``codeql-queries/`` relative to *this file's* project root
    4. None (use CodeQL pack references)

    Returns:
        Absolute Path if found, None if CodeQL pack references should be used.
    """
    # 1. Explicit config path
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p.resolve()
        logger.warning(f"Configured queries_path does not exist: {explicit}")

    # 2. Sibling relative to project_path (e.g. <repo_dir>/../codeql-queries)
    if project_path:
        sibling = (Path(project_path).resolve().parent / "codeql-queries")
        if sibling.exists():
            return sibling

    # 3. Default sibling relative to this project root
    if _DEFAULT_QUERIES_BASE.exists():
        return _DEFAULT_QUERIES_BASE

    return None


class QueryTemplateManager:
    """Manages QL query templates for different languages and vulnerability types.

    Resolution priority:
    1. Custom local template in templates_dir/{language}/{vuln-type}.ql
    2. Official CodeQL query path from the local ``codeql-queries`` clone
    3. CodeQL pack reference (e.g. ``codeql/java-queries:codeql-suites/...``)
    4. Full official query suite as fallback
    """

    def __init__(
        self,
        queries_base: Optional[Path] = None,
        templates_dir: Optional[Path] = None,
    ):
        # ``queries_base`` is the root of a github/codeql clone (or None for pack refs)
        self._queries_base = queries_base
        # ``templates_dir`` for local custom .ql overrides (defaults to queries_base)
        self._templates_dir = Path(templates_dir) if templates_dir else (
            self._queries_base if self._queries_base else _DEFAULT_QUERIES_BASE
        )
        self._cache: dict[str, str] = {}

    @property
    def using_pack_refs(self) -> bool:
        """True if the manager is using CodeQL pack references (no local clone)."""
        return self._queries_base is None

    def get_template_path(self, language: str, vuln_type: str) -> Path:
        """Get the path to a specific local template file."""
        lang = LANGUAGE_MAP.get(language.lower(), language.lower())
        return self._templates_dir / lang / f"{vuln_type}.ql"

    def load_template(self, language: str, vuln_type: str) -> Optional[str]:
        """Load a local custom query template override if it exists."""
        cache_key = f"{language}:{vuln_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        template_path = self.get_template_path(language, vuln_type)
        if not template_path.exists():
            return None

        try:
            content = template_path.read_text(encoding="utf-8")
            self._cache[cache_key] = content
            logger.debug(f"Loaded local template: {template_path}")
            return content
        except Exception as e:
            logger.error(f"Error loading template {template_path}: {e}")
            return None

    def get_query_spec(self, language: str, vuln_type: str) -> Optional[str]:
        """Get query spec: local override > local .ql file > pack reference."""
        lang = LANGUAGE_MAP.get(language.lower(), language.lower())

        # 1. Local custom template override
        template_path = self.get_template_path(lang, vuln_type)
        if template_path.exists():
            logger.debug(f"Using local template: {template_path}")
            return str(template_path)

        # 2. Local codeql-queries clone
        if self._queries_base is not None:
            key = (lang, vuln_type)
            rel = _QUERY_REL.get(key)
            if rel:
                ql_path = self._queries_base / rel
                if ql_path.exists():
                    return str(ql_path)

        # 3. CodeQL pack reference
        suite = _CODEQL_PACK_SUITES.get(lang)
        if suite:
            logger.debug(f"Using CodeQL pack for ({lang}, {vuln_type}): {suite}")
            return suite

        logger.warning(f"No specific query found for ({lang}, {vuln_type})")
        return None

    def get_suite(self, language: str) -> Optional[str]:
        """Get the full security suite for a language.

        Returns a file path (if local clone exists) or a CodeQL pack reference.
        """
        lang = LANGUAGE_MAP.get(language.lower(), language.lower())

        # 1. Local codeql-queries clone
        if self._queries_base is not None:
            rel = _SUITE_REL.get(lang)
            if rel:
                suite_path = self._queries_base / rel
                if suite_path.exists():
                    return str(suite_path)

        # 2. CodeQL pack reference
        pack_ref = _CODEQL_PACK_SUITES.get(lang)
        if pack_ref:
            logger.debug(f"Using CodeQL pack suite for {lang}: {pack_ref}")
            return pack_ref

        return None

    def build_query_specs(self, language: str, vuln_types: list[str]) -> list[str]:
        """Build deduplicated query specs, fallback to full suite if needed."""
        lang = LANGUAGE_MAP.get(language.lower(), language.lower())
        specs: list[str] = []
        missing: list[str] = []

        for vt in vuln_types:
            spec = self.get_query_spec(lang, vt)
            if spec and spec not in specs:
                specs.append(spec)
            elif not spec:
                missing.append(vt)

        if missing:
            suite = self.get_suite(lang)
            if suite and suite not in specs:
                logger.info(f"No specific queries for {missing} in {lang}, adding full suite")
                specs.insert(0, suite)

        return specs

    def list_templates(self, language: Optional[str] = None) -> dict[str, list[str]]:
        """List available local templates by language."""
        result: dict[str, list[str]] = {}
        if language:
            languages = [LANGUAGE_MAP.get(language.lower(), language.lower())]
        else:
            if not self._templates_dir.exists():
                return result
            languages = [d.name for d in self._templates_dir.iterdir() if d.is_dir()]

        for lang in languages:
            lang_dir = self._templates_dir / lang
            if not lang_dir.exists():
                continue
            vuln_types = [ql_file.stem for ql_file in lang_dir.glob("*.ql")]
            if vuln_types:
                result[lang] = sorted(vuln_types)
        return result

    def get_all_vuln_types(self) -> list[str]:
        """Get list of all supported vulnerability types."""
        return list(VULNERABILITY_TYPES.keys())


# ── Global singleton ──────────────────────────────────────────────────

_TEMPLATE_MANAGER: Optional[QueryTemplateManager] = None


def get_template_manager(
    queries_path: str = "",
    project_path: str = "",
) -> QueryTemplateManager:
    """Get or create the global template manager instance.

    Args:
        queries_path: Path to github/codeql clone (from ``baize.yaml``).
                      Empty to auto-detect. Supports ``${ENV_VAR}`` syntax.
        project_path: Project path for sibling auto-detection.

    Returns:
        QueryTemplateManager instance (singleton — cached after first call).
    """
    global _TEMPLATE_MANAGER

    if _TEMPLATE_MANAGER is not None:
        return _TEMPLATE_MANAGER

    # Resolve env var references
    import os
    if queries_path and queries_path.startswith("${") and queries_path.endswith("}"):
        queries_path = os.environ.get(queries_path[2:-1], "")

    proj = Path(project_path) if project_path else None
    resolved = _resolve_queries_base(
        explicit=queries_path if queries_path else None,
        project_path=proj,
    )

    if resolved:
        logger.info(f"Using local QL queries: {resolved}")
    else:
        logger.info("No local codeql-queries found — using CodeQL pack references")

    _TEMPLATE_MANAGER = QueryTemplateManager(queries_base=resolved)
    return _TEMPLATE_MANAGER


def reset_template_manager() -> None:
    """Reset the global template manager (useful for testing)."""
    global _TEMPLATE_MANAGER
    _TEMPLATE_MANAGER = None
