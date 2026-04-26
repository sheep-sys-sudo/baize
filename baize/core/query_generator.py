"""Query generator for CodeQL — resolution via QueryTemplateManager.

Query specs are resolved by QueryTemplateManager, which checks:
1. Local custom .ql template (templates_dir/{language}/{vuln_type}.ql)
2. Official query path from OFFICIAL_QUERY_PATHS (local cloned repo)
3. Full official suite from OFFICIAL_SUITES (language-level fallback)

This module re-exports QueryTemplateManager for convenience.
"""

from __future__ import annotations

from baize.queries.generator import QueryTemplateManager, get_template_manager

__all__ = ["QueryTemplateManager", "get_template_manager"]
