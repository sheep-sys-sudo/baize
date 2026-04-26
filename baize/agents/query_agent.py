"""Query generator agent for creating CodeQL queries."""

from __future__ import annotations

from loguru import logger

from baize.agents.base import AgentContext, AgentResult, BaseAgent, agent
from baize.queries import get_template_manager


@agent("query_generator")
class QueryGeneratorAgent(BaseAgent):
    """Query generator agent for generating CodeQL queries.

    This agent is responsible for:
    - Resolving official CodeQL query specs for requested vulnerability types
    - Falling back to full security suite when no specific query is available
    - Returning query spec strings ready for use with `codeql database analyze`
    """

    name = "query_generator"
    description = "Generates CodeQL queries for vulnerability detection"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the query generator.

        Args:
            context: Agent context with vuln_types and language

        Returns:
            AgentResult with query specs and metadata
        """
        vuln_types = context.get("vuln_types", ["sqli", "xss", "rce"])
        language = context.get("language", "java")

        manager = get_template_manager()
        query_specs = manager.build_query_specs(language, vuln_types)

        per_type: dict[str, str | None] = {}
        missing: list[str] = []
        for vt in vuln_types:
            spec = manager.get_query_spec(language, vt)
            per_type[vt] = spec
            if spec is None:
                missing.append(vt)

        suite_fallback = manager.get_suite(language)

        if missing:
            logger.warning(
                f"No specific query found for {missing} in {language}; "
                f"suite fallback: {suite_fallback}"
            )

        return AgentResult(
            success=True,
            output={
                "query_specs": query_specs,
                "per_type": per_type,
                "suite_fallback": suite_fallback,
                "language": language,
                "vuln_types_requested": vuln_types,
                "vuln_types_missing": missing,
            },
            metadata={
                "total_specs": len(query_specs),
                "language": language,
            },
        )
