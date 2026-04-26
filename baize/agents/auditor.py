"""Auditor agent for running vulnerability analysis."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from baize.agents.base import AgentContext, AgentResult, BaseAgent, agent
from baize.core import Analyzer, CodeQLBuilder, ResultProcessor, Scheduler
from baize.queries import get_template_manager
from baize.utils.codeql import CodeQLCLI


@agent("auditor")
class AuditorAgent(BaseAgent):
    """Auditor agent for executing vulnerability analysis.

    This agent is responsible for:
    - Building CodeQL databases
    - Running vulnerability queries
    - Collecting raw results
    """

    name = "auditor"
    description = "Runs vulnerability analysis using CodeQL"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the auditor workflow.

        Args:
            context: Agent context with project path and config

        Returns:
            AgentResult with analysis results
        """
        project_path = Path(context.project_path)

        if not project_path.exists():
            return AgentResult(
                success=False,
                error=f"Project path does not exist: {project_path}",
            )

        db_path = project_path / ".baize" / "db"

        if not db_path.exists():
            logger.info("Building CodeQL database...")
            codeql = CodeQLCLI()
            builder = CodeQLBuilder(codeql, Scheduler())

            async def build():
                strategy = await builder.decide_build_strategy(project_path)
                return await builder.build_database(project_path, strategy=strategy)

            success, metrics, db_path = await build()

            if not success:
                return AgentResult(
                    success=False,
                    error="Failed to build CodeQL database",
                    metadata={"metrics": metrics.to_dict()},
                )

        sarif_path = project_path / ".baize" / "reports" / "results.sarif"
        sarif_path.parent.mkdir(parents=True, exist_ok=True)

        vuln_types = context.get("vuln_types", ["sqli", "xss", "rce"])
        language = context.get("language", "java")
        manager = get_template_manager()
        query_specs = manager.build_query_specs(language, vuln_types)

        codeql = CodeQLCLI()
        analyzer = Analyzer(codeql)
        all_findings = []

        for spec in query_specs:
            spec_sarif = sarif_path.parent / f"results_{abs(hash(spec)) % 10000}.sarif"
            logger.info(f"Running analysis with queries: {spec}")

            success, result_path = await analyzer.execute_query(
                db_path=db_path,
                queries=spec,
                output_path=spec_sarif,
            )

            if not success:
                logger.warning(f"Query spec '{spec}' failed, skipping")
                continue

            processor = ResultProcessor()
            findings = processor.process_results(result_path)
            all_findings.extend(findings)

        return AgentResult(
            success=True,
            output={
                "sarif_path": str(sarif_path),
                "total_findings": len(all_findings),
                "findings": [f.to_dict() for f in all_findings],
            },
            metadata={
                "db_path": str(db_path),
                "sarif_path": str(sarif_path),
                "query_specs_used": query_specs,
            },
        )


