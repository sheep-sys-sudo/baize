"""Processor agent for filtering and ranking findings."""

from __future__ import annotations

from pathlib import Path


from baize.agents.base import AgentContext, AgentResult, BaseAgent, agent
from baize.core import ResultProcessor
from baize.core.dataflow import DataFlowAnalyzer
from baize.models.finding import FindingSeverity


@agent("processor")
class ProcessorAgent(BaseAgent):
    """Processor agent for filtering, ranking, and enriching findings.

    This agent is responsible for:
    - Deduplicating findings
    - Filtering false positives
    - Ranking by severity and confidence
    - Enriching with data flow paths
    """

    name = "processor"
    description = "Processes and enriches vulnerability findings"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the processor workflow.

        Args:
            context: Agent context with sarif_path and config

        Returns:
            AgentResult with processed findings
        """
        sarif_path = context.get("sarif_path")
        if not sarif_path:
            return AgentResult(
                success=False,
                error="No SARIF path provided",
            )

        sarif_path = Path(sarif_path)
        if not sarif_path.exists():
            return AgentResult(
                success=False,
                error=f"SARIF file not found: {sarif_path}",
            )

        processor = ResultProcessor()

        # process_results already denoises, deduplicates (by exclude patterns),
        # and ranks findings — no need for additional sort passes.
        findings = processor.process_results(sarif_path)
        findings = await processor.deduplicate(findings)
        findings = await processor.filter_by_confidence(findings, min_confidence=0.5)

        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == FindingSeverity.LOW),
        }

        dataflow_analyzer = DataFlowAnalyzer()
        enriched = await dataflow_analyzer.enrich_findings_with_dataflow(
            findings,
            sarif_path,
        )

        return AgentResult(
            success=True,
            output={
                "total_findings": len(enriched),
                "findings_by_severity": severity_counts,
                "top_findings": [f.to_dict() for f in enriched[:10]],
                "all_findings": [f.to_dict() for f in enriched],
            },
            metadata={
                "original_count": len(findings),
                "after_dedup_confidence": len(enriched),
                "severity_counts": severity_counts,
            },
        )
