"""Fix suggester agent for generating remediation suggestions."""

from __future__ import annotations

from pathlib import Path


from baize.agents.base import AgentContext, AgentResult, BaseAgent, agent
from baize.core import FixSuggester


@agent("fix_suggester")
class FixSuggesterAgent(BaseAgent):
    """Fix suggester agent — generates remediation suggestions for vulnerabilities.

    Uses FixSuggester with template-first, LLM fallback strategy:
    1. Static FIX_TEMPLATES (no LLM cost, instant)
    2. LLM generation when no template exists (async)
    """

    name = "fix_suggester"
    description = "Generates fix suggestions for vulnerabilities"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the fix suggester (async to support LLM fallback)."""
        findings = context.get("findings", [])

        if not findings:
            return AgentResult(success=False, error="No findings provided")

        fixer = FixSuggester()
        fixes = []

        for finding_data in findings:
            if isinstance(finding_data, dict):
                from baize.models.finding import Finding, FindingSeverity, VulnerabilityType
                from baize.models.dataflow import Location

                location = Location(
                    file=Path(finding_data.get("location", {}).get("file", "")),
                    line=finding_data.get("location", {}).get("line", 0),
                    column=finding_data.get("location", {}).get("column", 0),
                )

                finding = Finding(
                    id=finding_data.get("id", ""),
                    rule_id=finding_data.get("rule_id", ""),
                    severity=FindingSeverity(finding_data.get("severity", "medium")),
                    vuln_type=VulnerabilityType(finding_data.get("type", "unknown")),
                    location=location,
                )
            else:
                finding = finding_data

            fix = await fixer.suggest_fix_async(finding)
            fixes.append({
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "vuln_type": finding.vuln_type.value,
                "fix": fix,
            })

        return AgentResult(
            success=True,
            output={"total_fixes": len(fixes), "fixes": fixes},
            metadata={"fixes_generated": len(fixes)},
        )
