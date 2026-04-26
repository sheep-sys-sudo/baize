"""Report models for output generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from baize.models.finding import Finding


class ReportFormat(str, Enum):
    """Supported report output formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"


@dataclass
class ReportMetadata:
    """Metadata for a generated report."""

    project_name: str = ""
    project_path: str = ""
    generated_at: datetime = field(default_factory=datetime.utcnow)
    baize_version: str = ""
    codeql_version: str = ""
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_type: dict[str, int] = field(default_factory=dict)
    analysis_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "project_path": self.project_path,
            "generated_at": self.generated_at.isoformat(),
            "baize_version": self.baize_version,
            "codeql_version": self.codeql_version,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_type": self.findings_by_type,
            "analysis_duration_seconds": self.analysis_duration_seconds,
        }


@dataclass
class Report:
    """Complete analysis report."""

    metadata: ReportMetadata
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    dataflow_included: bool = False
    fixes_included: bool = False

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.metadata.total_findings = len(self.findings)

        severity = finding.severity.value
        self.metadata.findings_by_severity[severity] = (
            self.metadata.findings_by_severity.get(severity, 0) + 1
        )

        vuln_type = finding.vuln_type.value
        self.metadata.findings_by_type[vuln_type] = (
            self.metadata.findings_by_type.get(vuln_type, 0) + 1
        )

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "dataflow_included": self.dataflow_included,
            "fixes_included": self.fixes_included,
        }

    @classmethod
    def create_empty(cls, project_name: str = "", project_path: str = "") -> Report:
        """Create an empty report with initialized metadata."""
        metadata = ReportMetadata(project_name=project_name, project_path=project_path)
        return cls(metadata=metadata)