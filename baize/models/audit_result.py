"""Unified audit result model — the single output of ``baize audit``.

The agent consumes this structured JSON to understand what CodeQL found
without needing to run CodeQL or parse SARIF itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class DataFlowStep:
    """A single step in a taint-tracking dataflow path with source code."""

    file: str = ""
    line: int = 0
    column: int = 0
    code_snippet: str = ""
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "message": self.message,
        }


@dataclass
class AuditFinding:
    """A single vulnerability finding with full dataflow detail."""

    id: str = ""
    rule_id: str = ""
    severity: str = ""  # critical, high, medium, low, info
    vuln_type: str = ""  # sqli, xss, rce, ssrf, etc.
    title: str = ""
    message: str = ""
    location: dict = field(default_factory=dict)  # {file, line, column, snippet}
    cwe_id: str = ""
    confidence: float = 0.0
    dataflow: list[DataFlowStep] = field(default_factory=list)
    dataflow_complete: bool = False
    related_locations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "type": self.vuln_type,
            "title": self.title,
            "message": self.message,
            "location": self.location,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "dataflow": [step.to_dict() for step in self.dataflow],
            "dataflow_complete": self.dataflow_complete,
            "related_locations": self.related_locations,
        }


@dataclass
class TriageInfo:
    """Quick project assessment summary."""

    viable: bool = False
    score: int = 0
    language: str = "unknown"
    file_count: int = 0
    lines_of_code: int = 0
    build_system: str = "none"

    def to_dict(self) -> dict:
        return {
            "viable": self.viable,
            "score": self.score,
            "language": self.language,
            "file_count": self.file_count,
            "lines_of_code": self.lines_of_code,
            "build_system": self.build_system,
        }


@dataclass
class AuditResult:
    """The unified output of ``baize audit``.

    Written to ``.baize/result.json`` for the agent to consume.
    Contains all findings with dataflow, triage info, and scan metadata.
    """

    project_name: str = ""
    project_path: str = ""
    language: str = ""
    scan_timestamp: str = ""
    db_hash: str = ""
    total_findings: int = 0
    findings_by_severity: dict = field(default_factory=dict)
    findings: list[AuditFinding] = field(default_factory=list)
    triage: Optional[TriageInfo] = None
    delta: Optional[dict] = None
    build_info: dict = field(default_factory=dict)
    analysis_info: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "project_path": self.project_path,
            "language": self.language,
            "scan_timestamp": self.scan_timestamp,
            "db_hash": self.db_hash,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "triage": self.triage.to_dict() if self.triage else None,
            "delta": self.delta,
            "build_info": self.build_info,
            "analysis_info": self.analysis_info,
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def to_json(self, path: Optional[Path] = None) -> str:
        """Serialize to JSON. If path is given, writes to file as well.

        Args:
            path: Optional file path to write.

        Returns:
            JSON string.
        """
        json_str = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(json_str)
        return json_str

    @classmethod
    def create_empty(cls, project_name: str = "", project_path: str = "") -> AuditResult:
        """Create an empty result with timestamp."""
        return cls(
            project_name=project_name,
            project_path=project_path,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_findings(
        cls,
        findings: list,
        project_name: str = "",
        project_path: str = "",
        language: str = "",
        db_hash: str = "",
        triage: Optional[TriageInfo] = None,
    ) -> AuditResult:
        """Build an AuditResult from a list of Finding objects.

        Args:
            findings: List of Finding or AuditFinding objects.
            project_name: Project name.
            project_path: Project path.
            language: Detected language.
            db_hash: Database hash used for this scan.
            triage: Optional triage assessment.

        Returns:
            AuditResult with all data populated.
        """
        audit_findings = []
        severity_counts: dict[str, int] = {}

        for f in findings:
            if hasattr(f, "to_dict"):
                fd = f.to_dict()
            else:
                fd = f

            # Build dataflow steps
            dataflow_steps = []
            dataflow_complete = False
            df_path = fd.get("dataflow_path")
            if df_path:
                dataflow_complete = df_path.get("is_complete", False)
                for loc in df_path.get("locations", []):
                    dataflow_steps.append(DataFlowStep(
                        file=loc.get("file", ""),
                        line=loc.get("line", 0),
                        column=loc.get("column", 0),
                        code_snippet=loc.get("snippet", ""),
                    ))

            severity = fd.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            audit_findings.append(AuditFinding(
                id=fd.get("id", ""),
                rule_id=fd.get("rule_id", ""),
                severity=severity,
                vuln_type=fd.get("type", fd.get("vuln_type", "unknown")),
                title=fd.get("title", ""),
                message=fd.get("message", ""),
                location=fd.get("location", {}),
                cwe_id=fd.get("cwe_id", ""),
                confidence=fd.get("confidence", 0.0),
                dataflow=dataflow_steps,
                dataflow_complete=dataflow_complete,
                related_locations=fd.get("related_locations", []),
            ))

        return cls(
            project_name=project_name,
            project_path=project_path,
            language=language,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            db_hash=db_hash,
            total_findings=len(audit_findings),
            findings_by_severity=severity_counts,
            findings=audit_findings,
            triage=triage,
        )
