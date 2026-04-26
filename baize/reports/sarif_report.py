"""SARIF 2.1 report generator.

Converts Baize Report / Finding objects back to a valid SARIF 2.1 JSON file.
This is useful when a downstream tool (GitHub Advanced Security, VS Code SARIF
Viewer, etc.) needs a structured SARIF rather than the Markdown/HTML output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from baize.models.finding import Finding, FindingSeverity
from baize.models.report import Report


# Map Baize severities to SARIF notification levels
_SARIF_LEVEL: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor entry from a finding."""
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.title or finding.rule_id,
        "shortDescription": {"text": finding.title or finding.rule_id},
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity, "warning")
        },
    }
    if finding.cwe_id:
        rule["properties"] = {"tags": [finding.cwe_id]}
    return rule


def _location_to_sarif(loc: Any) -> dict[str, Any]:
    """Convert a Baize Location to a SARIF physicalLocation dict."""
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": str(loc.file).replace("\\", "/")},
            "region": {
                "startLine": max(loc.line, 1),
                "startColumn": max(loc.column, 1),
            },
        }
    }


def _finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": finding.message or finding.title or finding.rule_id},
        "locations": [_location_to_sarif(finding.location)],
    }

    # Attach dataflow as codeFlows when available
    if finding.dataflow_path and finding.dataflow_path.locations:
        thread_flow_locs = [
            {
                "location": _location_to_sarif(loc),
                **({"message": {"text": loc.snippet[:200]}} if loc.snippet else {}),
            }
            for loc in finding.dataflow_path.locations
        ]
        result["codeFlows"] = [
            {
                "threadFlows": [{"locations": thread_flow_locs}],
                "message": {
                    "text": f"is_complete={finding.dataflow_path.is_complete}"
                },
            }
        ]

    if finding.related_locations:
        result["relatedLocations"] = [
            _location_to_sarif(loc) for loc in finding.related_locations
        ]

    # Store extra metadata as properties
    props: dict[str, Any] = {
        "vuln_type": str(finding.vuln_type.value),
        "confidence": finding.confidence,
    }
    if finding.cwe_id:
        props["cwe"] = finding.cwe_id
    result["properties"] = props

    return result


def generate_sarif_report(report: Report, output_path: Path) -> None:
    """Generate a SARIF 2.1 file from a Baize Report.

    Args:
        report:      Baize Report object containing findings.
        output_path: Destination file path for the SARIF output.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect unique rules (one per distinct rule_id)
    seen_rules: set[str] = set()
    rules: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.rule_id not in seen_rules:
            rules.append(_build_rule(finding))
            seen_rules.add(finding.rule_id)

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Baize",
                        "version": "2.0",
                        "informationUri": "https://github.com/baize",
                        "rules": rules,
                    }
                },
                "results": [_finding_to_sarif_result(f) for f in report.findings],
                "properties": {
                    "project": report.metadata.project_name,
                    "generated_at": report.metadata.generated_at.isoformat(),
                    "total_findings": report.metadata.total_findings,
                },
            }
        ],
    }

    output_path.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8"
    )
