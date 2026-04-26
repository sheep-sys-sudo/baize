"""Markdown report generator."""

from pathlib import Path

from baize.models.report import Report
from baize.models.finding import FindingSeverity


def generate_markdown_report(report: Report, output_path: Path) -> None:
    """Generate a Markdown report from a Report object.

    Args:
        report: Report object to render
        output_path: Path to write Markdown file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []

    lines.append("# 安全审计报告")
    lines.append("")
    lines.append(f"**项目**: {report.metadata.project_name}")
    lines.append(f"**生成时间**: {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Baize 版本**: {report.metadata.baize_version}")
    lines.append("")

    lines.append("## 摘要")
    lines.append("")
    lines.append(f"- **总发现数**: {report.metadata.total_findings}")
    lines.append(f"- **严重漏洞**: {report.metadata.findings_by_severity.get('critical', 0) + report.metadata.findings_by_severity.get('high', 0)}")
    lines.append("")

    lines.append("### 按严重程度")
    lines.append("")
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = report.metadata.findings_by_severity.get(severity, 0)
        if count > 0:
            lines.append(f"- **{severity.upper()}**: {count}")
    lines.append("")

    lines.append("### 按类型")
    lines.append("")
    for vuln_type, count in report.metadata.findings_by_type.items():
        lines.append(f"- {vuln_type}: {count}")
    lines.append("")

    if report.findings:
        lines.append("## 漏洞详情")
        lines.append("")

        for i, finding in enumerate(report.findings, 1):
            severity_badge = _severity_badge(finding.severity)

            lines.append(f"### {i}. {finding.title} {severity_badge}")
            lines.append("")
            lines.append(f"**规则 ID**: `{finding.rule_id}`")
            lines.append("")
            lines.append(f"**位置**: `{finding.location.file}:{finding.location.line}:{finding.location.column}`")
            lines.append("")
            lines.append(f"**类型**: `{finding.vuln_type.value}`")
            lines.append("")

            if finding.message:
                lines.append(f"**消息**: {finding.message}")
                lines.append("")

            if finding.dataflow_path:
                lines.append("**数据流路径**:")
                lines.append("```")
                for loc in finding.dataflow_path.locations:
                    lines.append(f"{loc.file}:{loc.line} - {loc.snippet[:50]}...")
                lines.append("```")
                lines.append("")

            lines.append("---")
            lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _severity_badge(severity: FindingSeverity) -> str:
    """Generate a severity badge in Markdown."""
    badges = {
        FindingSeverity.CRITICAL: "🔴 CRITICAL",
        FindingSeverity.HIGH: "🟠 HIGH",
        FindingSeverity.MEDIUM: "🟡 MEDIUM",
        FindingSeverity.LOW: "🔵 LOW",
        FindingSeverity.INFO: "⚪ INFO",
    }
    return badges.get(severity, "")