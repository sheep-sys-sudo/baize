"""HTML report generator."""

from __future__ import annotations

import html
from pathlib import Path

from baize.models.finding import FindingSeverity
from baize.models.report import Report


_SEVERITY_COLOR = {
    FindingSeverity.CRITICAL: "#dc2626",
    FindingSeverity.HIGH:     "#ea580c",
    FindingSeverity.MEDIUM:   "#ca8a04",
    FindingSeverity.LOW:      "#16a34a",
    FindingSeverity.INFO:     "#2563eb",
}

_SEVERITY_BADGE = {
    FindingSeverity.CRITICAL: "badge-critical",
    FindingSeverity.HIGH:     "badge-high",
    FindingSeverity.MEDIUM:   "badge-medium",
    FindingSeverity.LOW:      "badge-low",
    FindingSeverity.INFO:     "badge-info",
}


def _escape(text: str) -> str:
    return html.escape(str(text), quote=True)


def _severity_counts_chart(by_severity: dict[str, int]) -> str:
    bars = []
    order = [s.value for s in FindingSeverity]
    for sev in order:
        count = by_severity.get(sev, 0)
        if count == 0:
            continue
        color = _SEVERITY_COLOR.get(FindingSeverity(sev), "#6b7280")
        bars.append(
            f'<div class="chart-bar">'
            f'<div class="bar-fill" style="background:{color};width:{min(count*20,200)}px"></div>'
            f'<span class="bar-label">{_escape(sev.upper())} ({count})</span>'
            f"</div>"
        )
    return "\n".join(bars) if bars else "<p>No findings.</p>"


def _finding_row(finding, index: int) -> str:
    sev = finding.severity
    color = _SEVERITY_COLOR.get(sev, "#6b7280")
    badge_cls = _SEVERITY_BADGE.get(sev, "badge-info")
    loc = finding.location
    dataflow_html = ""
    if finding.dataflow_path:
        dfp = finding.dataflow_path
        steps = [f'<li><code>{_escape(dfp.source.file)}:{dfp.source.line}</code> (source)</li>']
        for mid in dfp.intermediate:
            steps.append(f'<li><code>{_escape(mid.file)}:{mid.line}</code></li>')
        steps.append(f'<li><code>{_escape(dfp.sink.file)}:{dfp.sink.line}</code> (sink)</li>')
        dataflow_html = f'<div class="dataflow"><strong>Data Flow:</strong><ol>{"".join(steps)}</ol></div>'

    snippet_html = ""
    if finding.source_code or loc.snippet:
        code = finding.source_code or loc.snippet
        snippet_html = f'<pre class="code-snippet"><code>{_escape(code)}</code></pre>'

    return f"""
    <div class="finding" id="finding-{index}">
      <div class="finding-header" style="border-left:4px solid {color}">
        <span class="badge {badge_cls}">{_escape(sev.value.upper())}</span>
        <span class="finding-title">{_escape(finding.title or finding.vuln_type.value.upper())}</span>
        <span class="finding-id">{_escape(finding.id)}</span>
      </div>
      <div class="finding-body">
        <p class="message">{_escape(finding.message)}</p>
        <div class="meta-row">
          <span>📁 <code>{_escape(loc.file)}:{loc.line}</code></span>
          <span>🏷 <code>{_escape(finding.vuln_type.value)}</code></span>
          {f'<span>🔒 <code>{_escape(finding.cwe_id)}</code></span>' if finding.cwe_id else ''}
          <span>⚡ Confidence: {finding.confidence:.0%}</span>
        </div>
        {snippet_html}
        {dataflow_html}
      </div>
    </div>"""


def generate_html_report(report: Report, output_path: Path) -> None:
    """Generate an HTML report from a Report object.

    Args:
        report: Report object to serialize
        output_path: Path to write the HTML file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    meta = report.metadata
    now_str = _escape(meta.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
    project_name = _escape(meta.project_name or "Unknown Project")
    total = meta.total_findings

    finding_rows = "\n".join(
        _finding_row(f, i) for i, f in enumerate(report.findings, 1)
    )

    by_type_rows = "".join(
        f'<tr><td>{_escape(k)}</td><td>{v}</td></tr>'
        for k, v in sorted(meta.findings_by_type.items(), key=lambda x: -x[1])
    )

    chart_html = _severity_counts_chart(meta.findings_by_severity)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Baize Security Report — {project_name}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
          background:#f8fafc;color:#1e293b;line-height:1.6}}
    header{{background:#0f172a;color:#f1f5f9;padding:24px 40px}}
    header h1{{font-size:1.8rem;font-weight:700}}
    header p{{color:#94a3b8;font-size:.9rem;margin-top:4px}}
    .container{{max-width:1100px;margin:0 auto;padding:32px 20px}}
    .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:32px}}
    .summary-card{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
    .summary-card .value{{font-size:2rem;font-weight:700;color:#0f172a}}
    .summary-card .label{{font-size:.8rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
    .section-title{{font-size:1.2rem;font-weight:600;margin:28px 0 12px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}}
    .chart-bar{{display:flex;align-items:center;gap:10px;margin:6px 0}}
    .bar-fill{{height:20px;border-radius:3px;min-width:4px}}
    .bar-label{{font-size:.85rem;white-space:nowrap}}
    table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
    th{{background:#f1f5f9;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;padding:10px 14px;text-align:left}}
    td{{padding:10px 14px;border-top:1px solid #f1f5f9;font-size:.9rem}}
    .finding{{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:16px;overflow:hidden}}
    .finding-header{{display:flex;align-items:center;gap:10px;padding:14px 16px;background:#f8fafc}}
    .finding-title{{font-weight:600;flex:1}}
    .finding-id{{font-size:.75rem;color:#94a3b8;font-family:monospace}}
    .finding-body{{padding:14px 16px}}
    .message{{margin-bottom:10px;color:#334155}}
    .meta-row{{display:flex;flex-wrap:wrap;gap:14px;font-size:.82rem;color:#64748b;margin-bottom:10px}}
    pre.code-snippet{{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:12px;overflow-x:auto;font-size:.82rem;margin:10px 0}}
    .dataflow{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:10px 14px;margin-top:10px;font-size:.85rem}}
    .dataflow ol{{padding-left:18px;margin-top:6px}}
    .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase;color:#fff}}
    .badge-critical{{background:#dc2626}}.badge-high{{background:#ea580c}}
    .badge-medium{{background:#ca8a04}}.badge-low{{background:#16a34a}}.badge-info{{background:#2563eb}}
    code{{font-family:'JetBrains Mono',Consolas,monospace;font-size:.85em}}
    footer{{text-align:center;color:#94a3b8;font-size:.8rem;padding:24px}}
  </style>
</head>
<body>
  <header>
    <h1>🐉 Baize Security Report</h1>
    <p>{project_name} &mdash; generated {now_str}</p>
  </header>
  <div class="container">
    <div class="summary-grid">
      <div class="summary-card">
        <div class="value">{total}</div>
        <div class="label">Total Findings</div>
      </div>
      <div class="summary-card">
        <div class="value">{meta.findings_by_severity.get('critical', 0)}</div>
        <div class="label" style="color:#dc2626">Critical</div>
      </div>
      <div class="summary-card">
        <div class="value">{meta.findings_by_severity.get('high', 0)}</div>
        <div class="label" style="color:#ea580c">High</div>
      </div>
      <div class="summary-card">
        <div class="value">{meta.findings_by_severity.get('medium', 0)}</div>
        <div class="label" style="color:#ca8a04">Medium</div>
      </div>
    </div>

    <div class="section-title">Severity Distribution</div>
    <div class="chart">{chart_html}</div>

    <div class="section-title">Findings by Type</div>
    <table>
      <thead><tr><th>Vulnerability Type</th><th>Count</th></tr></thead>
      <tbody>{by_type_rows}</tbody>
    </table>

    <div class="section-title">Findings ({total})</div>
    {finding_rows if finding_rows else '<p style="color:#64748b">No findings detected.</p>'}
  </div>
  <footer>Generated by Baize &mdash; AI × CodeQL Security Audit Engine</footer>
</body>
</html>"""

    output_path.write_text(html_content, encoding="utf-8")
