"""Report generation modules."""

from pathlib import Path

from baize.reports.html_report import generate_html_report
from baize.reports.json_report import generate_json_report
from baize.reports.markdown_report import generate_markdown_report
from baize.reports.sarif_report import generate_sarif_report

REPORT_FORMATS = {
    "json": generate_json_report,
    "markdown": generate_markdown_report,
    "md": generate_markdown_report,
    "html": generate_html_report,
    "sarif": generate_sarif_report,
}


def generate_report(report_obj, output_path, format: str) -> None:
    """Generate a report in the specified format.

    Args:
        report_obj:  Report object to generate
        output_path: Path to write the report
        format:      Format string (json, markdown, md, html, sarif)
    """
    format_lower = format.lower()
    output_path = Path(output_path)

    generator = REPORT_FORMATS.get(format_lower)
    if generator is None:
        raise ValueError(
            f"Unsupported format: {format!r}. "
            f"Valid formats: {', '.join(REPORT_FORMATS)}"
        )
    generator(report_obj, output_path)


__all__ = [
    "generate_report",
    "generate_json_report",
    "generate_markdown_report",
    "generate_html_report",
    "generate_sarif_report",
    "REPORT_FORMATS",
]
