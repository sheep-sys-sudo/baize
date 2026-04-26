"""JSON report generator."""

from pathlib import Path

from baize.models.report import Report


def generate_json_report(report: Report, output_path: Path) -> None:
    """Generate a JSON report from a Report object.

    Args:
        report: Report object to serialize
        output_path: Path to write JSON file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    import json

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)