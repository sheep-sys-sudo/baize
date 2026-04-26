"""Delta analysis — compare two audit scans and report only new findings.

Useful for CI/CD pipelines and incremental audits where you only want
to see findings that didn't exist in the previous scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from loguru import logger


class ResolutionStatus(str, Enum):
    """Status of a finding across two scans."""

    NEW = "new"        # Only in current scan
    STILL_PRESENT = "still_present"  # In both scans
    FIXED = "fixed"    # Only in previous scan (was resolved)


@dataclass
class DeltaResult:
    """Result of a delta analysis between two scans."""

    total_current: int = 0
    total_previous: int = 0
    new_findings: list[dict] = field(default_factory=list)
    fixed_findings: list[dict] = field(default_factory=list)
    still_present: list[dict] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def unchanged_count(self) -> int:
        return len(self.still_present)

    def to_dict(self) -> dict:
        return {
            "total_current": self.total_current,
            "total_previous": self.total_previous,
            "new_count": self.new_count,
            "fixed_count": self.fixed_count,
            "unchanged_count": self.unchanged_count,
            "new_findings": self.new_findings,
            "fixed_findings": self.fixed_findings,
            "still_present": self.still_present,
        }


class DeltaAnalyzer:
    """Compares two audit result sets and identifies new/resolved findings."""

    def __init__(self, previous_result_path: Optional[Path] = None):
        """Initialize the analyzer.

        Args:
            previous_result_path: Path to the previous result.json.
                                  If None, uses ``.baize/result.json``.
        """
        self.previous_path = previous_result_path

    @staticmethod
    def _make_key(finding: dict) -> tuple:
        """Create a stable identity key for a finding.

        Keys are (file, line, rule_id) — the same fields used for deduplication.
        """
        loc = finding.get("location", {})
        file = loc.get("file", "")
        line = loc.get("line", 0)
        rule_id = finding.get("rule_id", "")
        return (str(file), int(line), str(rule_id))

    def analyze(
        self,
        current_findings: list[dict],
        previous_findings: Optional[list[dict]] = None,
    ) -> DeltaResult:
        """Compare current findings against previous ones.

        Args:
            current_findings: Findings from the current scan.
            previous_findings: Findings from the previous scan.
                              If None, attempts to load from previous_result_path.

        Returns:
            DeltaResult with new, fixed, and unchanged findings.
        """
        if previous_findings is None and self.previous_path is not None:
            previous_findings = self._load_previous(self.previous_path)

        if not previous_findings:
            logger.info("No previous findings to compare — all findings are new")
            return DeltaResult(
                total_current=len(current_findings),
                total_previous=0,
                new_findings=current_findings,
            )

        # Build index of previous findings
        prev_keys: dict[tuple, dict] = {}
        for f in previous_findings:
            key = self._make_key(f)
            prev_keys[key] = f

        # Build index of current findings
        curr_keys: dict[tuple, dict] = {}
        for f in current_findings:
            key = self._make_key(f)
            curr_keys[key] = f

        new = []
        still_present = []
        fixed = []

        # Identify new and still-present
        for key, finding in curr_keys.items():
            if key in prev_keys:
                still_present.append(finding)
            else:
                new.append(finding)

        # Identify fixed (in previous but not in current)
        for key, finding in prev_keys.items():
            if key not in curr_keys:
                fixed.append(finding)

        logger.info(
            f"Delta: {len(new)} new, {len(fixed)} fixed, "
            f"{len(still_present)} still present"
        )

        return DeltaResult(
            total_current=len(current_findings),
            total_previous=len(previous_findings),
            new_findings=new,
            fixed_findings=fixed,
            still_present=still_present,
        )

    @staticmethod
    def _load_previous(path: Path) -> list[dict]:
        """Load previous scan results from a result.json file."""
        try:
            data = json.loads(Path(path).read_text())
            return data.get("findings", [])
        except Exception as e:
            logger.warning(f"Failed to load previous results from {path}: {e}")
            return []

    def save_current(self, findings: list[dict], path: Path) -> None:
        """Save current findings for future delta comparison.

        Args:
            findings: List of finding dicts to save.
            path: Path to write the result file.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "findings": findings,
            "total": len(findings),
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        logger.info(f"Saved {len(findings)} findings to {path}")
