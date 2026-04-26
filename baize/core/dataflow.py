"""Data flow analyzer for source-sink path reconstruction from SARIF.

Enhanced with deep dataflow extraction: not just file:line, but actual
code snippets at each step of the taint path, extracted from SARIF
``threadFlows`` location entries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loguru import logger

from baize.models.dataflow import DataFlowPath, Location
from baize.models.finding import Finding


@dataclass
class DataFlowStep:
    """A single step in a dataflow path with full source code context."""

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
class DeepDataFlowPath:
    """A complete source-to-sink path with code snippets at every step."""

    source: DataFlowStep = field(default_factory=DataFlowStep)
    sink: DataFlowStep = field(default_factory=DataFlowStep)
    intermediate: list[DataFlowStep] = field(default_factory=list)
    is_complete: bool = False
    step_count: int = 0

    def to_dict(self) -> dict:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "intermediate": [s.to_dict() for s in self.intermediate],
            "is_complete": self.is_complete,
            "step_count": self.step_count,
        }

    @property
    def all_steps(self) -> list[DataFlowStep]:
        return [self.source] + self.intermediate + [self.sink]


def _extract_location(loc_entry: dict) -> Optional[Location]:
    """Extract a Location from a SARIF threadFlow location entry."""
    phys_loc = loc_entry.get("location", {}).get("physicalLocation", {})
    if not phys_loc:
        phys_loc = loc_entry.get("physicalLocation", {})

    artifact = phys_loc.get("artifactLocation", {})
    region = phys_loc.get("region", {})

    uri = artifact.get("uri", "")
    if not uri:
        return None

    return Location(
        file=Path(uri),
        line=region.get("startLine", 0),
        column=region.get("startColumn", 0),
        snippet=region.get("snippet", {}).get("text", ""),
    )


def _extract_dataflow_step(loc_entry: dict) -> Optional[DataFlowStep]:
    """Extract a DataFlowStep with code snippet from a SARIF location entry.

    Extracts file, line, column, code snippet text, and any flow message
    from the location entry. This provides the agent with actual source
    code at each step of the taint path.

    Args:
        loc_entry: A single location entry from a SARIF threadFlow.

    Returns:
        DataFlowStep if valid location found, None otherwise.
    """
    # The location can be nested as loc_entry.location.physicalLocation
    # or directly as loc_entry.physicalLocation
    loc = loc_entry.get("location", {})
    phys_loc = loc.get("physicalLocation", {})
    if not phys_loc:
        phys_loc = loc_entry.get("physicalLocation", {})

    artifact = phys_loc.get("artifactLocation", {})
    region = phys_loc.get("region", {})

    uri = artifact.get("uri", "")
    if not uri:
        return None

    # Extract code snippet — SARIF stores it in region.snippet.text
    snippet = region.get("snippet", {}).get("text", "")

    # If no inline snippet, try contextRegion (surrounding lines)
    if not snippet:
        context_region = phys_loc.get("contextRegion", {})
        snippet = context_region.get("snippet", {}).get("text", "")

    # Extract the flow message if present (explains what happens at this step)
    message = ""
    loc_msg = loc_entry.get("location", {}).get("message", {})
    if loc_msg:
        message = loc_msg.get("text", "")
    if not message:
        # Some SARIF versions place message at the top level of the location entry
        message = loc_entry.get("message", {}).get("text", "")

    return DataFlowStep(
        file=uri,
        line=region.get("startLine", 0),
        column=region.get("startColumn", 0),
        code_snippet=snippet,
        message=message,
    )


def _extract_thread_flow_locations(thread_flow: dict) -> list[Location]:
    """Extract an ordered list of Locations from a single SARIF threadFlow."""
    locations: list[Location] = []
    for entry in thread_flow.get("locations", []):
        loc = _extract_location(entry)
        if loc is not None:
            locations.append(loc)
    return locations


def _build_dataflow_path(locations: list[Location]) -> DataFlowPath:
    """Build a DataFlowPath from an ordered location list."""
    return DataFlowPath(
        source=locations[0],
        sink=locations[-1],
        intermediate=locations[1:-1],
        is_complete=len(locations) >= 3,
        raw_path=[],
    )


def extract_deep_dataflow(thread_flow: dict) -> Optional[DeepDataFlowPath]:
    """Extract a complete DeepDataFlowPath from a SARIF threadFlow.

    Unlike the basic approach, this extracts code snippets at every step.

    Args:
        thread_flow: A single threadFlow dict from SARIF codeFlows.

    Returns:
        DeepDataFlowPath with code snippets, or None if path too short.
    """
    steps: list[DataFlowStep] = []
    for entry in thread_flow.get("locations", []):
        step = _extract_dataflow_step(entry)
        if step is not None:
            steps.append(step)

    if len(steps) < 2:
        return None

    return DeepDataFlowPath(
        source=steps[0],
        sink=steps[-1],
        intermediate=steps[1:-1] if len(steps) > 2 else [],
        is_complete=len(steps) >= 3,
        step_count=len(steps),
    )


class DataFlowAnalyzer:
    """Analyzes data flow to reconstruct source-sink paths.

    SARIF 2.1 places ``codeFlows`` inside each ``result`` object, not at
    the ``run`` level.  This implementation reads from the correct level and
    indexes paths by (file, line) so look-ups are O(1) per finding.

    Enhanced with deep dataflow extraction that retrieves actual code
    snippets at each step of the taint path.
    """

    def __init__(self) -> None:
        self._cache: dict[str, DataFlowPath] = {}
        self._deep_cache: dict[tuple[str, int], list[DeepDataFlowPath]] = {}

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def load_paths_from_sarif(
        self, sarif_path: Path
    ) -> dict[tuple[str, int], list[DataFlowPath]]:
        """Parse all threadFlow paths from a SARIF file, indexed by sink location.

        Returns:
            Dict mapping (file_uri, line) -> list of DataFlowPath whose sink
            matches that location.  A single result may have multiple codeFlows.
        """
        sarif_path = Path(sarif_path)
        if not sarif_path.exists():
            logger.warning(f"SARIF file not found: {sarif_path}")
            return {}

        try:
            with open(sarif_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse SARIF file {sarif_path}: {e}")
            return {}

        index: dict[tuple[str, int], list[DataFlowPath]] = {}
        deep_index: dict[tuple[str, int], list[DeepDataFlowPath]] = {}

        for run in data.get("runs", []):
            for result in run.get("results", []):
                # codeFlows is a per-result array in SARIF 2.1
                for code_flow in result.get("codeFlows", []):
                    for thread_flow in code_flow.get("threadFlows", []):
                        # Basic extraction
                        locs = _extract_thread_flow_locations(thread_flow)
                        if len(locs) >= 2:
                            path = _build_dataflow_path(locs)
                            key = (str(path.sink.file), path.sink.line)
                            index.setdefault(key, []).append(path)

                        # Deep extraction with code snippets
                        deep = extract_deep_dataflow(thread_flow)
                        if deep is not None:
                            dkey = (deep.sink.file, deep.sink.line)
                            deep_index.setdefault(dkey, []).append(deep)

        total = sum(len(v) for v in index.values())
        logger.debug(f"Loaded {total} dataflow paths from {sarif_path}")
        self._deep_cache = deep_index
        return index

    def load_deep_dataflows(
        self, sarif_path: Path
    ) -> dict[tuple[str, int], list[DeepDataFlowPath]]:
        """Parse all threadFlows and extract deep paths with code snippets.

        Args:
            sarif_path: Path to the SARIF file.

        Returns:
            Dict mapping (file_uri, line) -> list of DeepDataFlowPath.
        """
        sarif_path = Path(sarif_path)
        if not sarif_path.exists():
            logger.warning(f"SARIF file not found: {sarif_path}")
            return {}

        try:
            with open(sarif_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse SARIF file {sarif_path}: {e}")
            return {}

        deep_index: dict[tuple[str, int], list[DeepDataFlowPath]] = {}
        results_count = 0

        for run in data.get("runs", []):
            for result in run.get("results", []):
                results_count += 1
                for code_flow in result.get("codeFlows", []):
                    for thread_flow in code_flow.get("threadFlows", []):
                        deep = extract_deep_dataflow(thread_flow)
                        if deep is not None:
                            dkey = (deep.sink.file, deep.sink.line)
                            deep_index.setdefault(dkey, []).append(deep)

        total = sum(len(v) for v in deep_index.values())
        logger.debug(
            f"Loaded {total} deep dataflow paths from {sarif_path} "
            f"({results_count} results)"
        )
        self._deep_cache = deep_index
        return deep_index

    def get_deep_path_for_finding(
        self,
        finding: Finding,
        sarif_path: Optional[Path] = None,
    ) -> Optional[DeepDataFlowPath]:
        """Get the best deep dataflow path for a finding.

        First checks the in-memory cache (populated by load_paths_from_sarif),
        then falls back to loading from SARIF if a path is provided.

        Args:
            finding: The finding to get a path for.
            sarif_path: Optional SARIF path to load if cache is empty.

        Returns:
            Best-matching DeepDataFlowPath, or None.
        """
        key = (str(finding.location.file), finding.location.line)
        candidates = self._deep_cache.get(key, [])

        if not candidates and sarif_path is not None:
            self.load_deep_dataflows(sarif_path)
            candidates = self._deep_cache.get(key, [])

        if not candidates:
            return None

        # Prefer path with most steps (most complete)
        return max(candidates, key=lambda p: p.step_count)

    def extract_deep_dataflows_for_findings(
        self,
        findings: list[Finding],
        sarif_path: Path,
    ) -> list[DeepDataFlowPath]:
        """Extract deep dataflow paths for all findings at once.

        Loads SARIF once and enriches all findings with code-snippet-level
        dataflow paths.

        Args:
            findings: List of findings to enrich.
            sarif_path: Path to the SARIF file.

        Returns:
            List of DeepDataFlowPath (one per finding, None if not found).
        """
        self.load_deep_dataflows(sarif_path)

        paths = []
        for finding in findings:
            path = self.get_deep_path_for_finding(finding)
            paths.append(path)

        return paths

    def extract_dataflow_for_finding(
        self,
        finding: Finding,
        path_index: dict[tuple[str, int], list[DataFlowPath]],
    ) -> Optional[DataFlowPath]:
        """Look up the best-matching DataFlowPath for a finding.

        Matching strategy: prefer a path whose sink file and line match the
        finding's primary location exactly.  If multiple paths match, pick the
        one with the most intermediate steps (most complete path).

        Args:
            finding: The finding to match.
            path_index: Pre-built index from :meth:`load_paths_from_sarif`.

        Returns:
            Best-matching DataFlowPath, or None.
        """
        key = (str(finding.location.file), finding.location.line)
        candidates = path_index.get(key, [])
        if not candidates:
            return None

        # Prefer the path with the most intermediate nodes (most detail)
        return max(candidates, key=lambda p: len(p.intermediate))

    async def enrich_findings_with_dataflow(
        self,
        findings: list[Finding],
        sarif_path: Path,
    ) -> list[Finding]:
        """Enrich findings with data flow information from a SARIF file.

        Loads the SARIF once and enriches all findings in a single pass.

        Args:
            findings: List of findings to enrich (modified in place).
            sarif_path: Path to the SARIF file.

        Returns:
            The same list with dataflow_path populated where found.
        """
        path_index = self.load_paths_from_sarif(Path(sarif_path))
        enriched_count = 0

        for finding in findings:
            if finding.dataflow_path is not None:
                continue  # Already has a path
            dataflow = self.extract_dataflow_for_finding(finding, path_index)
            if dataflow:
                finding.dataflow_path = dataflow
                enriched_count += 1

        logger.info(
            f"Enriched {enriched_count}/{len(findings)} findings with dataflow paths"
        )
        return findings

    async def build_path(
        self,
        source: Location,
        sink: Location,
        intermediate: Optional[list[Location]] = None,
        is_complete: bool = True,
    ) -> DataFlowPath:
        """Build a complete DataFlowPath from components."""
        return DataFlowPath(
            source=source,
            sink=sink,
            intermediate=intermediate or [],
            is_complete=is_complete,
        )

    def get_dataflow_summary(self, path: DataFlowPath) -> str:
        """Get a structured summary of a data flow path (no natural language)."""
        lines = [f"source:{path.source.file}:{path.source.line}"]

        for loc in path.intermediate:
            lines.append(f"  ->{loc.file}:{loc.line}")

        lines.append(f"sink:{path.sink.file}:{path.sink.line}")
        lines.append(f"complete:{path.is_complete}")
        lines.append(f"steps:{len(path.locations)}")

        return "\n".join(lines)
