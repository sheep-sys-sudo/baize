"""Data flow path models for source-sink tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Location:
    """Represents a code location in a data flow path."""

    file: Path
    line: int
    column: int
    snippet: str = ""
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "file": str(self.file),
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Location:
        return cls(
            file=Path(data["file"]),
            line=data["line"],
            column=data["column"],
            snippet=data.get("snippet", ""),
            context=data.get("context", ""),
        )


@dataclass
class DataFlowPath:
    """Represents a complete source-to-sink data flow path."""

    source: Location
    sink: Location
    intermediate: list[Location] = field(default_factory=list)
    is_complete: bool = True
    sanitizers: list[str] = field(default_factory=list)
    raw_path: list[dict] = field(default_factory=list)

    @property
    def locations(self) -> list[Location]:
        """Get all locations in order from source to sink."""
        return [self.source] + self.intermediate + [self.sink]

    def to_dict(self) -> dict:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "intermediate": [loc.to_dict() for loc in self.intermediate],
            "is_complete": self.is_complete,
            "sanitizers": self.sanitizers,
            "locations": [loc.to_dict() for loc in self.locations],
        }

    @classmethod
    def from_sarif_thread_flows(
        cls,
        thread_flows: list[dict],
        source_location: dict,
        sink_location: dict,
    ) -> DataFlowPath:
        """Build a DataFlowPath from SARIF threadFlows data."""
        locations = []
        for tf in thread_flows:
            for loc in tf.get("locations", []):
                loc_data = loc.get("physicalLocation", {})
                artifact = loc_data.get("artifactLocation", {})
                region = loc_data.get("region", {})
                locations.append(
                    Location(
                        file=Path(artifact.get("uri", "")),
                        line=region.get("startLine", 0),
                        column=region.get("startColumn", 0),
                        snippet=region.get("snippet", {}).get("text", ""),
                    )
                )

        return cls(
            source=Location.from_dict(source_location),
            sink=Location.from_dict(sink_location),
            intermediate=locations[1:-1] if len(locations) > 2 else [],
            is_complete=len(locations) > 2,
            raw_path=thread_flows,
        )