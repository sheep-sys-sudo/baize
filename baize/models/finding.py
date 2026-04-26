"""Vulnerability finding models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha1
from pathlib import Path
from typing import Optional

from baize.models.dataflow import DataFlowPath, Location


class FindingSeverity(str, Enum):
    """Severity level of a vulnerability finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities supported by Baize."""

    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path-traversal"
    COMMAND_INJECTION = "command-injection"
    XXE = "xxe"
    OPEN_REDIRECT = "open-redirect"
    CRYPTO = "crypto"
    LOG_INJECTION = "log-injection"
    SENSITIVE_DATA = "sensitive-data"
    MISSING_AUTH = "missing-auth"
    HARDCODED_CREDENTIALS = "hardcoded-credentials"
    UNSAFE_REFLECTION = "unsafe-reflection"
    SSTI = "ssti"
    JNDI_INJECTION = "jndi-injection"
    RE_DOS = "re-dos"
    INFO_LEAK = "info-leak"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """Represents a vulnerability finding from CodeQL analysis."""

    id: str
    rule_id: str
    severity: FindingSeverity
    vuln_type: VulnerabilityType
    title: str = ""
    message: str = ""
    location: Location = field(default_factory=Location)
    source_code: str = ""
    sink_code: str = ""
    dataflow_path: Optional[DataFlowPath] = None
    cwe_id: Optional[str] = None
    confidence: float = 1.0
    related_locations: list[Location] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "type": self.vuln_type.value,
            "title": self.title,
            "message": self.message,
            "location": self.location.to_dict(),
            "source_code": self.source_code,
            "sink_code": self.sink_code,
            "dataflow_path": self.dataflow_path.to_dict() if self.dataflow_path else None,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "related_locations": [loc.to_dict() for loc in self.related_locations],
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }

    @classmethod
    def from_sarif_result(
        cls,
        result: dict,
        sarif_run: dict,
        vuln_type: VulnerabilityType,
        severity: FindingSeverity,
    ) -> Finding:
        """Create a Finding from a SARIF result object."""
        rule_id = result.get("ruleId", "")
        message = result.get("message", {}).get("text", "")

        locations = result.get("locations", [])
        primary_loc = locations[0] if locations else {}
        phys_loc = primary_loc.get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})

        location = Location(
            file=Path(artifact.get("uri", "")),
            line=region.get("startLine", 0),
            column=region.get("startColumn", 0),
            snippet=region.get("snippet", {}).get("text", ""),
        )

        related_locs = []
        for related_loc in result.get("relatedLocations", []):
            rel_phys = related_loc.get("physicalLocation", {})
            rel_art = rel_phys.get("artifactLocation", {})
            rel_reg = rel_phys.get("region", {})
            related_locs.append(
                Location(
                    file=Path(rel_art.get("uri", "")),
                    line=rel_reg.get("startLine", 0),
                    column=rel_reg.get("startColumn", 0),
                )
            )

        _hash = sha1(
            f"{rule_id}:{artifact.get('uri', '')}:{region.get('startLine', 0)}:{message}".encode()
        ).hexdigest()[:8]

        return cls(
            id=f"F-{rule_id}-{location.line}-{_hash}",
            rule_id=rule_id,
            severity=severity,
            vuln_type=vuln_type,
            title=f"{vuln_type.value.upper()} vulnerability",
            message=message,
            location=location,
            related_locations=related_locs,
        )