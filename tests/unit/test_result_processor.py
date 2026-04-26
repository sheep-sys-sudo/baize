"""Unit tests for result processor module."""

import json
import pytest
from pathlib import Path

from baize.core.result_processor import ResultProcessor
from baize.models.finding import FindingSeverity, VulnerabilityType


class TestResultProcessor:
    @pytest.fixture
    def processor(self):
        return ResultProcessor()

    @pytest.fixture
    def sarif_path(self, tmp_path, sarif_sample):
        path = tmp_path / "results.sarif"
        with open(path, "w") as f:
            json.dump(sarif_sample, f)
        return path

    def test_parse_sarif(self, processor, sarif_path):
        results = processor.parse_sarif(sarif_path)
        assert len(results) == 2

    def test_process_results(self, processor, sarif_path):
        findings = processor.process_results(sarif_path)
        assert len(findings) == 2

    def test_filter_by_severity(self, processor, sarif_path):
        findings = processor.process_results(
            sarif_path,
            severity_filter=[FindingSeverity.HIGH],
        )
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH

    def test_filter_by_vuln_type(self, processor, sarif_path):
        findings = processor.process_results(
            sarif_path,
            vuln_types_filter=[VulnerabilityType.SQLI],
        )
        assert len(findings) == 1
        assert findings[0].vuln_type == VulnerabilityType.SQLI

    def test_exclude_test_files(self, processor, sarif_path):
        findings = processor.process_results(sarif_path)
        for f in findings:
            assert "/test/" not in str(f.location.file)
            assert "/tests/" not in str(f.location.file)

    def test_create_report(self, processor, sarif_path):
        report = processor.create_report(
            sarif_path,
            project_name="test-project",
            project_path="/test/path",
        )
        assert report.metadata.total_findings == 2
        assert "sqli" in report.metadata.findings_by_type


class TestFindingConversion:
    @pytest.fixture
    def processor(self):
        return ResultProcessor()

    def test_determine_vuln_type(self, processor):
        assert processor._determine_vuln_type("java/sql-injection") == VulnerabilityType.SQLI
        assert processor._determine_vuln_type("py/xss") == VulnerabilityType.XSS
        assert processor._determine_vuln_type("unknown-rule") == VulnerabilityType.UNKNOWN

    def test_determine_severity(self, processor):
        assert processor._determine_severity({"level": "error"}) == FindingSeverity.HIGH
        assert processor._determine_severity({"level": "warning"}) == FindingSeverity.MEDIUM
        assert processor._determine_severity({"level": "note"}) == FindingSeverity.LOW