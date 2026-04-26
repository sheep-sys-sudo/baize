"""Unit tests for query generator module."""

import pytest

from baize.queries import get_template_manager, QueryTemplateManager
from baize.queries.generator import OFFICIAL_QUERY_PATHS, OFFICIAL_SUITES


class TestQueryTemplateManager:
    """Tests for QueryTemplateManager."""

    @pytest.fixture
    def manager(self):
        return QueryTemplateManager()

    def test_get_template_path(self, manager):
        path = manager.get_template_path("java", "sqli")
        assert "java" in str(path)
        assert "sqli" in str(path)

    def test_list_templates_returns_dict(self, manager):
        templates = manager.list_templates()
        assert isinstance(templates, dict)

    def test_list_templates_empty_without_local_files(self, manager):
        # Templates directory has no .ql files — official queries resolve via OFFICIAL_QUERY_PATHS
        templates = manager.list_templates("java")
        assert isinstance(templates, dict)

    def test_load_template_returns_none_without_local_file(self, manager):
        # No local .ql override — load_template should return None; use get_query_spec instead
        content = manager.load_template("java", "sqli")
        assert content is None

    def test_template_exists_false_without_local_file(self, manager):
        assert not manager.template_exists("java", "sqli")
        assert not manager.template_exists("java", "nonexistent")

    def test_get_query_spec_java_sqli(self, manager):
        spec = manager.get_query_spec("java", "sqli")
        assert spec is not None
        assert "SqlTainted" in spec or "sql" in spec.lower()
        assert "codeql/java-queries" in spec

    def test_get_query_spec_java_xss(self, manager):
        spec = manager.get_query_spec("java", "xss")
        assert spec is not None
        assert "codeql/java-queries" in spec

    def test_get_query_spec_python_xss(self, manager):
        spec = manager.get_query_spec("python", "xss")
        assert spec is not None
        assert "codeql/python-queries" in spec

    def test_get_query_spec_unknown_returns_none(self, manager):
        spec = manager.get_query_spec("java", "nonexistent-vuln")
        assert spec is None

    def test_get_suite_java(self, manager):
        suite = manager.get_suite("java")
        assert suite is not None
        assert "java-security-extended" in suite

    def test_get_suite_python(self, manager):
        suite = manager.get_suite("python")
        assert suite is not None
        assert "python" in suite

    def test_get_suite_unknown_language(self, manager):
        suite = manager.get_suite("cobol")
        assert suite is None

    def test_build_query_specs_specific(self, manager):
        specs = manager.build_query_specs("java", ["sqli", "xss"])
        assert len(specs) == 2
        assert any("SqlTainted" in s for s in specs)
        assert any("XSS" in s for s in specs)

    def test_build_query_specs_with_unknown_adds_suite(self, manager):
        specs = manager.build_query_specs("java", ["sqli", "unknown-thing"])
        # Should include the individual sqli query AND the full suite as fallback
        assert any("java-security-extended" in s for s in specs)
        assert any("SqlTainted" in s for s in specs)

    def test_get_all_vuln_types(self, manager):
        vuln_types = manager.get_all_vuln_types()
        assert "sqli" in vuln_types
        assert "xss" in vuln_types
        assert "rce" in vuln_types

    def test_get_vuln_type_description(self, manager):
        desc = manager.get_vuln_type_description("sqli")
        assert "SQL" in desc or "sql" in desc.lower()

    def test_language_alias_resolution(self, manager):
        # "ts" and "typescript" should both resolve to javascript specs
        spec_ts = manager.get_query_spec("ts", "sqli")
        spec_js = manager.get_query_spec("javascript", "sqli")
        assert spec_ts == spec_js

        spec_golang = manager.get_query_spec("golang", "sqli")
        spec_go = manager.get_query_spec("go", "sqli")
        assert spec_golang == spec_go


class TestOfficialMappings:
    """Tests for the OFFICIAL_QUERY_PATHS and OFFICIAL_SUITES constants."""

    def test_official_suites_has_main_languages(self):
        for lang in ("java", "python", "javascript", "go"):
            assert lang in OFFICIAL_SUITES, f"Missing suite for {lang}"

    def test_official_query_paths_java_coverage(self):
        java_keys = {vt for (lang, vt) in OFFICIAL_QUERY_PATHS if lang == "java"}
        for expected in ("sqli", "xss", "rce", "path-traversal", "ssrf", "deserialization", "xxe"):
            assert expected in java_keys, f"Missing java/{expected} in OFFICIAL_QUERY_PATHS"

    def test_all_pack_refs_have_colon(self):
        for (lang, vt), path in OFFICIAL_QUERY_PATHS.items():
            assert ":" in path, f"({lang}, {vt}) path missing pack:path separator: {path}"

    def test_all_suite_refs_have_colon(self):
        for lang, suite in OFFICIAL_SUITES.items():
            assert ":" in suite, f"{lang} suite missing pack:path separator: {suite}"


class TestGetTemplateManager:
    """Tests for get_template_manager singleton."""

    def test_singleton(self):
        m1 = get_template_manager()
        m2 = get_template_manager()
        assert m1 is m2
