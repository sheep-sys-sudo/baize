"""Unit tests for source-sink detection module."""

import pytest

from baize.core.source_sink import SourceSinkDetector, create_detector


class TestSourceSinkDetector:
    """Tests for SourceSinkDetector."""

    @pytest.fixture
    def java_detector(self):
        return create_detector("java")

    @pytest.fixture
    def python_detector(self):
        return create_detector("python")

    def test_java_sources(self, java_detector):
        code = """
        String user = request.getParameter("username");
        String input = request.getHeader("X-Custom");
        """
        sources = java_detector.find_sources(code)
        assert len(sources) >= 2

    def test_java_sinks(self, java_detector):
        code = """
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        """
        sinks = java_detector.find_sinks(code)
        assert len(sinks) >= 1
        assert any(s[1] == "sqli" for s in sinks)

    def test_python_sources(self, python_detector):
        code = """
        username = request.args.get('username')
        password = request.form['password']
        """
        sources = python_detector.find_sources(code)
        assert len(sources) >= 2

    def test_python_sinks(self, python_detector):
        code = """
        cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
        """
        sinks = python_detector.find_sinks(code)
        assert len(sinks) >= 1

    def test_analyze_potential_vulns(self, java_detector):
        code = """
        String user = request.getParameter("username");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        """
        result = java_detector.analyze_potential_vulns(code)
        assert "potential_vulns" in result
        assert len(result["potential_vulns"]) >= 1

    def test_get_sources(self, java_detector):
        sources = java_detector.get_sources()
        assert len(sources) > 0

    def test_get_sinks(self, java_detector):
        sinks = java_detector.get_sinks()
        assert len(sinks) > 0

    def test_get_sanitizers(self, java_detector):
        sanitizers = java_detector.get_sanitizers()
        assert len(sanitizers) > 0